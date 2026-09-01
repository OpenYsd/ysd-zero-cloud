import type { ColumnInfo, TablePage, TableSummary } from '@/lib/domain';
import {
  analyzeStatement,
  withRowLimit,
  type SqlAnalysis,
} from '@/lib/sql-guard';
import { scopeForTable, type TenantScope } from '@/lib/tenancy';
import { d1DatabaseSize } from './cloudflare';
import { AUTH_TABLES, db, query, WORKSPACE_TABLES } from './db';

/**
 * Database Studio and the SQL Editor read the live D1 database.
 *
 * Three rules hold everywhere in this module. A table name is only ever
 * interpolated after being matched against the real schema. Columns that hold
 * credential material are replaced with a mask before a row leaves the server,
 * so an API client sees the same redaction the browser does. And every read is
 * limited to the caller's own rows: one D1 database backs every workspace, so
 * an unscoped read would return every tenant's data.
 */

export const MAX_ROWS = 200;

/** Columns whose value must never reach a client, keyed by table. */
const MASKED_COLUMNS: Record<string, string[]> = {
  account: ['password', 'accessToken', 'refreshToken', 'idToken', 'scope'],
  session: ['token'],
  verification: ['value'],
  secret: ['ciphertext', 'fingerprint'],
  node_pairing: ['codeHash'],
  compute_node: ['tokenCiphertext', 'tokenHash'],
  node_request_nonce: ['nonce'],
  organization_invitation: ['tokenHash'],
  service_account_token: ['tokenHash'],
  exposure_domain: ['tokenHash'],
  webhook_source: ['secretCiphertext', 'secretFingerprint'],
  // AI prompts and bounded model output live in these JSON columns. They are
  // visible only through the purpose-built, workspace-scoped AI surface.
  node_job: ['payload', 'payloadHash', 'claimSignature', 'result'],
  app_artifact: ['manifest'],
  node_security_event: ['networkFingerprint'],
};

const MASK = '••••••••';

export type TableKind = TableSummary['kind'];
export type { ColumnInfo, TablePage, TableSummary };

export type QueryResult = {
  analysis: SqlAnalysis;
  columns: string[];
  rows: Record<string, unknown>[];
  rowsRead: number;
  rowsWritten: number;
  durationMs: number;
  truncated: boolean;
};

function kindOf(name: string): TableKind {
  if ((AUTH_TABLES as readonly string[]).includes(name)) return 'auth';
  if ((WORKSPACE_TABLES as readonly string[]).includes(name))
    return 'workspace';
  return 'system';
}

/** Every user table in the database, ignoring SQLite's own bookkeeping. */
export async function listTableNames(): Promise<string[]> {
  const rows = await query<{ name: string }>(
    `SELECT name FROM sqlite_master
     WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'
     ORDER BY name`,
  );
  return rows.map((row) => row.name);
}

async function columnsOf(table: string): Promise<ColumnInfo[]> {
  // `table` is always a name that came back from sqlite_master, so the only
  // quoting concern is an embedded quote character.
  const rows = await query<{
    name: string;
    type: string;
    notnull: number;
    pk: number;
  }>(`PRAGMA table_info("${table.replace(/"/g, '""')}")`);
  return rows.map((row) => ({
    name: row.name,
    type: row.type || 'ANY',
    notNull: row.notnull === 1,
    primaryKey: row.pk > 0,
  }));
}

async function rowCount(
  table: string,
  columns: ColumnInfo[],
  scope: TenantScope,
): Promise<number> {
  const predicate = scopeForTable(
    table,
    columns.map((column) => column.name),
    scope,
  );
  const rows = await query<{ total: number }>(
    `SELECT COUNT(*) AS total FROM "${table.replace(/"/g, '""')}" WHERE ${predicate.sql}`,
    ...predicate.params,
  );
  return rows[0]?.total ?? 0;
}

/**
 * Every table in the schema, with row counts limited to the caller.
 *
 * The counts are scoped too: a sidebar that showed a global total would leak
 * how much data other tenants hold even though their rows stay hidden.
 */
/**
 * Column names per table.
 *
 * Used by the security scan to check that every table holding tenant data is
 * actually classified by the scoping rules, rather than silently falling
 * through to the deny-all default.
 */
export async function listTableColumns(): Promise<Record<string, string[]>> {
  const names = await listTableNames();
  const out: Record<string, string[]> = {};
  for (const name of names) {
    out[name] = (await columnsOf(name)).map((column) => column.name);
  }
  return out;
}

export async function listTables(scope: TenantScope): Promise<TableSummary[]> {
  const names = await listTableNames();
  const summaries: TableSummary[] = [];
  for (const name of names) {
    const columns = await columnsOf(name);
    summaries.push({
      name,
      kind: kindOf(name),
      rows: await rowCount(name, columns, scope),
      columns: columns.length,
      hasPrimaryKey: columns.some((column) => column.primaryKey),
      masked: (MASKED_COLUMNS[name]?.length ?? 0) > 0,
    });
  }
  return summaries;
}

function maskRow(
  table: string,
  row: Record<string, unknown>,
): Record<string, unknown> {
  const masked = MASKED_COLUMNS[table];
  if (!masked?.length) return row;
  const copy: Record<string, unknown> = { ...row };
  for (const column of masked) {
    if (column in copy && copy[column] !== null && copy[column] !== undefined) {
      copy[column] = MASK;
    }
  }
  return copy;
}

export type ReadTableOptions = {
  limit?: number;
  offset?: number;
  filter?: string;
};

/**
 * Reads one page of a table.
 *
 * @param table Must name a real table; anything else is rejected before it
 * reaches SQL.
 */
export async function readTable(
  table: string,
  scope: TenantScope,
  options: ReadTableOptions = {},
): Promise<TablePage | null> {
  const names = await listTableNames();
  if (!names.includes(table)) return null;

  const quoted = `"${table.replace(/"/g, '""')}"`;
  const columns = await columnsOf(table);
  const limit = Math.min(MAX_ROWS, Math.max(1, options.limit ?? 50));
  const offset = Math.max(0, options.offset ?? 0);

  // The tenant predicate is never optional and is ANDed ahead of the search
  // box, so no filter string can widen what the caller can see.
  const predicate = scopeForTable(
    table,
    columns.map((column) => column.name),
    scope,
  );
  const clauses = [predicate.sql];
  const params: unknown[] = [...predicate.params];

  const filter = options.filter?.trim().toLowerCase();
  if (filter) {
    // Every column is compared as text so the filter behaves the same way the
    // Studio search box looks like it should.
    const search = columns.map(
      (column) => `LOWER(CAST(${quoteIdentifier(column.name)} AS TEXT)) LIKE ?`,
    );
    clauses.push(`(${search.join(' OR ')})`);
    params.push(...columns.map(() => `%${filter}%`));
  }

  const where = `WHERE ${clauses.join(' AND ')}`;

  const totalRows = await query<{ total: number }>(
    `SELECT COUNT(*) AS total FROM ${quoted} ${where}`,
    ...params,
  );

  const rows = await query<Record<string, unknown>>(
    `SELECT * FROM ${quoted} ${where} LIMIT ? OFFSET ?`,
    ...params,
    limit,
    offset,
  );

  return {
    table,
    columns,
    rows: rows.map((row) => maskRow(table, row)),
    total: totalRows[0]?.total ?? 0,
    maskedColumns: MASKED_COLUMNS[table] ?? [],
  };
}

function quoteIdentifier(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

/**
 * Runs a statement from the SQL Editor.
 *
 * The guard decides what is allowed; this function only executes what the
 * guard approved, caps the result set, and redacts anything the statement
 * happened to select from a masked table.
 *
 * Note what this function does *not* do: it does not scope results to a
 * workspace. An arbitrary statement cannot be rewritten to add a tenant
 * predicate without a full SQL planner, so the route that calls this restricts
 * the editor to the instance owner instead. Do not expose it more widely
 * without solving that first.
 */
export async function runEditorQuery(
  sql: string,
  options: { allowWrite?: boolean; limit?: number } = {},
): Promise<QueryResult> {
  const analysis = analyzeStatement(sql, { allowWrite: options.allowWrite });
  const limit = Math.min(MAX_ROWS, Math.max(1, options.limit ?? MAX_ROWS));

  if (!analysis.allowed) {
    return {
      analysis,
      columns: [],
      rows: [],
      rowsRead: 0,
      rowsWritten: 0,
      durationMs: 0,
      truncated: false,
    };
  }

  const database = await db();
  const startedAt = Date.now();
  const statement =
    analysis.kind === 'read'
      ? withRowLimit(analysis.statement, limit)
      : analysis.statement;
  const result = await database
    .prepare(statement)
    .all<Record<string, unknown>>();
  const durationMs = Date.now() - startedAt;

  const rawRows = result.results ?? [];
  const truncated = rawRows.length >= limit;

  // A statement can select from a masked table under an alias, so masking is
  // applied for every table the guard saw referenced.
  let rows = rawRows;
  for (const table of analysis.referencedTables) {
    if (!MASKED_COLUMNS[table]) continue;
    rows = rows.map((row) => maskRow(table, row));
  }

  return {
    analysis,
    columns: rows[0] ? Object.keys(rows[0]) : [],
    rows,
    rowsRead: result.meta?.rows_read ?? rows.length,
    rowsWritten: result.meta?.rows_written ?? 0,
    durationMs,
    truncated,
  };
}

/**
 * Storage used by the database.
 *
 * D1 rejects `PRAGMA page_count` and `page_size` through its SQLite
 * authorizer, so a Worker cannot measure its own database. The figure comes
 * from the Cloudflare API when a token is configured.
 *
 * @returns `null` when the size is not observable, so callers can say so
 * instead of reporting a zero that looks like an empty database.
 */
export async function databaseBytes(): Promise<number | null> {
  return d1DatabaseSize();
}
