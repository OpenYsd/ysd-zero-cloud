/**
 * Row-level scoping for the surfaces that read the database directly.
 *
 * Every workspace in this deployment shares one D1 database, so a surface that
 * reads a table without a predicate reads every tenant's rows. The
 * workspace-scoped APIs each carry their own `WHERE workspaceId = ?`; Database
 * Studio reads arbitrary tables and needs the predicate derived instead.
 *
 * The rule is fail-closed: a table nobody has classified returns a predicate
 * that matches nothing, so adding a table without thinking about tenancy makes
 * it invisible rather than public.
 */

export type TenantScope = {
  workspaceId: string;
  userId: string;
};

export type ScopePredicate = {
  /** A SQL boolean expression over the table's own columns. */
  sql: string;
  params: unknown[];
};

/** Matches nothing. Used for tables that cannot be attributed to a caller. */
export const DENY_ALL: ScopePredicate = { sql: '0 = 1', params: [] };

/** Matches everything. Only for tables that hold no tenant data at all. */
export const ALLOW_ALL: ScopePredicate = { sql: '1 = 1', params: [] };

/**
 * Tables that describe the schema rather than any tenant's data. Their
 * contents are identical for every operator, so showing them leaks nothing.
 */
const SCHEMA_TABLES = new Set(['d1_migrations', 'ysd_migration']);

/**
 * Builds the predicate that limits a table to one caller's rows.
 *
 * @param table Table name as it appears in the schema.
 * @param columnNames The table's real columns, used to detect ownership.
 */
export function scopeForTable(
  table: string,
  columnNames: readonly string[],
  scope: TenantScope,
): ScopePredicate {
  if (SCHEMA_TABLES.has(table)) return ALLOW_ALL;

  const columns = new Set(columnNames);

  // Workspace-owned rows are the common case across the product tables.
  if (columns.has('workspaceId')) {
    return { sql: 'workspaceId = ?', params: [scope.workspaceId] };
  }

  // The workspace row itself is identified by its own primary key.
  if (table === 'workspace') {
    return { sql: 'id = ?', params: [scope.workspaceId] };
  }

  // A caller may see their own account record and nobody else's.
  if (table === 'user') {
    return { sql: 'id = ?', params: [scope.userId] };
  }

  if (columns.has('userId')) {
    return { sql: 'userId = ?', params: [scope.userId] };
  }

  // `verification` is keyed by email address with no owner column, so a row
  // cannot be attributed to the caller and none are shown.
  return DENY_ALL;
}

/**
 * Whether a table is worth showing at all.
 *
 * A table that can never match is still listed, so the schema stays visible
 * even where the rows are not.
 */
export function isSchemaOnlyTable(table: string): boolean {
  return SCHEMA_TABLES.has(table);
}
