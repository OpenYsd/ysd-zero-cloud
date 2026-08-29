import { env } from 'cloudflare:workers';

import { splitStatements, stripSqlComments } from '@/lib/sql-guard';
import authSchema from '../../db/migrations/0001_auth.sql?raw';
import workspaceSchema from '../../db/migrations/0002_workspace.sql?raw';
import authRateLimitSchema from '../../db/migrations/0003_auth_rate_limit.sql?raw';
import securitySchema from '../../db/migrations/0004_security.sql?raw';
import storageSchema from '../../db/migrations/0005_storage.sql?raw';
import computeNodesSchema from '../../db/migrations/0006_compute_nodes.sql?raw';

/**
 * D1 access and schema management.
 *
 * Migrations run lazily on the first query of an isolate rather than through a
 * deploy step, because a Worker has no pre-flight hook and D1 has no local
 * connection the CLI can reach. Every statement is written to be safe to
 * replay, so a cold start that races another one converges instead of failing.
 */

const MIGRATIONS: { name: string; sql: string }[] = [
  { name: '0001_auth', sql: authSchema },
  { name: '0002_workspace', sql: workspaceSchema },
  { name: '0003_auth_rate_limit', sql: authRateLimitSchema },
  { name: '0004_security', sql: securitySchema },
  { name: '0005_storage', sql: storageSchema },
  { name: '0006_compute_nodes', sql: computeNodesSchema },
];

const LEDGER = `CREATE TABLE IF NOT EXISTS ysd_migration (
  name TEXT PRIMARY KEY,
  appliedAt INTEGER NOT NULL
)`;

/** Tables the app owns. Studio and Shield use this to separate them from D1 internals. */
export const AUTH_TABLES = [
  'user',
  'session',
  'account',
  'verification',
  'rateLimit',
  'user_role',
  'auth_attempt',
  'rate_limit',
] as const;
export const WORKSPACE_TABLES = [
  'workspace',
  'project',
  'deployment',
  'log_event',
  'secret',
  'shield_scan',
  'shield_finding',
  'storage_object',
  'storage_meter',
  'node_pairing',
  'compute_node',
  'node_request_nonce',
  'node_job',
  'node_metric',
  'node_job_event',
  'node_security_event',
] as const;

export function getDatabase(): D1Database {
  const database = env.DB;
  if (!database) {
    throw new Error(
      'The DB binding is missing. Set "d1" in .openai/hosting.json and restart the dev server.',
    );
  }
  return database;
}

/**
 * A replayed migration re-runs `CREATE TABLE` against tables that already
 * exist. SQLite reports that as an ordinary error, and it is the one error
 * that means the migration already succeeded.
 */
function isAlreadyExists(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /already exists/i.test(message);
}

async function applyMigration(
  database: D1Database,
  name: string,
  sql: string,
): Promise<boolean> {
  const applied = await database
    .prepare('SELECT 1 AS ok FROM ysd_migration WHERE name = ?')
    .bind(name)
    .first<{ ok: number }>();
  if (applied) return false;

  for (const statement of splitStatements(stripSqlComments(sql))) {
    try {
      await database.prepare(statement).run();
    } catch (error) {
      if (!isAlreadyExists(error)) {
        throw new Error(
          `Migration ${name} failed on: ${statement.slice(0, 120)}`,
          { cause: error },
        );
      }
    }
  }

  await database
    .prepare(
      'INSERT OR IGNORE INTO ysd_migration (name, appliedAt) VALUES (?, ?)',
    )
    .bind(name, Date.now())
    .run();
  return true;
}

let schemaReady: Promise<void> | undefined;

/** Brings the database up to date. Memoised for the lifetime of the isolate. */
export function ensureSchema(): Promise<void> {
  schemaReady ??= (async () => {
    const database = getDatabase();
    await database.prepare(LEDGER).run();
    for (const migration of MIGRATIONS) {
      await applyMigration(database, migration.name, migration.sql);
    }
  })().catch((error: unknown) => {
    // A failed migration must not be cached, or every later request in this
    // isolate would report success against a half-built schema.
    schemaReady = undefined;
    throw error;
  });
  return schemaReady;
}

/** The migrated database handle. Every server module goes through this. */
export async function db(): Promise<D1Database> {
  await ensureSchema();
  return getDatabase();
}

export async function query<T>(
  sql: string,
  ...params: unknown[]
): Promise<T[]> {
  const database = await db();
  const result = await database
    .prepare(sql)
    .bind(...params)
    .all<T>();
  return result.results ?? [];
}

export async function queryOne<T>(
  sql: string,
  ...params: unknown[]
): Promise<T | null> {
  const database = await db();
  return (
    (await database
      .prepare(sql)
      .bind(...params)
      .first<T>()) ?? null
  );
}

export async function execute(
  sql: string,
  ...params: unknown[]
): Promise<D1Result> {
  const database = await db();
  return database
    .prepare(sql)
    .bind(...params)
    .run();
}

/** `COUNT(*)` for a statement that already filters to one workspace. */
export async function count(
  sql: string,
  ...params: unknown[]
): Promise<number> {
  const row = await queryOne<{ total: number }>(sql, ...params);
  return row?.total ?? 0;
}
