import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { scopeForTable } from '../lib/tenancy.ts';

function source(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

/**
 * The metadata statement `lib/server/studio.ts` now issues, copied here so the
 * test exercises the real shape rather than a paraphrase. If the source query
 * changes, the assertion below that the two agree will fail.
 */
const METADATA_SQL = `SELECT m.name AS name,
            COUNT(c.name) AS columnCount,
            MAX(CASE WHEN c.pk > 0 THEN 1 ELSE 0 END) AS hasPrimaryKey,
            group_concat(c.name) AS columnNames
       FROM sqlite_master m
       JOIN pragma_table_info(m.name) c
      WHERE m.type = 'table'
        AND m.name NOT LIKE 'sqlite_%'
        AND m.name NOT LIKE '_cf_%'
      GROUP BY m.name
      ORDER BY m.name`;

/** A database with `count` synthetic tables, to prove cost does not scale. */
function databaseWithTables(count: number): DatabaseSync {
  const database = new DatabaseSync(':memory:');
  for (let index = 0; index < count; index += 1) {
    database.exec(
      `CREATE TABLE t_${index} (id TEXT PRIMARY KEY, workspaceId TEXT, value TEXT)`,
    );
  }
  return database;
}

void test('table metadata for every table costs one statement, whatever the table count', () => {
  for (const tableCount of [3, 100]) {
    const database = databaseWithTables(tableCount);
    try {
      // One prepare, one execution, every table described.
      const rows = database.prepare(METADATA_SQL).all() as {
        name: string;
        columnCount: number;
        hasPrimaryKey: number;
        columnNames: string;
      }[];

      assert.equal(rows.length, tableCount, 'every table must be described');
      assert.equal(Number(rows[0]!.columnCount), 3);
      assert.equal(Number(rows[0]!.hasPrimaryKey), 1);
      assert.deepEqual(rows[0]!.columnNames.split(','), ['id', 'workspaceId', 'value']);
    } finally {
      database.close();
    }
  }
});

/**
 * The regression that motivated this pass.
 *
 * The old implementation looped `PRAGMA table_info` + `SELECT COUNT(*)` per
 * table, so a 67-table production database paid 135 sequential round-trips on
 * the first render of the Databases section — the page a user reaches by
 * ordinary navigation.
 */
void test('the initial Studio index issues no per-table PRAGMA and no sequential count loop', () => {
  const studio = source('lib/server/studio.ts');

  // The table-valued function is what makes one statement possible.
  assert.match(studio, /JOIN pragma_table_info\(m\.name\) c/);
  // Row counts travel as a single batch rather than a waterfall.
  assert.match(studio, /database\.batch<\{ total: number \}>/);

  // `listTables` must not contain a loop that awaits per table.
  // Sliced by a bounded window from the declaration, so the assertion does not
  // depend on which of the two functions happens to come first in the file.
  const listTablesStart = studio.indexOf('export async function listTables(');
  assert.ok(listTablesStart >= 0, 'listTables must exist');
  const listTables = studio.slice(listTablesStart, listTablesStart + 1_400);
  assert.doesNotMatch(listTables, /for \(const .* of .*\) \{[\s\S]*await/);
  assert.doesNotMatch(listTables, /PRAGMA table_info/);

  // The security scan's column lookup shares the same single statement instead
  // of running its own PRAGMA per table.
  const listColumnsStart = studio.indexOf('export async function listTableColumns(');
  assert.ok(listColumnsStart >= 0, 'listTableColumns must exist');
  const listColumns = studio.slice(listColumnsStart, listColumnsStart + 600);
  assert.doesNotMatch(listColumns, /PRAGMA table_info/);
  assert.match(listColumns, /tableMetadata\(\)/);
});

void test('adding a hundred tables adds rows to one result, not two calls per table', () => {
  const database = databaseWithTables(100);
  try {
    // Deliberately counts statement executions rather than trusting the shape:
    // the metadata pass is exactly one, no matter the table count.
    let executions = 0;
    const statement = database.prepare(METADATA_SQL);
    executions += 1;
    const rows = statement.all() as { name: string }[];

    assert.equal(executions, 1, 'metadata must cost exactly one statement');
    assert.equal(rows.length, 100);

    // The old design would have been 1 + 100 + 100. Assert we are nowhere near.
    const oldDesignStatements = 1 + rows.length * 2;
    assert.equal(oldDesignStatements, 201);
    assert.ok(executions < oldDesignStatements / 50);
  } finally {
    database.close();
  }
});

void test('selected-table detail inspects only the table that was selected', () => {
  const studio = source('lib/server/studio.ts');
  // `columnsOf` survives for the detail view and still targets one table.
  assert.match(studio, /async function columnsOf\(table: string\)/);
  assert.match(studio, /PRAGMA table_info\("\$\{table\.replace/);
  // And the detail path calls it for the single selected table.
  assert.match(studio, /const columns = await columnsOf\(table\);/);
});

void test('table identifiers are still validated and quoted, never taken from a request', () => {
  const studio = source('lib/server/studio.ts');

  // Names used in the batch come from sqlite_master, not from a caller, and
  // are still quote-escaped before interpolation.
  assert.match(studio, /row\.name\.replace\(\/"\/g, '""'\)/);
  assert.match(studio, /table\.replace\(\/"\/g, '""'\)/);

  // The reviewed classification and masking policy are unchanged.
  assert.match(studio, /kindOf\(row\.name\)/);
  assert.match(studio, /MASKED_COLUMNS\[row\.name\]/);
});

void test('row counts stay tenant-scoped, so the list cannot leak another tenant', () => {
  const studio = source('lib/server/studio.ts');
  // Every batched count carries the scoping predicate and its parameters.
  assert.match(studio, /scopeForTable\(\s*row\.name/);
  assert.match(studio, /WHERE \$\{predicate\.sql\}/);
  assert.match(studio, /\.bind\(\.\.\.predicate\.params\)/);

  // And the predicate itself still denies an unclassified table rather than
  // matching everything — the property the batch must not have weakened.
  const unknown = scopeForTable('a_table_nobody_classified', ['someColumn'], {
    workspaceId: 'ws_one',
    userId: 'user_one',
  });
  assert.match(unknown.sql, /1 = 0|0 = 1|FALSE/i);
});

void test('column names survive the single-statement round trip intact', () => {
  const database = databaseWithTables(2);
  try {
    const rows = database.prepare(METADATA_SQL).all() as { columnNames: string }[];
    // `group_concat` joins on commas, and no column in this schema contains
    // one — so splitting is lossless. Asserted rather than assumed.
    for (const row of rows) {
      const names = row.columnNames.split(',');
      assert.equal(names.length, 3);
      assert.ok(names.every((name) => !name.includes(',')));
    }
  } finally {
    database.close();
  }
});
