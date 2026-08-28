import assert from 'node:assert/strict';
import test from 'node:test';
import {
  analyzeStatement,
  splitStatements,
  stripSqlComments,
  withRowLimit,
} from '../lib/sql-guard.ts';

const SINGLE = String.fromCharCode(39);
const DOUBLE = String.fromCharCode(34);

void test('a plain SELECT is allowed as a read', () => {
  const analysis = analyzeStatement('SELECT id, name FROM project');
  assert.equal(analysis.allowed, true);
  assert.equal(analysis.kind, 'read');
  assert.equal(analysis.verb, 'SELECT');
  assert.deepEqual(analysis.referencedTables, ['project']);
});

void test('a write is refused unless write mode is on', () => {
  const readOnly = analyzeStatement("UPDATE project SET status = 'idle'");
  assert.equal(readOnly.allowed, false);
  assert.match(readOnly.reason, /write mode/i);

  const permitted = analyzeStatement("UPDATE project SET status = 'idle'", { allowWrite: true });
  assert.equal(permitted.allowed, true);
  assert.equal(permitted.kind, 'write');
});

void test('credential tables are unreachable in either mode', () => {
  for (const statement of [
    'SELECT password FROM account',
    'SELECT * FROM session',
    'DELETE FROM verification',
    'SELECT a.password FROM account AS a JOIN "user" AS u ON u.id = a.userId',
  ]) {
    const analysis = analyzeStatement(statement, { allowWrite: true });
    assert.equal(analysis.allowed, false, `expected refusal for: ${statement}`);
    assert.match(analysis.reason, /credential material/i);
  }
});

void test('the user table is readable but never writable', () => {
  assert.equal(analyzeStatement('SELECT email FROM "user"').allowed, true);

  const write = analyzeStatement("UPDATE \"user\" SET name = 'x'", { allowWrite: true });
  assert.equal(write.allowed, false);
  assert.match(write.reason, /read-only/i);
});

void test('structural statements are always refused', () => {
  for (const statement of [
    'DROP TABLE project',
    'ALTER TABLE project ADD COLUMN x TEXT',
    'CREATE TABLE evil (id TEXT)',
    'ATTACH DATABASE \'other.db\' AS other',
    'VACUUM',
  ]) {
    const analysis = analyzeStatement(statement, { allowWrite: true });
    assert.equal(analysis.allowed, false, `expected refusal for: ${statement}`);
  }
});

void test('a second statement cannot be smuggled in behind a semicolon', () => {
  const analysis = analyzeStatement('SELECT 1; DROP TABLE project', { allowWrite: true });
  assert.equal(analysis.allowed, false);
  assert.match(analysis.reason, /one statement at a time/i);
});

void test('a trailing semicolon on a single statement is fine', () => {
  assert.equal(analyzeStatement('SELECT 1;').allowed, true);
});

void test('a comment cannot hide a second statement', () => {
  const analysis = analyzeStatement('SELECT 1 -- harmless\n; DELETE FROM project', {
    allowWrite: true,
  });
  assert.equal(analysis.allowed, false);
  assert.match(analysis.reason, /one statement at a time/i);
});

void test('a semicolon inside a string literal is not a separator', () => {
  const analysis = analyzeStatement(`SELECT ${SINGLE}a;b${SINGLE} AS value`);
  assert.equal(analysis.allowed, true);
  assert.equal(analysis.kind, 'read');
});

void test('a table name inside a string literal is not a table reference', () => {
  const analysis = analyzeStatement(`SELECT ${SINGLE}FROM account${SINGLE} AS note`);
  assert.equal(analysis.allowed, true);
  assert.deepEqual(analysis.referencedTables, []);
});

void test('a CTE in front of a write is treated as a write', () => {
  const statement = 'WITH stale AS (SELECT id FROM project) DELETE FROM project WHERE id IN (SELECT id FROM stale)';

  const readOnly = analyzeStatement(statement);
  assert.equal(readOnly.allowed, false);
  assert.match(readOnly.reason, /write mode/i);

  const permitted = analyzeStatement(statement, { allowWrite: true });
  assert.equal(permitted.allowed, true);
  assert.equal(permitted.kind, 'write');
});

void test('a CTE in front of a SELECT stays a read', () => {
  const analysis = analyzeStatement(
    'WITH recent AS (SELECT id FROM deployment) SELECT * FROM recent',
  );
  assert.equal(analysis.allowed, true);
  assert.equal(analysis.kind, 'read');
});

void test('only introspection pragmas D1 permits are allowed', () => {
  for (const statement of [
    'PRAGMA table_info(project)',
    'PRAGMA table_list',
    'PRAGMA index_list(project)',
    'PRAGMA foreign_key_list(project)',
    'PRAGMA quick_check',
  ]) {
    assert.equal(analyzeStatement(statement).allowed, true, `expected ${statement} to be allowed`);
  }
});

void test('pragmas D1 rejects are refused by the guard first', () => {
  // D1 answers these with SQLITE_AUTH. Refusing them here turns an opaque
  // driver error into an explanation the editor can show.
  for (const statement of [
    'PRAGMA page_count',
    'PRAGMA page_size',
    'PRAGMA database_list',
    'PRAGMA integrity_check',
    'PRAGMA compile_options',
  ]) {
    const analysis = analyzeStatement(statement);
    assert.equal(analysis.allowed, false, `expected ${statement} to be refused`);
    assert.match(analysis.reason, /allow list/i);
  }
});

void test('a pragma that writes is refused', () => {
  assert.equal(analyzeStatement('PRAGMA writable_schema').allowed, false);
  assert.equal(analyzeStatement('PRAGMA journal_mode = WAL').allowed, false);
  assert.equal(analyzeStatement('PRAGMA foreign_keys = OFF').allowed, false);
});

void test('a quoted identifier cannot pose as a keyword', () => {
  const analysis = analyzeStatement(`${DOUBLE}SELECT${DOUBLE} FROM project`);
  assert.equal(analysis.allowed, false);
});

void test('an empty statement is refused rather than run', () => {
  assert.equal(analyzeStatement('   ').allowed, false);
  assert.equal(analyzeStatement('-- just a comment').allowed, false);
});

void test('comment stripping leaves quoted text alone', () => {
  const stripped = stripSqlComments(`SELECT ${SINGLE}-- not a comment${SINGLE} /* gone */`);
  assert.match(stripped, /-- not a comment/);
  assert.doesNotMatch(stripped, /gone/);
});

void test('statement splitting ignores quoted semicolons', () => {
  assert.deepEqual(splitStatements(`SELECT ${SINGLE};${SINGLE}; SELECT 2`), [
    `SELECT ${SINGLE};${SINGLE}`,
    'SELECT 2',
  ]);
});

void test('a row limit is added only when one is missing', () => {
  assert.equal(withRowLimit('SELECT * FROM project', 25), 'SELECT * FROM project LIMIT 25');
  assert.equal(withRowLimit('SELECT * FROM project LIMIT 5', 25), 'SELECT * FROM project LIMIT 5');
  assert.equal(withRowLimit('PRAGMA page_count', 25), 'PRAGMA page_count');
});
