import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import {
  ACCOUNT_LIMITS,
  EMAIL_CHANGE_AVAILABILITY,
  accountDisplayName,
  accountInitials,
  normalizeDisplayName,
  parsePasswordChange,
  parseProfileUpdate,
} from '../lib/account.ts';
import { EVIDENCE_ACTIONS, evidenceAction, narrowEvidenceMetadata } from '../lib/audit-actions.ts';
import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';

function source(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function migration(name: string): string {
  return source(`db/migrations/${name}`);
}

function apply(database: DatabaseSync, name: string): void {
  const sql = migration(name);
  if (name >= '0010_organizations.sql') {
    for (const statement of splitStatements(stripSqlComments(sql))) database.exec(statement);
  } else {
    database.exec(sql);
  }
}

const MIGRATIONS = readdirSync(new URL('../db/migrations', import.meta.url))
  .filter((file) => file.endsWith('.sql'))
  .sort();

/**
 * A local-only fixture. `@ysd.invalid` is a reserved non-routable domain and
 * the hash below is a literal placeholder string, not a credential — nothing
 * here can authenticate against anything.
 */
const FIXTURE = {
  userId: 'user_p0_local',
  email: 'p0-local-user@ysd.invalid',
  passwordHashPlaceholder: 'local-fixture-not-a-real-hash',
} as const;

function databaseBefore0017(): DatabaseSync {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = ON');
  for (const name of MIGRATIONS.filter((file) => file < '0017_account_experience.sql')) {
    apply(database, name);
  }
  database.exec(`
    INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt) VALUES
      ('${FIXTURE.userId}','Local Fixture','${FIXTURE.email}',0,NULL,1,1);
    INSERT INTO "session" (id,expiresAt,token,createdAt,updatedAt,ipAddress,userAgent,userId) VALUES
      ('sess_local',9999,'local-fixture-token',1,1,'127.0.0.1','fixture-agent','${FIXTURE.userId}');
    INSERT INTO account (id,issuer,accountId,providerId,userId,password,createdAt,updatedAt) VALUES
      ('acct_local','credential','${FIXTURE.email}','credential','${FIXTURE.userId}','${FIXTURE.passwordHashPlaceholder}',1,1);
  `);
  return database;
}

void test('migration 0017 adds only passwordChangedAt and preserves every user, credential and session', () => {
  const database = databaseBefore0017();
  try {
    const before = database
      .prepare('SELECT u.id AS id, u.name AS name, u.email AS email, a.password AS password FROM "user" u JOIN account a ON a.userId = u.id')
      .all() as { id: string; name: string; email: string; password: string }[];
    assert.equal(before.length, 1);

    apply(database, '0017_account_experience.sql');

    const after = database
      .prepare('SELECT u.id, u.name, u.email, u.passwordChangedAt, a.password FROM "user" u JOIN account a ON a.userId = u.id')
      .all() as {
        id: string;
        name: string;
        email: string;
        passwordChangedAt: number | null;
        password: string;
      }[];

    assert.equal(after.length, 1, 'no user may be lost');
    assert.equal(after[0]!.id, before[0]!.id);
    assert.equal(after[0]!.email, before[0]!.email);
    // The credential is untouched by the migration.
    assert.equal(after[0]!.password, before[0]!.password);
    // Nullable, and honestly null rather than a fabricated timestamp.
    assert.equal(after[0]!.passwordChangedAt, null);

    // Sessions survive: nobody is signed out by upgrading.
    assert.equal(
      Number((database.prepare('SELECT COUNT(*) AS total FROM "session"').get() as { total: number }).total),
      1,
    );
  } finally {
    database.close();
  }
});

void test('migration 0017 is safe to replay the way the runner replays it', () => {
  const database = databaseBefore0017();
  try {
    apply(database, '0017_account_experience.sql');
    // The lazy runner swallows "duplicate column name", which is exactly what a
    // second application raises. Assert that is the error, so the runner's
    // guard genuinely covers it.
    assert.throws(
      () => apply(database, '0017_account_experience.sql'),
      /duplicate column name/i,
    );
    const runner = source('lib/server/db.ts');
    assert.match(runner, /duplicate column name/i);
  } finally {
    database.close();
  }
});

void test('display names are normalised, bounded, and free of control characters', () => {
  assert.equal(normalizeDisplayName('  Ada   Lovelace  '), 'Ada Lovelace');
  assert.equal(normalizeDisplayName('Ada'), 'Ada');

  // Control characters are built from char codes rather than escapes so the
  // fixture cannot be mangled by whatever writes this file.
  const control = (code: number) => 'Ada' + String.fromCharCode(code) + 'Lovelace';

  for (const rejected of [
    '',
    '   ',
    // Below the minimum once trimmed.
    'A',
    'x'.repeat(ACCOUNT_LIMITS.displayNameMaximum + 1),
    control(10),  // newline
    control(9),   // tab
    control(0),   // NUL
    control(127), // DEL
    42,
    null,
    undefined,
  ]) {
    assert.equal(normalizeDisplayName(rejected), null, JSON.stringify(rejected));
  }

  // Ordinary internal spacing is collapsed, not rejected.
  assert.equal(normalizeDisplayName('Ada  Lovelace'), 'Ada Lovelace');
});

void test('a profile update may only ever change the display name', () => {
  const ok = parseProfileUpdate({ displayName: 'Ada Lovelace' });
  assert.equal(ok.ok, true);
  if (ok.ok) assert.equal(ok.value.displayName, 'Ada Lovelace');

  // The identity and tenancy fields are refused outright rather than ignored,
  // so a caller cannot hope a later layer honours them.
  for (const forbidden of [
    'userId',
    'id',
    'organizationId',
    'workspaceId',
    'actorId',
    'email',
    'role',
    'emailVerified',
    'passwordChangedAt',
  ]) {
    const parsed = parseProfileUpdate({ displayName: 'Ada', [forbidden]: 'x' });
    assert.equal(parsed.ok, false, forbidden);
  }

  assert.equal(parseProfileUpdate({ displayName: '' }).ok, false);
  assert.equal(parseProfileUpdate({}).ok, false);
  assert.equal(parseProfileUpdate('nope').ok, false);
});

void test('a password change is shape-checked without judging the credential itself', () => {
  const ok = parsePasswordChange({
    currentPassword: 'old-fixture-value',
    newPassword: 'new-fixture-value-1234',
    confirmPassword: 'new-fixture-value-1234',
  });
  assert.equal(ok.ok, true);

  // Mismatch.
  assert.equal(
    parsePasswordChange({
      currentPassword: 'a-value',
      newPassword: 'new-fixture-value-1234',
      confirmPassword: 'different-value-1234',
    }).ok,
    false,
  );
  // Too short for the configured policy.
  assert.equal(
    parsePasswordChange({ currentPassword: 'a', newPassword: 'short', confirmPassword: 'short' }).ok,
    false,
  );
  // Reusing the current one.
  assert.equal(
    parsePasswordChange({
      currentPassword: 'same-fixture-value-1234',
      newPassword: 'same-fixture-value-1234',
      confirmPassword: 'same-fixture-value-1234',
    }).ok,
    false,
  );
  // Missing current password.
  assert.equal(
    parsePasswordChange({
      currentPassword: '',
      newPassword: 'new-fixture-value-1234',
      confirmPassword: 'new-fixture-value-1234',
    }).ok,
    false,
  );
  // Extra fields.
  assert.equal(
    parsePasswordChange({
      currentPassword: 'a-value',
      newPassword: 'new-fixture-value-1234',
      confirmPassword: 'new-fixture-value-1234',
      userId: 'someone-else',
    }).ok,
    false,
  );
});

void test('account evidence records the fact and never the credential', () => {
  for (const action of ['account.profile.update', 'account.password.change']) {
    const entry = evidenceAction(action);
    assert.ok(entry, `${action} must be catalogued`);
    assert.equal(entry.resourceType, 'user');
    assert.ok(source(entry.route).includes(action), `${action} must be recorded by ${entry.route}`);
  }

  // A credential rotation is critical: an unprovable one must surface.
  assert.equal(evidenceAction('account.password.change')?.critical, true);

  // Every credential-shaped key is dropped, whatever a caller supplies.
  const narrowed = narrowEvidenceMetadata('account.password.change', {
    revokedOtherSessions: true,
    password: 'should-never-appear',
    passwordHash: 'should-never-appear',
    currentPassword: 'should-never-appear',
    newPassword: 'should-never-appear',
    confirmPassword: 'should-never-appear',
    sessionToken: 'should-never-appear',
    cookie: 'should-never-appear',
  });
  assert.deepEqual(narrowed, { revokedOtherSessions: true });

  const profile = narrowEvidenceMetadata('account.profile.update', {
    field: 'displayName',
    // The value itself is user text and must not accumulate in the trail.
    displayName: 'should-never-appear',
    email: 'should-never-appear',
  });
  assert.deepEqual(profile, { field: 'displayName' });
});

void test('the account server module never handles a credential itself', () => {
  const account = source('lib/server/account.ts');
  // Password work is delegated to Better Auth, not reimplemented.
  assert.match(account, /auth\.api\.changePassword/);
  assert.match(account, /revokeOtherSessions: true/);
  // No hashing of its own, and no SQL against the credential table. These
  // target statements rather than the word "account.password", which the prose
  // in that module uses when explaining what it deliberately leaves alone — a
  // comment is not a read.
  assert.doesNotMatch(account, /bcrypt|scrypt|argon|createHash/);
  assert.doesNotMatch(account, /FROM account|UPDATE account|INTO account/);
  // Identity always comes from the session.
  assert.match(account, /input\.session\.user\.id/);
  assert.doesNotMatch(account, /body\.userId|params\.userId/);
  // A suspended account fails closed on every mutation.
  assert.match(account, /session\.actor\.suspended/);
});

void test('account routes are authenticated, bounded, and rate limited', () => {
  const profileRoute = source('app/api/account/route.ts');
  const passwordRoute = source('app/api/account/password/route.ts');

  for (const route of [profileRoute, passwordRoute]) {
    assert.match(route, /requireApiSession/);
    assert.match(route, /enforceRateLimit/);
    assert.match(route, /readBoundedJson/);
    assert.match(route, /application\/json/);
    // No id is accepted from the caller anywhere in the account surface.
    assert.doesNotMatch(route, /params.*userId/);
  }

  // A credential rotation gets the strict hourly budget, not the write budget.
  assert.match(passwordRoute, /enforceRateLimit\(\s*'auth:reset'/);
  // Nothing echoes the submitted body back.
  assert.doesNotMatch(passwordRoute, /newPassword:.*payload|body: parsed/);
});

void test('the sign-in address is honest about verification and about being unchangeable', () => {
  assert.equal(EMAIL_CHANGE_AVAILABILITY.available, false);
  assert.match(EMAIL_CHANGE_AVAILABILITY.reason, /verify/i);

  const view = source('components/account-view.tsx');
  // The UI states the restriction rather than showing a form that cannot work.
  assert.match(view, /account\.emailChange\.reason/);
  // Verification state is rendered from the stored flag, never assumed.
  assert.match(view, /account\.emailVerified \? 'verified' : 'unverified'/);
  // No token is ever rendered in the session list.
  assert.doesNotMatch(view, /\.token|sessionToken/);
});

void test('the shell identifies the account by name, and the page shows the address', () => {
  const shell = source('components/cloud-shell.tsx');
  assert.match(shell, /displayName\(user\)/);
  // The full address is no longer the primary shell identity.
  assert.doesNotMatch(shell, /\{user\.email\}/);

  assert.equal(accountDisplayName({ name: 'Ada Lovelace', email: 'a@b.invalid' }), 'Ada Lovelace');
  // Falls back to the local part, never the whole address.
  assert.equal(accountDisplayName({ name: '   ', email: 'ada@b.invalid' }), 'ada');
  assert.equal(accountInitials('Ada Lovelace', 'a@b.invalid'), 'AL');
  assert.equal(accountInitials('', 'ada.lovelace@b.invalid'), 'AL');
});

void test('Phase 13 catalog grew by exactly the two implemented account actions', () => {
  const accountActions = EVIDENCE_ACTIONS.filter((entry) =>
    entry.action.startsWith('account.'),
  ).map((entry) => entry.action);
  // Email change and session revocation are deliberately absent: the first is
  // blocked by verification architecture, the second already audits through the
  // existing `session.revoke` path rather than a new action.
  assert.deepEqual(accountActions.sort(), [
    'account.password.change',
    'account.profile.update',
  ]);
});

/**
 * Both of these were found by the local authenticated acceptance run, not by
 * reading the code, and both looked like a success from the server's side.
 */
void test('the password change keeps the browser that made it signed in', () => {
  const server = source('lib/server/account.ts');
  const route = source('app/api/account/password/route.ts');

  // Better Auth revokes the other sessions by rotating this one's token and
  // returning it as a Set-Cookie on ITS response. Called server-side, that
  // response is discarded — so the headers have to be asked for...
  assert.match(server, /returnHeaders: true/);
  assert.match(server, /setCookie = changed\.headers\.getSetCookie\(\)/);
  assert.match(server, /revokedOtherSessions: true, setCookie/);

  // ...and replayed onto the response the browser actually receives, appended
  // so the rate-limit headers are not dropped.
  assert.match(route, /for \(const cookie of result\.setCookie \?\? \[\]\) headers\.append\(\s*'Set-Cookie',\s*cookie,?\s*\)/);
  // The cookie is passed through, never inspected or logged.
  assert.doesNotMatch(route, /console\.(log|warn|error)/);
});

void test('the profile echoed after a rename is the stored one, not the request snapshot', () => {
  const server = source('lib/server/account.ts');

  // The session is resolved before the UPDATE, so reading the name from it
  // returns the previous value and the Account page snaps back.
  assert.match(
    server,
    /SELECT name, email, emailVerified, createdAt, passwordChangedAt FROM "user" WHERE id = \?/,
  );
  assert.match(server, /const name = row\?\.name \?\? session\.user\.name;/);
  assert.match(server, /const email = row\?\.email \?\? session\.user\.email;/);
  assert.match(server, /initials: accountInitials\(name, email\)/);

  // Still exactly one user row read: the fix must not add a query.
  assert.equal(server.match(/FROM "user" WHERE id = \?/g)?.length, 1);
});
