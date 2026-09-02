import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { selectMembership, selectWorkspace } from '../lib/context-fallback.ts';

function source(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

/**
 * Fixtures only. These are shapes, not credentials — no password, token, or
 * real address appears anywhere in this file.
 */
const MEMBERSHIPS = [
  { organizationId: 'org_current' },
  { organizationId: 'org_second' },
] as const;

const WORKSPACES = [{ id: 'ws_current' }, { id: 'ws_second' }] as const;

void test('a valid preference is honoured and reports no repair', () => {
  const org = selectMembership(MEMBERSHIPS, 'org_second');
  assert.equal(org.selected?.organizationId, 'org_second');
  assert.equal(org.repaired, false);

  const workspace = selectWorkspace(WORKSPACES, 'ws_second');
  assert.equal(workspace.selected?.id, 'ws_second');
  assert.equal(workspace.repaired, false);
});

void test('no preference selects the first membership without claiming a repair', () => {
  for (const absent of [undefined, null, '']) {
    const org = selectMembership(MEMBERSHIPS, absent);
    assert.equal(org.selected?.organizationId, 'org_current');
    assert.equal(org.repaired, false, String(absent));

    const workspace = selectWorkspace(WORKSPACES, absent);
    assert.equal(workspace.selected?.id, 'ws_current');
    assert.equal(workspace.repaired, false, String(absent));
  }
});

/**
 * The regression test for the exact defect.
 *
 * A year-long `HttpOnly` cookie named an organization the account can no longer
 * reach. The old code returned `null`, `readSession` reported "no session", and
 * a completely valid login bounced back to `/sign-in` permanently. The user
 * could not clear the cookie themselves because it is `HttpOnly`.
 */
void test('a stale organization preference falls back instead of signing the user out', () => {
  const stale = selectMembership(MEMBERSHIPS, 'org_the_user_left');

  // The critical assertion: a real membership, not null.
  assert.notEqual(stale.selected, null, 'a valid session must never resolve to no access');
  assert.equal(stale.selected?.organizationId, 'org_current');
  // And the caller is told, so it can rewrite the stale cookie.
  assert.equal(stale.repaired, true);
});

void test('a stale workspace preference falls back within the resolved organization', () => {
  const stale = selectWorkspace(WORKSPACES, 'ws_archived_last_year');
  assert.notEqual(stale.selected, null);
  assert.equal(stale.selected?.id, 'ws_current');
  assert.equal(stale.repaired, true);
});

void test('a workspace belonging to another organization cannot be selected', () => {
  // The caller passes a list already scoped to the resolved organization, so a
  // foreign id simply is not present and the fallback stays inside the tenant.
  const foreign = selectWorkspace(WORKSPACES, 'ws_belonging_to_org_two');
  assert.equal(foreign.selected?.id, 'ws_current');
  assert.ok(
    WORKSPACES.some((workspace) => workspace.id === foreign.selected?.id),
    'the fallback must come from the scoped candidate list',
  );
  assert.equal(foreign.repaired, true);
});

void test('no valid membership still fails closed', () => {
  // A suspended or removed member arrives here with an empty list, and an empty
  // list must stay "no access" — the fallback must not invent one.
  const none = selectMembership([], 'org_current');
  assert.equal(none.selected, null);
  assert.equal(none.repaired, false, 'nothing was repaired because nothing was available');

  const noWorkspace = selectWorkspace([], 'ws_current');
  assert.equal(noWorkspace.selected, null);
  assert.equal(noWorkspace.repaired, false);
});

void test('the resolver uses the fallback and reports a repaired context', () => {
  const organizations = source('lib/server/organizations.ts');
  assert.match(organizations, /selectMembership\(memberships, input\.organizationId\)/);
  assert.match(organizations, /selectWorkspace\(workspaces, input\.workspaceId\)/);
  assert.match(organizations, /repairedContext: organizationRepaired \|\| workspaceRepaired/);
  // The scoped SQL that makes the fallback safe must stay in place.
  assert.match(organizations, /m\.status = 'active' AND m\.suspendedAt IS NULL/);
});

void test('signing out clears the stored context preference', () => {
  const route = source('app/api/context/route.ts');
  assert.match(route, /export async function DELETE/);
  assert.match(route, /ysd_organization/);
  assert.match(route, /ysd_workspace/);
  assert.match(route, /Max-Age=0/);

  const shell = source('components/cloud-shell.tsx');
  // Both sign-out paths clear it, not just the ordinary one.
  assert.equal((shell.match(/clearStoredContext\(\)/g) ?? []).length >= 2, true);
  assert.match(shell, /await clearStoredContext\(\);\s*\n\s*await signOut\(\)/);
});

void test('login redirects exactly once and never through a router push', () => {
  const form = source('components/auth-form.tsx');
  // One full document load, and only one.
  assert.equal((form.match(/window\.location\.assign\('\/'\)/g) ?? []).length, 1);
  // No client-side navigation call. Matched with a paren so the surrounding
  // comment explaining *why* `router.push` is avoided does not fail the test.
  assert.doesNotMatch(form, /router\.(?:push|replace)\(/);
});

/**
 * The performance regression.
 *
 * Production has 67 tables, and `listTables` walks each one with a PRAGMA and a
 * COUNT — 1 + 67×2 = 135 sequential D1 round-trips. That ran on the exact page
 * sign-in lands on.
 */
void test('the dashboard never triggers a full table inventory', () => {
  const usage = source('lib/server/usage.ts');

  // The expensive walk is now opt-in and named.
  assert.match(usage, /databaseRows: 'inventory' \| 'summary'/);
  assert.match(usage, /scope\.databaseRows === 'inventory'/);
  // The cheap path costs two statements, and neither is per-table.
  assert.match(usage, /FROM sqlite_master/);
  assert.match(usage, /FROM usage_snapshot WHERE workspaceId = \? ORDER BY capturedAt DESC LIMIT 1/);
  // `summarizeUsage` — what every interactive page calls — defaults to cheap.
  assert.match(usage, /databaseRows = 'summary'/);

  // The dashboard reaches usage only through summarizeUsage, never listTables.
  const dashboard = source('app/page.tsx');
  assert.doesNotMatch(dashboard, /listTables/);
  assert.match(dashboard, /summarizeUsage/);
});

void test('only the scheduled collector pays for the exact inventory', () => {
  const retention = source('lib/server/retention.ts');
  // The cron snapshot is the single caller that walks the tables.
  assert.match(retention, /databaseRows: 'inventory'/);

  // The interactive capacity API must not.
  const capacityApi = source('app/api/retention/route.ts');
  assert.match(capacityApi, /databaseRows: 'summary'/);
  assert.doesNotMatch(capacityApi, /databaseRows: 'inventory'/);
});

void test('usage no longer performs two independent full inventories', () => {
  const section = source('app/[section]/page.tsx');
  // The page computes readings once and hands them to the lifecycle state
  // rather than letting it collect a second time.
  assert.match(section, /readings: usage\.readings/);

  // `listTables` still appears in this file, but only for Studio. Slice the
  // usage branch out and prove the expensive walk is not in it — asserting the
  // whole file is free of it would be wrong, because Studio genuinely needs it.
  const usageCase = section.slice(
    section.indexOf("case 'usage': {"),
    section.indexOf("case 'shield': {"),
  );
  assert.ok(usageCase.length > 0, 'the usage branch must be locatable');
  assert.doesNotMatch(usageCase, /listTables/);
  assert.match(usageCase, /summarizeUsage/);

  const databasesCase = section.slice(section.indexOf("case 'databases': {"));
  assert.match(databasesCase.slice(0, 600), /listTables/);
});

void test('Studio keeps its exact table metadata', () => {
  // The detailed walk still exists for the surface that genuinely needs it;
  // this phase moved it off the interactive dashboard, it did not delete it.
  const studio = source('lib/server/studio.ts');
  assert.match(studio, /export async function listTables/);
  assert.match(studio, /PRAGMA table_info/);
});

void test('the context fallback never widens the candidate list itself', () => {
  const fallback = source('lib/context-fallback.ts');
  // No querying, no filtering, no tenant logic — the scoping stays in SQL.
  assert.doesNotMatch(fallback, /SELECT |FROM |query\(|execute\(/);
  assert.doesNotMatch(fallback, /organizationId ===\s*undefined/);
});
