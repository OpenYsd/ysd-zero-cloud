import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { EVIDENCE_ACTIONS } from '../lib/audit-actions.ts';
import type { AppArtifact } from '../lib/domain.ts';
import {
  boundedReleasePageSize,
  classifyRelease,
  evaluateRollbackEligibility,
  parsePrunedArtifactIds,
  parseReleaseCursor,
  releaseLabel,
  releaseStatusLabel,
  RELEASE_PAGE_MAXIMUM,
  RELEASE_PAGE_SIZE,
  rollbackReasonMessage,
  type RollbackEligibilityInput,
  type RollbackReasonCode,
} from '../lib/releases.ts';

/**
 * Source text with line endings normalised. The working tree is checked out
 * with CRLF on Windows, so multi-line extraction patterns below would
 * otherwise match on one machine and silently fail on another.
 */
function source(file: string): string {
  return readFileSync(new URL(`../${file}`, import.meta.url), 'utf8')
    .split(String.fromCharCode(13))
    .join('');
}

/**
 * The physical invariant Phase 17 is built on.
 *
 * The Node Agent resolves an artifact's bytes at
 * `<root>/workspaces/<ws>/projects/<prj>/deployments/<deploymentId>/artifacts/<artifactId>`,
 * and the `deploymentId` in that path is the one carried by the job payload --
 * the deployment being acted on, not the deployment the artifact was built
 * for. So an artifact only exists, on disk, underneath its own deployment.
 *
 * Everything else in this file follows from that one fact.
 */
void test('artifact bytes are addressed under their own deployment directory', () => {
  const agent = source('agent/app-runtime.ts');
  const directory = agent.match(/function artifactDirectory\([^)]*\)[^{]*\{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.match(directory, /deploymentDirectory\(/, 'artifacts must hang off the deployment directory');
  const deployment = agent.match(/function deploymentDirectory\([^)]*\)[^{]*\{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.match(deployment, /payload\.deploymentId/, 'the directory is keyed by the payload deployment');
  assert.ok(
    !directory.includes('targetDeploymentId'),
    'Phase 17 does not add a second deployment id to the wire contract',
  );
});

void test('the rollback target query agrees on every scope, deployment included', () => {
  const server = source('lib/server/deployments.ts');
  const query = server.match(
    /SELECT id, deploymentId, projectId, nodeId, version, state, checksum[\s\S]*?FROM app_artifact([\s\S]*?)`/,
  )?.[1];
  assert.ok(query, 'the rollback target lookup was not found');
  for (const scope of ['workspaceId = ?', 'projectId = ?', 'deploymentId = ?', 'nodeId = ?', 'id = ?']) {
    assert.ok(query.includes(scope), `the rollback target lookup must scope by ${scope}`);
  }
  assert.match(query, /deletedAt IS NULL/, 'a deleted artifact is never a rollback target');
});

void test('rollback never enters the build or source-fetch path', () => {
  const agent = source('agent/app-runtime.ts');
  const handler = agent.match(/const selectedArtifact = payload\.operation === 'rollback'[\s\S]*?healthCheck\(/)?.[0];
  assert.ok(handler, 'the rollback activation path was not found');
  for (const forbidden of ['downloadSource', 'installDependencies', 'runBuild', 'api.github.com', 'npm']) {
    assert.ok(!handler.includes(forbidden), `rollback must not reach ${forbidden}`);
  }
  assert.match(handler, /verifyArtifact\(/, 'rollback verifies the artifact before activating it');
});

void test('a new release reuses the deploy wire verb rather than widening the protocol', () => {
  const runtime = source('lib/app-runtime.ts');
  const operations = runtime.match(/APP_RUNTIME_OPERATIONS = \[([\s\S]*?)\]/)?.[1] ?? '';
  assert.ok(!operations.includes("'release'"), 'the wire operation set stays as agent 0.4.0 knows it');
  const keys = runtime.match(/onlyKeys\(value, \[([\s\S]*?)\]\)/)?.[1] ?? '';
  assert.ok(!keys.includes('targetDeploymentId'), 'the payload key allowlist is unchanged');
  assert.ok(!keys.includes('prunedArtifactIds'), 'pruning is reported in the result, never the payload');
});

void test('the release action records its own kind without inventing a wire operation', () => {
  const server = source('lib/server/deployments.ts');
  assert.ok(server.includes('RELEASE_ACTION_KIND'), 'the release action kind is named once');
  assert.ok(
    server.includes("operation: 'redeploy'"),
    'a release is queued as the rebuild-and-activate verb the agent already speaks',
  );
});

void test('deployment.rollback is a single catalogued action carrying outcome, not three actions', () => {
  const actions: readonly string[] = EVIDENCE_ACTIONS.map((entry) => entry.action);
  assert.ok(actions.includes('deployment.rollback'), 'rollback needs its own evidence action');
  for (const invented of ['deployment.rollback.success', 'deployment.rollback.failed', 'deployment.rollback.denied']) {
    assert.ok(!actions.includes(invented), `${invented} duplicates the outcome field`);
  }
  const entry = EVIDENCE_ACTIONS.find((item) => item.action === 'deployment.rollback')!;
  const keys: readonly string[] = entry.metadataKeys;
  for (const key of ['targetArtifactId', 'fromArtifactId', 'reasonCodes']) {
    assert.ok(keys.includes(key), `rollback evidence must record ${key}`);
  }
  for (const forbidden of ['checksum', 'manifest', 'path', 'token', 'environment']) {
    assert.ok(!keys.includes(forbidden), `rollback evidence must not carry ${forbidden}`);
  }
});

void test('Phase 17 adds no migration and no second cron', () => {
  const ledger = source('lib/server/db.ts');
  const migrations = source('wrangler.jsonc');
  assert.ok(!ledger.includes('0020_'), 'Phase 17 introduces no migration 0020');
  assert.equal(
    (migrations.match(/\* \* \* \* \*/g) ?? []).length,
    1,
    'the single one-minute cron trigger stays single',
  );
});

const DEPLOYMENT = {
  id: 'dpl_aaaaaaaaaaaaaaaaaaaaaaaa',
  projectId: 'prj_bbbbbbbbbbbbbbbbbbbbbbbb',
  nodeId: 'node_cccccccccccccccccccccccc',
  state: 'healthy',
  currentArtifactId: 'art_111111111111111111111111',
  deletedAt: null,
};

const READY_NODE = { status: 'online' as const, appRuntimeAvailable: true, blockers: [] as string[] };

function artifact(overrides: Partial<AppArtifact> = {}): AppArtifact {
  return {
    id: 'art_222222222222222222222222',
    deploymentId: DEPLOYMENT.id,
    projectId: DEPLOYMENT.projectId,
    nodeId: DEPLOYMENT.nodeId,
    commitSha: 'a'.repeat(40),
    version: 2,
    state: 'verified',
    checksum: `sha256:${'b'.repeat(64)}`,
    sizeBytes: 1_024,
    createdAt: 1,
    verifiedAt: 2,
    activatedAt: null,
    ...overrides,
  };
}

function reasons(input: Partial<RollbackEligibilityInput> = {}): RollbackReasonCode[] {
  return evaluateRollbackEligibility({
    artifact: artifact(),
    deployment: DEPLOYMENT,
    node: READY_NODE,
    ...input,
  }).reasons;
}

void test('a verified earlier release on the same deployment and node is restorable', () => {
  const verdict = evaluateRollbackEligibility({
    artifact: artifact(),
    deployment: DEPLOYMENT,
    node: READY_NODE,
  });
  assert.equal(verdict.eligible, true);
  assert.deepEqual(verdict.reasons, []);
});

void test('the running release is never a rollback target', () => {
  assert.ok(reasons({ artifact: artifact({ id: DEPLOYMENT.currentArtifactId }) }).includes('current_release'));
});

void test('only a verified artifact is restorable', () => {
  assert.ok(reasons({ artifact: artifact({ state: 'building' }) }).includes('artifact_unverified'));
  assert.ok(reasons({ artifact: artifact({ state: 'failed' }) }).includes('artifact_unverified'));
  assert.ok(reasons({ artifact: artifact({ state: 'corrupted' }) }).includes('artifact_corrupted'));
  assert.ok(reasons({ artifact: artifact({ state: 'deleted' }) }).includes('artifact_deleted'));
});

void test('an artifact from another deployment, project or node is refused', () => {
  assert.ok(reasons({ artifact: artifact({ deploymentId: 'dpl_dddddddddddddddddddddddd' }) }).includes('wrong_deployment'));
  assert.ok(reasons({ artifact: artifact({ projectId: 'prj_dddddddddddddddddddddddd' }) }).includes('wrong_project'));
  assert.ok(reasons({ artifact: artifact({ nodeId: 'node_dddddddddddddddddddddddd' }) }).includes('wrong_node'));
});

void test('an unknown artifact reads the same as a foreign one', () => {
  // The scoped lookup returns nothing for either, so neither answer reveals
  // that a row exists somewhere else.
  const verdict = evaluateRollbackEligibility({ artifact: null, deployment: DEPLOYMENT, node: READY_NODE });
  assert.deepEqual(verdict.reasons, ['artifact_missing']);
});

void test('node readiness gates rollback', () => {
  for (const status of ['stale', 'offline', 'revoked'] as const) {
    assert.ok(reasons({ node: { ...READY_NODE, status } }).includes('node_offline'), status);
  }
  assert.ok(reasons({ node: { ...READY_NODE, appRuntimeAvailable: false } }).includes('runtime_unavailable'));
  assert.ok(reasons({ node: { ...READY_NODE, blockers: ['agent-protocol'] } }).includes('node_incompatible'));
});

void test('a deployment mid-action refuses a second lifecycle action', () => {
  for (const state of ['queued', 'building', 'starting', 'rolling_back', 'stopping', 'deleting']) {
    assert.ok(reasons({ deployment: { ...DEPLOYMENT, state } }).includes('deployment_busy'), state);
  }
  assert.ok(reasons({ deployment: { ...DEPLOYMENT, state: 'blocked' } }).includes('deployment_unavailable'));
  assert.ok(reasons({ deployment: { ...DEPLOYMENT, deletedAt: 1 } }).includes('deployment_unavailable'));
});

void test('a stopped or failed deployment can still be rolled back', () => {
  // Rollback is how someone recovers from a bad release, so a deployment that
  // is down is exactly when it matters most.
  for (const state of ['stopped', 'failed', 'crash_loop']) {
    const verdict = evaluateRollbackEligibility({
      artifact: artifact(),
      deployment: { ...DEPLOYMENT, state },
      node: READY_NODE,
    });
    assert.equal(verdict.eligible, true, `${state} should still allow a rollback`);
  }
});

void test('node facts are optional so a history page costs one node read', () => {
  const verdict = evaluateRollbackEligibility({ artifact: artifact(), deployment: DEPLOYMENT, node: null });
  assert.equal(verdict.eligible, true);
});

void test('release status never calls a superseded build healthy', () => {
  assert.equal(classifyRelease({ artifact: artifact({ id: DEPLOYMENT.currentArtifactId }), currentArtifactId: DEPLOYMENT.currentArtifactId }), 'current');
  assert.equal(classifyRelease({ artifact: artifact(), currentArtifactId: DEPLOYMENT.currentArtifactId }), 'superseded');
  assert.equal(classifyRelease({ artifact: artifact({ state: 'failed' }), currentArtifactId: null }), 'failed');
  assert.equal(classifyRelease({ artifact: artifact({ state: 'corrupted' }), currentArtifactId: null }), 'corrupted');
  assert.equal(classifyRelease({ artifact: artifact({ state: 'deleted' }), currentArtifactId: null }), 'unavailable');
  for (const status of ['current', 'superseded', 'building', 'failed', 'corrupted', 'unavailable'] as const) {
    assert.doesNotMatch(releaseStatusLabel(status), /\bhealthy\b/i, status);
  }
});

void test('a failed release does not become current merely by being newest', () => {
  // The pointer is what decides, so a newer failed artifact classifies as
  // failed while the older running one stays current.
  const failedNewer = artifact({ id: 'art_333333333333333333333333', version: 3, state: 'failed' });
  const runningOlder = artifact({ id: DEPLOYMENT.currentArtifactId, version: 1 });
  assert.equal(classifyRelease({ artifact: failedNewer, currentArtifactId: DEPLOYMENT.currentArtifactId }), 'failed');
  assert.equal(classifyRelease({ artifact: runningOlder, currentArtifactId: DEPLOYMENT.currentArtifactId }), 'current');
});

void test('release labels come from the persisted version and tolerate gaps', () => {
  assert.equal(releaseLabel(1), 'v1');
  assert.equal(releaseLabel(8), 'v8');
});

void test('history pages stay bounded whatever the caller asks for', () => {
  assert.equal(boundedReleasePageSize(undefined), RELEASE_PAGE_SIZE);
  assert.equal(boundedReleasePageSize('nonsense'), RELEASE_PAGE_SIZE);
  assert.equal(boundedReleasePageSize(-5), RELEASE_PAGE_SIZE);
  assert.equal(boundedReleasePageSize(10_000), RELEASE_PAGE_MAXIMUM);
  assert.equal(boundedReleasePageSize({}), RELEASE_PAGE_SIZE);
  assert.equal(boundedReleasePageSize('30'), 30);
  assert.equal(parseReleaseCursor('12'), 12);
  assert.equal(parseReleaseCursor('0'), null);
  assert.equal(parseReleaseCursor('-1'), null);
  assert.equal(parseReleaseCursor("1; DROP TABLE app_artifact"), null);
  assert.equal(parseReleaseCursor(12), null);
});

void test('a node can only report artifact ids in the shape the control plane issues', () => {
  const parsed = parsePrunedArtifactIds([
    'art_444444444444444444444444',
    'art_444444444444444444444444',
    'dpl_555555555555555555555555',
    'art_NOTHEX00000000000000000',
    '../../etc/passwd',
    42,
    null,
  ]);
  assert.deepEqual(parsed, ['art_444444444444444444444444']);
  assert.deepEqual(parsePrunedArtifactIds('art_444444444444444444444444'), []);
  assert.deepEqual(parsePrunedArtifactIds(null), []);
  const many = Array.from({ length: 100 }, (_, index) => `art_${String(index).padStart(24, '0')}`);
  assert.equal(parsePrunedArtifactIds(many).length, 32);
});

void test('every refusal reason has fixed wording that leaks nothing', () => {
  const codes: RollbackReasonCode[] = [
    'current_release', 'artifact_missing', 'artifact_unverified', 'artifact_corrupted',
    'artifact_deleted', 'wrong_deployment', 'wrong_project', 'wrong_node', 'node_offline',
    'node_incompatible', 'runtime_unavailable', 'deployment_busy', 'deployment_unavailable',
    'stale_current_release',
  ];
  for (const code of codes) {
    const message = rollbackReasonMessage(code);
    assert.ok(message.length > 10, code);
    assert.doesNotMatch(message, /[\\/]|sha256:|token|art_|dpl_|node_/, `${code} must not expose internals`);
  }
});

void test('a node can only retire artifacts belonging to the job it just ran', () => {
  const control = source('lib/server/app-runtime-control.ts');
  const block = control.match(/const pruned = parsePrunedArtifactIds[\s\S]*?\n  }\n/)?.[0] ?? '';
  assert.ok(block, 'the pruning reconciliation was not found');
  for (const scope of ['workspaceId = ?', 'projectId = ?', 'deploymentId = ?', 'nodeId = ?']) {
    assert.ok(block.includes(scope), `pruning must be re-scoped by ${scope}`);
  }
  assert.ok(
    block.includes('input.job.assignedNodeId'),
    'pruning must be attributed to the node the job was assigned to, not a reported id',
  );
  assert.ok(
    block.includes('filter((id) => id !== artifactId)'),
    'a node must not be able to retire the release it just activated',
  );
  assert.ok(!/state = 'deleted'[\s\S]{0,120}WHERE workspaceId = \?\s*AND id IN/.test(block),
    'pruning must never be scoped by workspace and id alone');
});

void test('a stale job result cannot move a deployment that has moved on', () => {
  const control = source('lib/server/app-runtime-control.ts');
  const update = control.match(/UPDATE deployment\n[\s\S]*?WHERE workspaceId = \? AND id = \? AND jobId = \?/)?.[0];
  assert.ok(update, 'the deployment completion update was not found');
  assert.match(update, /AND jobId = \?$/, 'completion must match the job the deployment currently owns');
});

void test('the deployment commit follows the release that actually activated', () => {
  const control = source('lib/server/app-runtime-control.ts');
  assert.match(
    control,
    /commitSha = CASE WHEN \? = 1 AND \? IS NOT NULL/,
    'the deployment commit must only move on a successful activation',
  );
  assert.ok(
    control.includes('SELECT commitSha FROM app_artifact WHERE workspaceId = ? AND id = ?'),
    'the commit must be read from the artifact that activated, not supplied by the node',
  );
});

void test('rollback and release reuse the existing deployment permissions', () => {
  const roles = source('lib/roles.ts');
  const policy = roles.match(/if \(pathname\.startsWith\('\/api\/deployments'\)\).*/)?.[0] ?? '';
  assert.ok(policy.includes("read ? 'deployment.read'"), 'reading history stays a read permission');
  assert.ok(policy.includes("'deployment.lifecycle'"), 'writing stays a lifecycle permission');
  // Both new routes live under /api/deployments, so they inherit that policy
  // rather than introducing a parallel permission model.
  for (const file of ['app/api/deployments/[id]/releases/route.ts', 'app/api/deployments/[id]/rollback/route.ts']) {
    const route = source(file);
    assert.ok(route.includes('requireApiSession'), `${file} must authenticate`);
    assert.ok(route.includes('auth.session.workspace.id'), `${file} must scope to the session workspace`);
    assert.ok(route.includes('allowedProjectIds'), `${file} must honour project restrictions`);
  }
});

void test('a preview writes nothing and the executor trusts nothing it returned', () => {
  const rollback = source('app/api/deployments/[id]/rollback/route.ts');
  const get = rollback.match(/export async function GET[\s\S]*?\n}/)?.[0] ?? '';
  assert.ok(get, 'the preview handler was not found');
  for (const mutation of ['createDeploymentAction', 'enqueueJob', 'recordEvidence', 'execute(']) {
    assert.ok(!get.includes(mutation), `a preview must not ${mutation}`);
  }
  const post = rollback.match(/export async function POST[\s\S]*?\n}/)?.[0] ?? '';
  assert.ok(
    post.includes("new Set(['targetArtifactId', 'expectedCurrentArtifactId'])"),
    'execute accepts only the target and the expected current release',
  );
  assert.ok(!post.includes('previewRollback'), 'execute re-derives eligibility rather than replaying a preview');

  const server = source('lib/server/releases.ts');
  for (const mutation of ['INSERT INTO', 'UPDATE ', 'DELETE FROM', 'enqueueJob']) {
    assert.ok(!server.includes(mutation), `the release read model must not ${mutation.trim()}`);
  }
});

void test('history and preview cost a fixed number of reads regardless of page size', () => {
  const server = source('lib/server/releases.ts');
  const from = server.indexOf('export async function listReleases');
  const list = from < 0 ? '' : server.slice(from, server.indexOf('export type RollbackPreview'));
  assert.ok(list.length > 500, 'listReleases was not found');
  // One deployment read, one node read, one artifact page. Node readiness is
  // resolved once and handed to every row, so a page never fans out.
  assert.equal((list.match(/await query</g) ?? []).length, 1, 'the artifact page is a single query');
  assert.equal((list.match(/nodeFacts\(/g) ?? []).length, 1, 'node readiness is resolved once per page');
  assert.ok(list.includes('LIMIT ?'), 'the page is bounded in SQL, not in memory');
  assert.ok(!/for \([\s\S]*?await /.test(list), 'no per-row awaits');
});

void test('a release takes its repository from the deployment, never from the caller', () => {
  const server = source('lib/server/deployments.ts');
  const release = server.match(/export async function createRelease[\s\S]*?\n}\n/)?.[0] ?? '';
  assert.ok(release, 'createRelease was not found');
  assert.ok(
    release.includes('repository: detail.repository'),
    'the repository must come from the stored deployment',
  );
  assert.ok(release.includes('inspectRepositoryForDeploy'), 'the release reuses the guarded source inspection');
  assert.ok(release.includes('plan.contract'), 'the build contract is rebuilt from the new commit');
  // The service identity is what makes this a release rather than a new deployment.
  assert.ok(release.includes('port: detail.localPort'), 'a release keeps the service port');
  assert.ok(release.includes('deploymentId: detail.id'), 'a release keeps the deployment');
  assert.ok(
    !/currentArtifactId\s*=/.test(release),
    'a release must not move the current pointer before the node reports health',
  );
});

void test('the release route refuses fields outside its contract', () => {
  const route = source('app/api/deployments/[id]/releases/route.ts');
  assert.ok(route.includes("new Set(['branch', 'commit'])"), 'only a branch or commit may be chosen');
  assert.ok(route.includes('status: 400'), 'unexpected fields are refused, not ignored');
});

void test('a redeploy rebuilds the release that is running, not the one first deployed', () => {
  // Before Phase 17 a deployment only ever had one commit, so the stored plan
  // and the running release could not disagree. They can now: shipping a new
  // release leaves `plan` describing the original commit. A redeploy that read
  // the plan would quietly rebuild an older version of the application.
  const server = source('lib/server/deployments.ts');
  assert.ok(server.includes('let redeploySource = detail.plan.source;'), 'redeploy resolves its own source');
  assert.ok(
    server.includes('SELECT manifest FROM app_artifact'),
    'redeploy reads the running artifact manifest',
  );
  assert.ok(
    server.includes('commit: redeploySource.commit'),
    'the queued job carries the running commit',
  );
  assert.ok(
    !server.includes('commit: detail.plan.source.commit'),
    'the original plan commit is no longer what a redeploy rebuilds',
  );
});

void test('the build temp directory stays short enough for the platform path limit', () => {
  // A package manager creates its own subdirectories under TMP. When TMP sat
  // inside the artifact -- roughly two hundred characters down, past
  // workspaces/projects/deployments/artifacts -- those subdirectories overran
  // the Windows 260-character limit and npm retried the failing path forever:
  // a pinned core, no output at all, until the build timeout reported only
  // "The operation was aborted". Measured threshold on the acceptance machine
  // was between 234 (built fine) and 241 (hung) characters.
  const agent = source('agent/app-runtime.ts');
  const temp = agent.match(/function buildTempDirectory\([^)]*\)[^{]*\{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.ok(temp, 'buildTempDirectory was not found');
  assert.ok(temp.includes('safeRoot(root)'), 'the build temp directory hangs off the agent root');
  assert.ok(!temp.includes('artifactDirectory'), 'it must not nest inside the artifact directory');
  assert.ok(!temp.includes('deployments'), 'it must not repeat the deep deployment path');

  const installFrom = agent.indexOf('async function installDependencies');
  const install = installFrom < 0
    ? ''
    : agent.slice(installFrom, agent.indexOf('async function verifyExtractedContract'));
  assert.ok(install.length > 400, 'installDependencies was not found');
  assert.ok(install.includes('input.tempDirectory'), 'the installer takes the short temp directory');
  assert.ok(
    !install.includes("path.join(input.artifactDirectory, '.ysd-tmp')"),
    'the old artifact-nested temp directory must not come back',
  );

  // The depth the fix actually buys: root + "tmp" + one artifact id, versus the
  // full workspaces/projects/deployments/artifacts chain it replaced.
  const artifactId = 'art_' + 'a'.repeat(24);
  const root = 'C:\\Users\\operator\\AppData\\Local\\Temp\\ysd-agent\\.ysd-app-runtime';
  const shortTemp = [root, 'tmp', artifactId].join('\\');
  const nestedTemp = [
    root, 'workspaces', 'ws_' + 'b'.repeat(24), 'projects', 'prj_' + 'c'.repeat(24),
    'deployments', 'dpl_' + 'd'.repeat(24), 'artifacts', artifactId, '.ysd-tmp',
  ].join('\\');
  assert.ok(shortTemp.length < 160, `short temp path is ${shortTemp.length} characters`);
  assert.ok(nestedTemp.length > 200, `the old layout reached ${nestedTemp.length} characters`);
  assert.ok(
    nestedTemp.length - shortTemp.length > 100,
    'the fix must reclaim real headroom, not a few characters',
  );
});

void test('a retry with the same idempotency key resolves before the busy guard', () => {
  // A retried request is the same request. If the in-progress guard answers
  // first, a client that retries after a dropped response gets "already in
  // progress" and cannot tell that from a real conflict -- while a different
  // key during a running action still has to be refused.
  const server = source('lib/server/deployments.ts');
  for (const fn of ['createDeploymentAction', 'createRelease']) {
    const from = server.indexOf(`export async function ${fn}`);
    assert.ok(from > 0, `${fn} was not found`);
    const body = server.slice(from, from + 4000);
    const idempotency = body.indexOf('WHERE workspaceId = ? AND idempotencyKey = ?');
    const busy = body.indexOf('A deployment action is already in progress.');
    assert.ok(idempotency > 0 && busy > 0, `${fn} is missing one of the two guards`);
    assert.ok(
      idempotency < busy,
      `${fn} must answer idempotency before refusing as busy`,
    );
  }
});
