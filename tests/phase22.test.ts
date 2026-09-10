import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  APP_RUNTIME_OPERATIONS,
  appRuntimeLeaseDuration,
  validateAppRuntimeJobPayload,
  type AppRuntimeJobPayload,
} from '../lib/app-runtime.ts';
import {
  backupReasonMessage,
  BACKUP_REASON_CODES,
  evaluateImportIdentity,
  evaluateRestoreIdentity,
  type ImportIdentity,
} from '../lib/artifact-backup.ts';
import {
  CURRENT_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  parseArtifactBackupCapability,
} from '../lib/nodes.ts';
import { RECOVERY_REASON_CODES, recoveryReasonMessage } from '../lib/runtime-recovery.ts';
import {
  eligibleReplacements,
  importCommand,
  recoveryPhase,
  IMPORT_COMMAND_PLACEHOLDER,
} from '../lib/replacement-recovery.ts';
import { EVIDENCE_ACTIONS } from '../lib/audit-actions.ts';

function source(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

const nodes = source('lib/server/nodes.ts');
const DPL = `dpl_${'1'.repeat(24)}`;
const PRJ = `prj_${'2'.repeat(24)}`;
const DACT = `dact_${'3'.repeat(24)}`;
const NEW_ART = `art_${'4'.repeat(24)}`;
const SOURCE_ART = `art_${'5'.repeat(24)}`;
const CHECKSUM = `sha256:${'a'.repeat(64)}`;

// ---------------------------------------------------------------------------
// The operation contract.
// ---------------------------------------------------------------------------

const importPayload: AppRuntimeJobPayload = {
  operation: 'import',
  deploymentId: DPL,
  projectId: PRJ,
  actionId: DACT,
  artifactId: NEW_ART,
  targetArtifactId: SOURCE_ART,
  source: null,
  contract: {
    version: 1, framework: 'Node.js', packageManager: 'npm', lockfile: 'package-lock.json',
    nodeMajor: 26, installPolicy: 'frozen-lockfile-ignore-scripts', buildPolicy: 'none',
    startPolicy: 'node-entry', entrypoint: 'server.js', envNames: [],
  },
  environment: 'Production',
  environmentCiphertext: null,
  port: 41100,
  healthPath: '/',
  memoryMb: 512,
  diskQuotaBytes: 512 * 1024 * 1024,
  retainArtifacts: 3,
  expectedDesiredRevision: 7,
  protectedArtifactIds: [],
} as AppRuntimeJobPayload;

void test('import is an allowlisted operation and no existing operation moved', () => {
  assert.ok(APP_RUNTIME_OPERATIONS.includes('import'));
  for (const existing of ['deploy', 'start', 'stop', 'restart', 'redeploy', 'rollback', 'recover', 'delete', 'status']) {
    assert.ok(APP_RUNTIME_OPERATIONS.includes(existing as never), existing);
  }
});

void test('an import payload needs both artifacts, the contract, and the revision', () => {
  assert.equal(validateAppRuntimeJobPayload(importPayload).ok, true);
  for (const missing of ['artifactId', 'targetArtifactId', 'contract'] as const) {
    const broken = { ...importPayload, [missing]: null };
    assert.equal(validateAppRuntimeJobPayload(broken).ok, false, missing);
  }
  assert.equal(
    validateAppRuntimeJobPayload({ ...importPayload, expectedDesiredRevision: null }).ok,
    false,
    'revision',
  );
});

void test('import cannot name one artifact as both source and replacement', () => {
  const same = { ...importPayload, targetArtifactId: NEW_ART };
  assert.equal(validateAppRuntimeJobPayload(same).ok, false);
});

void test('import rejects malformed identifiers and unknown keys', () => {
  assert.equal(validateAppRuntimeJobPayload({ ...importPayload, artifactId: 'art_nope' }).ok, false);
  assert.equal(
    validateAppRuntimeJobPayload({ ...importPayload, sourceNodeId: `node_${'6'.repeat(24)}` }).ok,
    false,
    'extra key',
  );
  assert.equal(validateAppRuntimeJobPayload({ ...importPayload, expectedDesiredRevision: 0 }).ok, false);
});

void test('a target artifact stays refused for every operation but rollback and import', () => {
  for (const operation of ['start', 'stop', 'restart', 'recover', 'deploy', 'delete'] as const) {
    const payload = { ...importPayload, operation, targetArtifactId: SOURCE_ART };
    assert.equal(validateAppRuntimeJobPayload(payload).ok, false, operation);
  }
});

void test('recover keeps its own contract unchanged', () => {
  const recover = {
    ...importPayload, operation: 'recover' as const, targetArtifactId: null,
  };
  assert.equal(validateAppRuntimeJobPayload(recover).ok, true);
  assert.equal(
    validateAppRuntimeJobPayload({ ...recover, expectedDesiredRevision: null }).ok,
    false,
  );
});

void test('import leases like an artifact operation, not like a quick action', () => {
  assert.equal(appRuntimeLeaseDuration('import'), appRuntimeLeaseDuration('rollback'));
  assert.ok(appRuntimeLeaseDuration('import') > appRuntimeLeaseDuration('start'));
});

// ---------------------------------------------------------------------------
// The import identity gate, and the same-node restore gate it must not touch.
// ---------------------------------------------------------------------------

const manifest = {
  workspaceId: 'ws_1',
  projectId: PRJ,
  deploymentId: DPL,
  artifactId: SOURCE_ART,
  artifactChecksum: CHECKSUM,
};

const authoritative: ImportIdentity = {
  workspaceId: 'ws_1',
  projectId: PRJ,
  deploymentId: DPL,
  nodeId: `node_${'7'.repeat(24)}`,
  sourceArtifactId: SOURCE_ART,
  replacementArtifactId: NEW_ART,
  checksum: CHECKSUM,
  desiredRevision: 7,
  sourceNodeRevoked: true,
  awaitingImport: true,
};

void test('an authorized import is allowed', () => {
  const result = evaluateImportIdentity({
    manifest, authoritative, authenticatedNodeId: authoritative.nodeId, expectedDesiredRevision: 7,
  });
  assert.deepEqual(result, { allowed: true, reason: null });
});

void test('import refuses a node that does not own the deployment', () => {
  const result = evaluateImportIdentity({
    manifest, authoritative, authenticatedNodeId: `node_${'8'.repeat(24)}`, expectedDesiredRevision: 7,
  });
  assert.deepEqual(result, { allowed: false, reason: 'wrong_node' });
});

void test('import refuses while the source node is still live', () => {
  const result = evaluateImportIdentity({
    manifest,
    authoritative: { ...authoritative, sourceNodeRevoked: false },
    authenticatedNodeId: authoritative.nodeId,
    expectedDesiredRevision: 7,
  });
  assert.deepEqual(result, { allowed: false, reason: 'source_node_live' });
});

void test('import refuses a deployment that was never transferred', () => {
  const result = evaluateImportIdentity({
    manifest,
    authoritative: { ...authoritative, awaitingImport: false },
    authenticatedNodeId: authoritative.nodeId,
    expectedDesiredRevision: 7,
  });
  assert.deepEqual(result, { allowed: false, reason: 'not_transferred' });
});

void test('import refuses a stale transfer revision', () => {
  const result = evaluateImportIdentity({
    manifest, authoritative, authenticatedNodeId: authoritative.nodeId, expectedDesiredRevision: 6,
  });
  assert.deepEqual(result, { allowed: false, reason: 'source_changed' });
});

void test('import refuses a bundle from another deployment or another checksum', () => {
  for (const broken of [
    { ...manifest, deploymentId: `dpl_${'9'.repeat(24)}` },
    { ...manifest, projectId: `prj_${'9'.repeat(24)}` },
    { ...manifest, artifactId: NEW_ART },
    { ...manifest, artifactChecksum: `sha256:${'b'.repeat(64)}` },
  ]) {
    const result = evaluateImportIdentity({
      manifest: broken, authoritative, authenticatedNodeId: authoritative.nodeId,
      expectedDesiredRevision: 7,
    });
    assert.deepEqual(result, { allowed: false, reason: 'identity_mismatch' });
  }
});

void test('ordinary same-node restore is unchanged and still refuses another node', () => {
  const same = {
    workspaceId: 'ws_1', projectId: PRJ, deploymentId: DPL,
    nodeId: `node_${'7'.repeat(24)}`, currentArtifactId: SOURCE_ART, checksum: CHECKSUM,
  };
  assert.deepEqual(
    evaluateRestoreIdentity({ manifest, authoritative: same, authenticatedNodeId: same.nodeId }),
    { allowed: true, reason: null },
  );
  assert.deepEqual(
    evaluateRestoreIdentity({
      manifest, authoritative: same, authenticatedNodeId: `node_${'8'.repeat(24)}`,
    }),
    { allowed: false, reason: 'wrong_node' },
  );
});

void test('every backup and recovery reason code has a message', () => {
  for (const code of BACKUP_REASON_CODES) assert.ok(backupReasonMessage(code).length > 10, code);
  for (const code of RECOVERY_REASON_CODES) assert.ok(recoveryReasonMessage(code).length > 10, code);
  assert.ok(RECOVERY_REASON_CODES.includes('node_lost'));
  assert.ok(RECOVERY_REASON_CODES.includes('awaiting_import'));
});

// ---------------------------------------------------------------------------
// Capability compatibility with the fleet that is already paired.
// ---------------------------------------------------------------------------

void test('a paired 0.8.0 capability still parses and cannot import', () => {
  const shipped = { version: 1, supported: true, offlineVerify: true, sameNodeRestore: true };
  const parsed = parseArtifactBackupCapability(shipped);
  assert.ok(parsed, 'a shipped 0.8.0 capability must not stop parsing');
  assert.notEqual(parsed?.replacementImport, true);
});

void test('a replacement-capable capability parses, and an unsupported claim does not', () => {
  const capable = {
    version: 1, supported: true, offlineVerify: true, sameNodeRestore: true, replacementImport: true,
  };
  assert.equal(parseArtifactBackupCapability(capable)?.replacementImport, true);
  assert.equal(parseArtifactBackupCapability({ ...capable, replacementImport: 'yes' }), null);
  assert.equal(
    parseArtifactBackupCapability({
      version: 1, supported: false, offlineVerify: false, sameNodeRestore: false, replacementImport: true,
    }),
    null,
  );
});

// ---------------------------------------------------------------------------
// Control-plane guarantees that live in SQL. These read the shipped statements
// rather than a database, which is how every prior phase pins server behaviour
// in this repository -- `lib/server` imports `cloudflare:workers` and cannot be
// loaded by the test runner.
// ---------------------------------------------------------------------------

function fn(name: string): string {
  const start = nodes.indexOf(`export async function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist`);
  const next = nodes.indexOf('\nexport async function ', start + 1);
  return nodes.slice(start, next === -1 ? nodes.length : next);
}

void test('declare-lost kills the credential exactly as revoke does', () => {
  const body = fn('declareNodeLost');
  assert.match(body, /revokedAt = \?/);
  assert.match(body, /tokenCiphertext = ''/);
  assert.match(body, /assignmentsDisabledAt = COALESCE/);
});

void test('declare-lost never writes desiredState', () => {
  const body = fn('declareNodeLost');
  const deployment = body.slice(body.indexOf('UPDATE deployment'));
  assert.ok(!/desiredState\s*=/.test(deployment), 'the operator intent must survive the machine');
  assert.match(deployment, /recoveryReasonCode = 'node_lost'/);
  assert.match(deployment, /state = 'blocked'/);
});

void test('declare-lost is latched on the credential write so revisions bump once', () => {
  const body = fn('declareNodeLost');
  assert.match(body, /WHERE workspaceId = \? AND id = \? AND revokedAt IS NULL/);
  const latch = body.indexOf('if (!changed(claimed))');
  assert.notEqual(latch, -1);
  assert.ok(latch < body.indexOf('desiredRevision = COALESCE'), 'the bump must sit behind the latch');
});

void test('declare-lost never touches artifact ownership', () => {
  assert.ok(!/UPDATE app_artifact/.test(fn('declareNodeLost')));
});

void test('generic revoke still stops deployments', () => {
  const body = fn('revokeNode');
  assert.match(body, /state = 'node_revoked', desiredState = 'stopped'/);
});

void test('the transfer is one conditional statement fenced on every precondition', () => {
  const body = fn('transferDeploymentOwnership');
  const cas = body.slice(body.indexOf('const moved = await execute'));
  assert.match(cas, /SET nodeId = \?/);
  assert.match(cas, /desiredRevision = \?/);
  assert.match(cas, /recoveryReasonCode = 'awaiting_import'/);
  assert.match(cas, /AND nodeId = \? AND desiredRevision = \?/);
  assert.match(cas, /AND currentArtifactId = \?/);
  assert.ok(!/desiredState\s*=/.test(cas), 'intent is preserved through the transfer');
  assert.ok(!/localPort\s*=/.test(cas), 'the old port travels as a preference');
  assert.match(body, /if \(!changed\(moved\)\)/);
});

void test('the transfer refuses a live source node and an ineligible replacement', () => {
  const body = fn('transferDeploymentOwnership');
  assert.match(body, /guard\.sourceRevokedAt === null/);
  assert.match(body, /replacementRevokedAt !== null \|\| guard\.replacementDisabledAt !== null/);
  assert.match(body, /artifactState !== 'verified'/);
  assert.match(body, /replacementImport !== true/);
});

void test('the transfer never mutates the source artifact row', () => {
  assert.ok(!/UPDATE app_artifact/.test(fn('transferDeploymentOwnership')));
});

void test('import preflight allocates the artifact id and reads the checksum from the source row', () => {
  const body = fn('readArtifactImportPreflight');
  assert.match(body, /createId\('art'\)/);
  assert.ok(!/body\./.test(body), 'the node supplies nothing but the deployment it asks about');
  assert.match(body, /checksum: row\.sourceChecksum/);
  assert.match(body, /COALESCE\(MAX\(version\), 0\) \+ 1/);
  assert.match(body, /nodeId = \?/);
});


void test('import preflight demands ownership, the awaiting-import block, and a revoked source', () => {
  const body = fn('readArtifactImportPreflight');
  assert.match(body, /row\.nodeId !== context\.node\.id/);
  assert.match(body, /row\.sourceRevokedAt === null/);
  assert.match(body, /row\.sourceRevokedAt === null/);
  assert.match(body, /row\.sourceNodeId === context\.node\.id/);
});

void test('the provisional row is inserted in the existing artifact lifecycle', () => {
  const body = fn('readArtifactImportPreflight');
  assert.match(body, /'building', \?, NULL, 0, \?, NULL, NULL, NULL, 'unknown', NULL/);
  assert.match(body, /kind: 'backup-import'/);
});

void test('import-complete trusts the source row for the checksum, not the request', () => {
  const body = fn('confirmArtifactImport');
  assert.match(body, /constantTimeEqual\(checksum, row\.sourceChecksum\)/);
  assert.match(body, /SET state = 'verified', checksum = \?/);
  assert.ok(/row\.sourceChecksum, sizeBytes/.test(body), 'the recorded checksum is the source one');
});

void test('currentArtifactId flips only after the replacement row is verified', () => {
  const body = fn('confirmArtifactImport');
  const verify = body.indexOf("SET state = 'verified'");
  const flip = body.indexOf('SET currentArtifactId = ?');
  assert.notEqual(verify, -1);
  assert.notEqual(flip, -1);
  assert.ok(verify < flip, 'verification precedes the pointer move');
  assert.match(body, /AND desiredRevision = \?\s+AND currentArtifactId = \?/);
});

void test('import-complete replay is idempotent and a different checksum is refused', () => {
  const body = fn('confirmArtifactImport');
  assert.match(body, /replayed: true/);
  assert.match(body, /A different artifact is already recorded under that id/);
  assert.match(body, /row\.desiredRevision !== expectedDesiredRevision/);
});

void test('import-complete starts no runtime and never writes desiredState', () => {
  const body = fn('confirmArtifactImport');
  assert.ok(!/desiredState\s*=/.test(body));
  assert.ok(!/enqueueJob|'start'|operation: 'start'/.test(body));
});

void test('the block clears only when artifact, node, availability and port all agree', () => {
  const body = fn('clearReplacementImportBlock');
  assert.match(body, /artifactState !== 'verified'/);
  assert.match(body, /artifactNodeId !== context\.node\.id/);
  assert.match(body, /availabilityState !== 'present'/);
  assert.match(body, /row\.localPort === null/);
  assert.ok(!/desiredState\s*=/.test(body), 'clearing a block is not a decision about intent');
});

void test('the lease guard re-reads every import fact and leaves other operations alone', () => {
  const guard = nodes.slice(
    nodes.indexOf("appPayload.payload.operation === 'import'"),
    nodes.indexOf("appPayload.payload.operation === 'recover'"),
  );
  assert.match(guard, /d\.nodeId = \?/);
  assert.match(guard, /d\.desiredRevision = \?/);
  assert.match(guard, /source\.nodeId <> d\.nodeId/);
  assert.match(guard, /lost\.revokedAt IS NOT NULL/);
  assert.match(guard, /replacement\.nodeId = \? AND replacement\.state = 'building'/);
  assert.match(guard, /source\.state = 'verified'/);
  assert.match(nodes, /appPayload\.payload\.operation === 'recover'/);
});

void test('a bindable port that a sibling deployment already holds is not retained', () => {
  const body = fn('negotiatePrivatePort');
  const taken = body.indexOf('const taken = new Set');
  const early = body.indexOf('candidates.includes(expected)');
  assert.ok(taken < early, 'the taken set must be known before the early return');
  assert.match(body, /candidates\.includes\(expected\) && !taken\.has\(expected\)/);
  assert.match(body, /for \(const candidate of candidates\)/);
});

// ---------------------------------------------------------------------------
// Audit.
// ---------------------------------------------------------------------------

void test('the three Phase 22 events are catalogued as critical with bounded metadata', () => {
  const added = ['node.declare_lost', 'deployment.ownership_transfer', 'deployment.artifact_import'];
  for (const action of added) {
    const entry = EVIDENCE_ACTIONS.find((candidate) => candidate.action === action);
    assert.ok(entry, action);
    assert.equal(entry?.critical, true, action);
    assert.ok((entry?.metadataKeys.length ?? 0) <= 5, action);
    for (const key of entry?.metadataKeys ?? []) {
      assert.ok(
        !/token|secret|credential|cookie|authorization|path|checksum$/i.test(key),
        `${action} metadata key ${key}`,
      );
    }
  }
});

void test('Phase 22 audit metadata carries no secret material', () => {
  for (const name of ['declareNodeLost', 'transferDeploymentOwnership', 'confirmArtifactImport']) {
    const body = fn(name);
    const evidence = body.slice(body.indexOf('recordEvidence'));
    assert.ok(
      !/token|tokenCiphertext|credential|cookie|authorization|agent\.key/i.test(evidence),
      name,
    );
  }
});

// ---------------------------------------------------------------------------
// Nothing about this phase needs new schema.
// ---------------------------------------------------------------------------

void test('Phase 22 adds no migration', () => {
  const db = source('lib/server/db.ts');
  assert.ok(!db.includes('0021'), 'no 0021 migration may be registered');
  assert.match(db, /0020_runtime_recovery/);
});

// ---------------------------------------------------------------------------
// Prompt 3B: the reservation and the routes that carry it.
// ---------------------------------------------------------------------------

const AGENT_ROUTES = [
  'app/api/nodes/agent/deployments/[id]/import-preflight/route.ts',
  'app/api/nodes/agent/deployments/[id]/import-complete/route.ts',
  'app/api/nodes/agent/deployments/[id]/import-ready/route.ts',
];
const OPERATOR_ROUTES = [
  'app/api/nodes/[id]/declare-lost/route.ts',
  'app/api/deployments/[id]/transfer/route.ts',
];




void test('the queued payload names the new artifact, the source artifact and the revision', () => {
  const body = fn('readArtifactImportPreflight');
  const payload = body.slice(body.indexOf('payload: {'), body.indexOf('targetNodeId:'));
  assert.match(payload, /operation: 'import'/);
  assert.match(payload, /artifactId: replacementArtifactId/);
  assert.match(payload, /targetArtifactId: row\.sourceArtifactId/);
  assert.match(payload, /expectedDesiredRevision: row\.desiredRevision/);
  assert.ok(!/checksum/.test(payload), 'the checksum is never carried in the job payload');
});

void test('the runtime shape is read from the lost node, never invented', () => {
  const body = fn('readArtifactImportPreflight');
  assert.match(body, /a\.nodeId = \?[\s\S]{0,200}row\.sourceNodeId, APP_RUNTIME_JOB_TYPE/);
  assert.match(body, /memoryMb: prior\.memoryMb, diskQuotaBytes: prior\.diskQuotaBytes/);
  assert.match(body, /no longer on record, so it cannot be imported/);
});

void test('every Agent import route is signed node authentication', () => {
  for (const route of AGENT_ROUTES) {
    const body = source(route);
    assert.match(body, /authenticateAgentRequest\(request, parsed\.raw\)/, route);
    assert.match(body, /readBoundedJson\(request, 1024\)/, route);
    assert.ok(!/requireApiSession/.test(body), `${route} must not accept a browser session`);
    assert.match(body, /if \(!auth\.ok\) return auth\.response;/, route);
  }
});

void test('import-preflight takes no body values from the node', () => {
  const body = source(AGENT_ROUTES[0]!);
  assert.match(body, /readArtifactImportPreflight\(auth\.context, id\)/);
  assert.ok(!/parsed\.body/.test(body), 'nothing the node sends may steer a preflight');
});

void test('operator routes are session authenticated and never node authenticated', () => {
  for (const route of OPERATOR_ROUTES) {
    const body = source(route);
    assert.match(body, /requireApiSession\(request\)/, route);
    assert.match(body, /enforceRateLimit\('api:write'/, route);
    assert.ok(!/authenticateAgentRequest/.test(body), `${route} must not be a node route`);
    assert.match(body, /auth\.session\.workspace\.id/, route);
  }
});

void test('the declare-lost route calls declareNodeLost and nothing else', () => {
  const body = source(OPERATOR_ROUTES[0]!);
  assert.match(body, /declareNodeLost\(\{/);
  assert.ok(!/revokeNode/.test(body), 'declare lost must never fall back to generic revoke');
});

void test('the transfer route passes every expected identity through unchanged', () => {
  const body = source(OPERATOR_ROUTES[1]!);
  assert.match(body, /transferDeploymentOwnership\(\{/);
  for (const field of ['sourceNodeId', 'replacementNodeId', 'expectedDesiredRevision', 'expectedArtifactId']) {
    assert.match(body, new RegExp(`${field}:`), field);
  }
  assert.match(body, /expectedDesiredRevision === 'number' \? body\.expectedDesiredRevision : -1/);
});

void test('no route body or response carries credential material', () => {
  for (const route of [...AGENT_ROUTES, ...OPERATOR_ROUTES]) {
    // Prose may discuss credentials; code may not touch them.
    const body = source(route).replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
    assert.ok(
      !/token|tokenCiphertext|credential|cookie|Authorization|agent\.key/i.test(body),
      route,
    );
  }
});

void test('import-ready refuses a wrong node, an unverified or absent artifact, and a stale revision', () => {
  const body = fn('clearReplacementImportBlock');
  assert.match(body, /AND d\.nodeId = \?/);
  assert.match(body, /artifactState !== 'verified'/);
  assert.match(body, /availabilityState !== 'present'/);
  assert.match(body, /artifactNodeId !== context\.node\.id/);
  // The revision fence lives on the artifact pointer: only the import that this
  // deployment currently points at can clear its own block.
  assert.match(body, /a\.id = d\.currentArtifactId/);
});

void test('import-ready replay is a no-op rather than an error', () => {
  const body = fn('clearReplacementImportBlock');
  const early = body.indexOf('row.recoveryStatus === null');
  assert.notEqual(early, -1);
  assert.match(body.slice(early, early + 260), /ok: true, cleared: false/);
  assert.match(body, /AND recoveryStatus IS NOT NULL/);
});

void test('import-ready starts, builds and enqueues nothing', () => {
  const body = fn('clearReplacementImportBlock');
  assert.ok(!/enqueueJob|INSERT INTO node_job|INSERT INTO app_deployment_action/.test(body));
  assert.ok(!/desiredState\s*=/.test(body));
  assert.ok(!/createId\('art'\)/.test(body));
});

void test('the same-node restore routes are untouched', () => {
  for (const route of [
    'app/api/nodes/agent/deployments/[id]/restore-preflight/route.ts',
    'app/api/nodes/agent/deployments/[id]/restore-complete/route.ts',
  ]) {
    const body = source(route);
    assert.ok(!/[Ii]mport(Preflight|Identity|Artifact|-ready|-complete)/.test(body),
      `${route} must not learn about import`);
    assert.ok(!/confirmArtifactImport|readArtifactImportPreflight/.test(body), route);
    assert.match(body, /authenticateAgentRequest/);
  }
});

// ---------------------------------------------------------------------------
// Prompt 3C: what a crash between the job and its rows must not cost.
// ---------------------------------------------------------------------------

void test('the reservation is looked up by job before anything is allocated', () => {
  const body = fn('readArtifactImportPreflight');
  const lookup = body.indexOf('const reserved = await queryOne');
  const queue = body.indexOf('const queued = await enqueueJob');
  assert.notEqual(lookup, -1);
  assert.ok(lookup < queue, 'an existing job is found before a new one is attempted');
  assert.match(body, /FROM node_job\s+WHERE workspaceId = \? AND idempotencyKey = \? AND type = \?/);
});

void test('exactly one artifact id and one action id are ever minted per preflight', () => {
  const body = fn('readArtifactImportPreflight');
  assert.equal(body.match(/createId\('art'\)/g)?.length, 1);
  assert.equal(body.match(/createId\('dact'\)/g)?.length, 1);
  assert.equal(body.match(/enqueueJob\(/g)?.length, 1);
});

void test('a retry after a crash repairs the missing artifact from the reserved payload', () => {
  const body = fn('readArtifactImportPreflight');
  const repair = body.slice(body.indexOf('async function adoptExistingReservation'));
  assert.match(repair, /const artifactId = claim\.artifactId;/);
  assert.match(repair, /if \(!artifact\) \{/);
  assert.match(repair, /INSERT INTO app_artifact/);
  assert.ok(!/createId\('art'\)/.test(repair), 'repair must never mint a second artifact id');
});

void test('a retry after a crash repairs the missing action from the reserved payload', () => {
  const repair = fn('readArtifactImportPreflight')
    .slice(fn('readArtifactImportPreflight').indexOf('async function adoptExistingReservation'));
  assert.match(repair, /if \(!action\) \{/);
  assert.match(repair, /INSERT INTO app_deployment_action/);
  assert.match(repair, /\.bind\(claim\.actionId/);
  assert.ok(!/createId\('dact'\)/.test(repair), 'repair must reuse the reserved action id');
});

void test('a retry with all three rows present writes nothing and reuses the artifact', () => {
  const repair = fn('readArtifactImportPreflight')
    .slice(fn('readArtifactImportPreflight').indexOf('async function adoptExistingReservation'));
  // The hold is re-asserted every time, which is a no-op when it already holds:
  // the conditional UPDATE matches nothing unless the job drifted back to queued.
  assert.match(repair, /await database\.batch\(repairs\)/);
  assert.match(repair, /AND state = .queued./);
  assert.match(repair, /return \{ ok: true, artifactId, contract: claim\.contract \}/);
});

void test('a reservation that no longer describes this import is a conflict, not a repair', () => {
  const repair = fn('readArtifactImportPreflight')
    .slice(fn('readArtifactImportPreflight').indexOf('async function adoptExistingReservation'));
  for (const guard of [
    /claim\.operation !== 'import'/,
    /claim\.deploymentId !== deploymentId/,
    /claim\.projectId !== projectId/,
    /claim\.targetArtifactId !== sourceArtifactId/,
    /claim\.expectedDesiredRevision !== desiredRevision/,
  ]) assert.match(repair, guard);
  assert.match(repair, /A conflicting import is already reserved for this deployment/);
  assert.match(repair, /The reserved artifact belongs to another node or deployment/);
});

void test('a lost race adopts the winner instead of reserving a second job', () => {
  const body = fn('readArtifactImportPreflight');
  const raced = body.slice(body.indexOf('if (!queued.created)'), body.indexOf('const next = await queryOne'));
  assert.match(raced, /adoptExistingReservation\(queued\.job\.id, raced\.payload\)/);
  assert.ok(!/INSERT INTO/.test(raced), 'the losing request inserts nothing of its own');
  assert.equal(body.match(/enqueueJob\(/g)?.length, 1);
});

void test('the queued payload still names the new artifact, the source artifact and the revision', () => {
  const body = fn('readArtifactImportPreflight');
  const payload = body.slice(body.indexOf('payload: {'), body.indexOf('targetNodeId:'));
  assert.match(payload, /operation: 'import'/);
  assert.match(payload, /artifactId: replacementArtifactId/);
  assert.match(payload, /targetArtifactId: row\.sourceArtifactId/);
  assert.match(payload, /expectedDesiredRevision: row\.desiredRevision/);
  assert.ok(!/checksum/.test(payload), 'the checksum is never carried in the job payload');
});

// ---------------------------------------------------------------------------
// Why depending on job history is safe: nothing deletes it.
//
// The App Runtime's memory limit, disk quota and encrypted environment envelope
// have no column anywhere in the schema -- `node_job.payload` is their only
// durable home, and Phase 18's same-node recovery already depends on exactly
// this. If a retention sweep is ever added for these tables, this test fails
// before a disaster backup silently becomes unrestorable.
// ---------------------------------------------------------------------------

void test('nothing in the tree deletes App Runtime job history', () => {
  const roots = ['lib', 'app'];
  const offenders: string[] = [];
  const walk = (directory: string): void => {
    for (const entry of readdirSync(new URL(`../${directory}`, import.meta.url), { withFileTypes: true })) {
      const next = `${directory}/${entry.name}`;
      if (entry.isDirectory()) walk(next);
      else if (entry.name.endsWith('.ts')) {
        const body = source(next);
        if (/DELETE\s+FROM\s+(node_job|app_deployment_action)\b/i.test(body)) offenders.push(next);
      }
    }
  };
  for (const root of roots) walk(root);
  assert.deepEqual(offenders, [], 'job history is the only durable home of the runtime shape');
});

void test('the App Runtime resource shape has no column of its own to read instead', () => {
  const schema = ['0009_app_runtime', '0020_runtime_recovery']
    .map((name) => source(`db/migrations/${name}.sql`)).join('\n');
  for (const field of ['memoryMb', 'diskQuotaBytes', 'environmentCiphertext']) {
    assert.ok(!schema.includes(field), `${field} is not a column, so job history is authoritative`);
  }
});

// ---------------------------------------------------------------------------
// Prompt 4: the Agent side. `agent/*` reaches the network and the disk, so the
// import flow is pinned by reading the shipped source, the way this repository
// pins every other Agent guarantee.
// ---------------------------------------------------------------------------

const cli = source('agent/cli.ts');
const backup = source('agent/artifact-backup.ts');

function agentFn(body: string, name: string): string {
  const start = body.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist`);
  const next = body.indexOf('\nasync function ', start + 1);
  const alt = body.indexOf('\nexport async function ', start + 1);
  const end = [next, alt].filter((value) => value > 0).sort((a, b) => a - b)[0] ?? body.length;
  return body.slice(start, end);
}

void test('the Agent is 0.9.0 on protocol 1 and advertises replacementImport truthfully', () => {
  assert.equal(CURRENT_AGENT_VERSION, '0.9.0');
  assert.equal(NODE_PROTOCOL_VERSION, 1);
  const runtime = source('agent/runtime.ts');
  assert.match(runtime, /sameNodeRestore: true,\s*\n\s*replacementImport: true,/);
  assert.equal(
    parseArtifactBackupCapability({
      version: 1, supported: true, offlineVerify: true, sameNodeRestore: true,
      replacementImport: true,
    })?.replacementImport,
    true,
  );
});

void test('import is its own command and restore keeps its identity rules', () => {
  assert.match(cli, /type BackupAction = 'create' \| 'verify' \| 'restore' \| 'import'/);
  assert.match(cli, /artifact backup import  <bundle>/);
  const restore = agentFn(cli, 'runBackupRestore');
  assert.match(restore, /restore-preflight/);
  assert.ok(!/import/i.test(restore.replace(/imported/g, '')), 'restore must not learn about import');
  const restoreImpl = agentFn(backup, 'restoreArtifactBackup');
  assert.match(restoreImpl, /evaluateRestoreIdentity/);
  assert.ok(!/evaluateImportIdentity/.test(restoreImpl));
});

void test('the import command verifies offline before it contacts the control plane', () => {
  const fnBody = agentFn(cli, 'runBackupImport');
  const verify = fnBody.indexOf('verifyArtifactBackup(bundlePath)');
  const server = fnBody.indexOf('import-preflight');
  assert.notEqual(verify, -1);
  assert.ok(verify < server, 'a bundle that fails offline verification never reaches the server');
});

void test('preflight sends nothing the server is authoritative for', () => {
  const fnBody = agentFn(cli, 'runBackupImport');
  const call = fnBody.slice(fnBody.indexOf('import-preflight') - 400, fnBody.indexOf('import-preflight') + 200);
  assert.match(call, /body: \{\},/);
  assert.ok(!/checksum|artifactId|version/.test(call.split('body:')[1] ?? ''), 'the body carries nothing');
});

void test('the import uses the server-issued artifact id, never the bundle one', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  assert.match(impl, /const artifactId = input\.authoritative\.replacementArtifactId;/);
  assert.match(impl, /path\.join\(artifactsRoot, artifactId\)/);
  assert.ok(!/artifactsRoot, manifest\.artifactId/.test(impl), 'the source id never becomes a directory');
});

void test('the import gate is the import gate, checked against the transfer revision', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  assert.match(impl, /evaluateImportIdentity\(\{/);
  assert.match(impl, /expectedDesiredRevision: input\.expectedDesiredRevision/);
  assert.ok(!/evaluateRestoreIdentity/.test(impl));
});

void test('both the bundle and the control plane must agree on the checksum', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  assert.match(impl, /manifest\.artifactChecksum !== input\.authoritative\.checksum/);
  assert.match(impl, /staged\.checksum !== input\.authoritative\.checksum/);
  const gate = impl.indexOf('manifest.artifactChecksum !== input.authoritative.checksum');
  assert.ok(gate < impl.indexOf('const stagingRoot'), 'the disagreement is caught before staging');
});

void test('the runtime manifest is rebuilt for the new id and signed with this token', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  assert.match(impl, /contract: input\.contract/);
  assert.match(impl, /artifactId,\s*\n\s*commit: manifest\.commit/);
  assert.match(impl, /signText\(\s*\n?\s*input\.token/);
  assert.ok(!/manifest\.runtime\.signature|copyFile/.test(impl), 'no source signature is ever carried over');
});

void test('staging is outside artifacts, traversal-checked, streamed and cleaned up', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  assert.match(impl, /path\.join\(deploymentRoot, '\.restore-tmp'\)/);
  assert.match(impl, /assertInside\(staging, target\)/);
  assert.match(impl, /open\(target, 'wx'/);
  assert.match(impl, /finally \{\s*\n\s*await rm\(staging, \{ recursive: true, force: true \}\)/);
  assert.ok(!/readFile\(input\.bundlePath\)/.test(impl), 'the bundle is never buffered whole');
});

void test('the install is atomic and refuses to overwrite anything', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  assert.match(impl, /await rename\(staging, finalPath\)/);
  assert.match(impl, /if \(await stat\(finalPath\)[\s\S]{0,80}fail\('artifact_conflict'\)/);
  assert.match(impl, /evaluateArtifactCollision/);
  assert.match(impl, /collision\.action === 'already_restored'/);
});


void test('import-complete carries exactly five values and retries only transport failures', () => {
  const fnBody = agentFn(cli, 'runBackupImport');
  const body = fnBody.slice(fnBody.indexOf('import-complete'), fnBody.indexOf('negotiatePrivatePort'));
  for (const field of ['artifactId', 'sourceArtifactId', 'checksum', 'sizeBytes', 'expectedDesiredRevision']) {
    assert.match(body, new RegExp(`${field}:`), field);
  }
  assert.match(body, /error instanceof ControlPlaneError\) throw new BackupError/);
  assert.match(fnBody, /attempt < 3/);
});

void test('the existing port negotiation is reused and its answer is authoritative', () => {
  const fnBody = agentFn(cli, 'runBackupImport');
  assert.match(fnBody, /const localPort = await negotiatePrivatePort\(\{/);
  assert.match(fnBody, /currentPort: authoritative\.localPort/);
  assert.match(fnBody, /localPort,/);
  assert.ok(!/bindablePrivatePorts|privatePortSearchOrder/.test(fnBody), 'no second allocator');
});

void test('import-ready is called last, after the port is settled', () => {
  const fnBody = agentFn(cli, 'runBackupImport');
  const port = fnBody.indexOf('negotiatePrivatePort');
  const ready = fnBody.indexOf('import-ready');
  assert.notEqual(ready, -1);
  assert.ok(port < ready, 'the block is cleared only once the port is authoritative');
});

void test('the import flow starts, builds, fetches and installs nothing', () => {
  const fnBody = agentFn(cli, 'runBackupImport');
  const impl = agentFn(backup, 'importArtifactBackup');
  for (const forbidden of [/github\.com/i, /npm\s/i, /'install'/, /startManagedApp|spawn\(/, /operation: 'start'/, /buildArtifact/]) {
    assert.ok(!forbidden.test(fnBody), `cli: ${forbidden}`);
    assert.ok(!forbidden.test(impl), `impl: ${forbidden}`);
  }
  assert.match(fnBody, /runtimeStart: 'delegated to reconciliation'/);
});

void test('a restarted Agent clears its own abandoned staging and reuses the reservation', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  assert.match(impl, /await rm\(staging, \{ recursive: true, force: true \}\);\s*\n\s*await mkdir\(staging/);
  const fnBody = agentFn(cli, 'runBackupImport');
  assert.ok(!/createId|randomUUID/.test(fnBody), 'the Agent never mints an artifact id');
});

void test('the printed result claims integrity only, and no secret', () => {
  const fnBody = agentFn(cli, 'runBackupImport');
  const tail = fnBody.indexOf('const flags') === -1 ? fnBody : fnBody.slice(0, fnBody.indexOf('const flags'));
  const result = tail.slice(tail.lastIndexOf('return {'));
  assert.match(result, /integrity: 'verified'/);
  assert.ok(!/[Hh]ealthy/.test(result), 'this command never observes Healthy, so it never says it');
  for (const secret of [/token/i, /credential/i, /ciphertext/i, /cookie/i, /authorization/i]) {
    assert.ok(!secret.test(result), `${secret} must not be printed`);
  }
});

// ---------------------------------------------------------------------------
// Prompt 4B: nothing becomes visible under `artifacts/` until it has proven
// itself. Verifying after the rename would mean a failed import still
// published a directory the App Runtime can see.
// ---------------------------------------------------------------------------

void test('the staged tree is verified before it is renamed into place', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  const verify = impl.indexOf('verifyArtifact(staging, input.token, artifactId)');
  const rename = impl.indexOf('await rename(staging, finalPath)');
  assert.notEqual(verify, -1, 'the staged tree must be verified');
  assert.notEqual(rename, -1);
  assert.ok(verify < rename, 'verification precedes publication');
});

void test('the whole install order holds: stage, checksum, manifest, verify, rename, sync', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  const order = [
    'const staging = path.join',
    'staged.checksum !== input.authoritative.checksum',
    'RUNTIME_MANIFEST_NAME',
    'verifyArtifact(staging',
    'await rename(staging, finalPath)',
    'await syncDirectory(artifactsRoot)',
  ].map((needle) => {
    const at = impl.indexOf(needle);
    assert.notEqual(at, -1, needle);
    return at;
  });
  for (let index = 1; index < order.length; index += 1) {
    assert.ok(order[index]! > order[index - 1]!, `step ${index} is out of order`);
  }
});

void test('a failed verification publishes nothing and cleans its staging', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  const between = impl.slice(
    impl.indexOf('verifyArtifact(staging'),
    impl.indexOf('await rename(staging, finalPath)'),
  );
  assert.match(between, /fail\('artifact_unverified'\)/);
  // `fail` throws, so the rename below is unreachable and the `finally` runs.
  assert.match(impl, /\} finally \{\s*\n\s*await rm\(staging, \{ recursive: true, force: true \}\)/);
  assert.match(source('agent/artifact-backup.ts'), /function fail\([\s\S]{0,200}throw new BackupError/);
});

void test('a failed import never reaches import-complete or import-ready', () => {
  const fnBody = agentFn(cli, 'runBackupImport');
  const install = fnBody.indexOf('await importArtifactBackup({');
  const complete = fnBody.indexOf('import-complete');
  const ready = fnBody.indexOf('import-ready');
  assert.ok(install < complete && complete < ready, 'both calls sit downstream of the install');
  // Nothing catches the install, so a thrown BackupError leaves the function
  // before either call can be made.
  const guard = fnBody.slice(install, complete);
  assert.ok(!/catch\s*\{[\s\S]*importArtifactBackup/.test(guard));
  assert.ok(!/try \{\s*\n\s*const imported/.test(fnBody), 'the install is not swallowed by a try');
});

void test('the CLI does not re-verify what staging already proved', () => {
  const fnBody = agentFn(cli, 'runBackupImport');
  assert.ok(!/verifyArtifact\(/.test(fnBody), 'one verification, on the tree that had not been published');
  const restore = agentFn(cli, 'runBackupRestore');
  assert.match(restore, /verifyArtifact\(artifactDirectory/, 'restore keeps its own unchanged behaviour');
});

void test('an identical existing artifact is verified before it is trusted', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  const retry = impl.slice(
    impl.indexOf("collision.action === 'already_restored'"),
    impl.indexOf('const free = await freeBytes'),
  );
  assert.match(retry, /verifyArtifact\(finalPath, input\.token, artifactId\)/);
  assert.match(retry, /fail\('artifact_unverified'\)/);
  assert.match(retry, /outcome: 'already_restored'/);
});

void test('an existing artifact with different bytes is still refused outright', () => {
  const impl = agentFn(backup, 'importArtifactBackup');
  assert.match(impl, /if \(collision\.action === 'refuse'\) fail\('artifact_conflict'\)/);
  const refuse = impl.indexOf("collision.action === 'refuse'");
  assert.ok(refuse < impl.indexOf('const stagingRoot'), 'refused before a byte is staged');
  assert.ok(!/force: true \}\);\s*\n\s*await rename/.test(impl), 'nothing is ever overwritten');
});

// ---------------------------------------------------------------------------
// Prompt 5: the operator flow. The pure helpers are exercised directly; the
// copy and the wiring are read out of the shipped components, which is how this
// repository pins UI it cannot mount.
// ---------------------------------------------------------------------------

const nodesView = source('components/nodes-view.tsx');
const recoveryView = source('components/replacement-recovery.tsx');
const recoveryRules = source('lib/replacement-recovery.ts');

void test('declaring a node lost is its own action, not a second revoke', () => {
  assert.match(nodesView, /Declare \$\{node\.name\} permanently lost/);
  assert.match(nodesView, /\/api\/nodes\/\$\{node\.id\}\/declare-lost/);
  // The ordinary revoke path is untouched and still present.
  assert.match(nodesView, /Its token will stop working immediately/);
  assert.match(nodesView, /method: 'DELETE'/);
});

void test('declaring a node lost requires a typed phrase, never one click', () => {
  assert.match(nodesView, /const LOST_CONFIRMATION = 'DECLARE LOST'/);
  assert.match(nodesView, /window\.prompt\(/);
  assert.match(nodesView, /if \(typed\?\.trim\(\) !== LOST_CONFIRMATION\) return;/);
  const handler = nodesView.slice(nodesView.indexOf('async function declareLost'));
  const guard = handler.indexOf('LOST_CONFIRMATION) return;');
  assert.ok(guard < handler.indexOf('fetch('), 'nothing is called before the phrase matches');
});

void test('the warning is honest about permanence and about what it cannot promise', () => {
  const handler = nodesView.slice(
    nodesView.indexOf('async function declareLost'),
    nodesView.indexOf('async function cancelTicket'),
  );
  assert.match(handler, /This cannot be undone/);
  assert.match(handler, /credential is permanently revoked/);
  assert.match(handler, /deployments are preserved/);
  assert.match(handler, /cannot guarantee that a process on the lost machine has physically stopped/);
  assert.match(handler, /genuinely lost or unrecoverable/);
  // The one claim it must never make.
  assert.ok(!/has been stopped|is stopped|no longer running/.test(handler));
});

void test('a lost node reads differently from an ordinary revoked node', () => {
  assert.match(nodesView, /Lost, credential permanently revoked/);
  assert.match(nodesView, /lostNodeIds\.includes\(node\.id\)/);
  assert.match(nodesView, /lostNodeIds\?: readonly string\[\]/);
  // Nothing implies deletion or a merely temporary condition.
  const row = nodesView.slice(nodesView.indexOf('lostNodeIds.includes(node.id)') - 200);
  assert.ok(!/[Dd]eleted|[Tt]emporarily|[Oo]ffline only/.test(row.slice(0, 400)));
});

void test('only a node that can actually import may be selected as a replacement', () => {
  const candidate = {
    id: `node_${'1'.repeat(24)}`, name: 'spare', agentVersion: '0.9.0',
    status: 'online' as const, assignmentsDisabled: false, replacementImport: true,
  };
  const lostId = `node_${'0'.repeat(24)}`;
  assert.equal(eligibleReplacements([candidate], lostId).length, 1);
  for (const ineligible of [
    { ...candidate, status: 'revoked' as const },
    { ...candidate, assignmentsDisabled: true },
    { ...candidate, replacementImport: false, agentVersion: '0.8.0' },
    { ...candidate, id: lostId },
  ]) {
    assert.equal(eligibleReplacements([ineligible], lostId).length, 0, JSON.stringify(ineligible));
  }
});

void test('with no eligible node the operator is told, not silently offered nothing', () => {
  assert.match(recoveryView, /No compatible replacement Compute Node is available/);
  assert.match(recoveryView, /Agent 0\.9\.0 or\s*\n?\s*later/);
  assert.match(recoveryView, /cannot import a replacement artifact and are not/);
  assert.ok(!/pairNode|createPairing/.test(recoveryView), 'the UI never pairs a node for you');
});

void test('the transfer sends the exact revision and artifact it displayed', () => {
  const fnBody = recoveryView.slice(recoveryView.indexOf('async function transfer'));
  assert.match(fnBody, /expectedDesiredRevision: deployment\.desiredRevision/);
  assert.match(fnBody, /expectedArtifactId: deployment\.currentArtifactId/);
  assert.match(fnBody, /sourceNodeId: deployment\.nodeId/);
  assert.match(fnBody, /replacementNodeId: replacement\.id/);
  assert.match(fnBody, /\/api\/deployments\/\$\{deployment\.id\}\/transfer/);
});

void test('the transfer names both nodes and warns before it is confirmed', () => {
  const fnBody = recoveryView.slice(recoveryView.indexOf('async function transfer'));
  for (const line of [/Source node:/, /Replacement node:/, /Deployment:/, /Desired state:/, /Source artifact:/]) {
    assert.match(fnBody, line);
  }
  assert.match(fnBody, /only node YSD will accept control-plane work from/);
  assert.match(fnBody, /may still exist if that machine is ever powered on/);
  const confirm = fnBody.indexOf('window.confirm');
  assert.ok(confirm < fnBody.indexOf('fetch('), 'the confirmation precedes the request');
});

void test('a stale 409 refreshes rather than retrying the same values', () => {
  const fnBody = recoveryView.slice(recoveryView.indexOf('async function transfer'));
  const conflict = fnBody.slice(fnBody.indexOf('response.status === 409'));
  assert.match(conflict, /router\.refresh\(\)/);
  assert.match(conflict, /return;/);
  assert.ok(!/fetch\(/.test(conflict.slice(0, 400)), 'no blind retry');
});

void test('awaiting import says what happened and what is being waited for', () => {
  assert.match(recoveryRules, /label: 'Ownership transferred'/);
  assert.match(recoveryRules, /Waiting for the artifact backup to be imported/);
  assert.match(recoveryRules, /label: 'Deployment preserved'/);
  assert.match(recoveryRules, /Waiting for a replacement Compute Node/);
});

void test('the import command is shown as a template with no real path', () => {
  assert.equal(IMPORT_COMMAND_PLACEHOLDER, '<path-to-backup>.ysdbak');
  const command = importCommand();
  assert.match(command, /^ysd-node-agent artifact backup import "/);
  assert.ok(command.includes(IMPORT_COMMAND_PLACEHOLDER));
  for (const forbidden of [/--config/, /C:\\/, /\/home\//, /\/Users\//, /--url/, /token/i, /key/i]) {
    assert.ok(!forbidden.test(command), `${forbidden} must not appear in the shown command`);
  }
});

void test('a deployment that is meant to stay stopped is described truthfully', () => {
  const stopped = recoveryPhase({
    id: DPL, name: 'api', nodeId: null, nodeName: null, desiredState: 'stopped',
    recoveryReasonCode: null, observedState: 'stopped', health: null, desiredRevision: 8,
    currentArtifactId: NEW_ART, artifactChecksum: CHECKSUM, localPort: 41100,
  });
  assert.match(stopped.label, /Artifact restored, runtime stopped/);
  assert.match(stopped.detail, /intentionally stopped, so nothing will start it/);
  assert.match(recoveryView, /restored and left stopped/);
});

void test('Healthy is claimed only when health actually says so', () => {
  const base = {
    id: DPL, name: 'api', nodeId: null, nodeName: null, desiredState: 'running' as const,
    recoveryReasonCode: null, observedState: 'starting', health: null, desiredRevision: 8,
    currentArtifactId: NEW_ART, artifactChecksum: CHECKSUM, localPort: 41100,
  };
  assert.equal(recoveryPhase(base).label, 'Waiting for reconciliation');
  assert.equal(recoveryPhase({ ...base, health: 'healthy' }).label, 'Healthy');
  assert.equal(recoveryPhase({ ...base, recoveryReasonCode: 'awaiting_import' }).label, 'Ownership transferred');
});

void test('the recovery UI renders no secret and no local path', () => {
  for (const forbidden of [
    /token/i, /credential/i, /ciphertext/i, /cookie/i, /authorization/i, /agent\.key/i,
    /environmentCiphertext/, /C:\\\\/, /\/home\//,
  ]) {
    assert.ok(!forbidden.test(recoveryView), `${forbidden} must not reach the operator's screen`);
  }
});

void test('the backup boundary is stated, and no availability claim is made', () => {
  assert.match(recoveryView, /immutable application artifact/);
  assert.match(recoveryView, /does not contain<\/span> runtime data, databases,\s*\n?\s*game-world data, or machine state/);
  assert.match(recoveryView, /not automatic failover, not high\s*\n?\s*availability, and not zero-downtime migration/);
  assert.ok(!/failover ready|high availability enabled|zero downtime/i.test(
    recoveryView.replace(/not automatic failover[\s\S]{0,120}/, '')));
});

void test('same-node restore wording is untouched by the recovery screen', () => {
  const words = (recoveryView + recoveryRules).replace(/restored/g, '').replace(/replacement-recovery/g, '');
  assert.ok(!/restore/i.test(words), 'restore keeps its own vocabulary');
  const backupSummary = nodesView.slice(nodesView.indexOf('function ArtifactBackupSummary'));
  assert.match(backupSummary.slice(0, 900), /Restores/);
});

void test('the recovery actions are reachable by keyboard and labelled destructively', () => {
  assert.match(nodesView, /aria-label=\{`Declare \$\{node\.name\} permanently lost`\}/);
  assert.match(nodesView, /className="text-red-300\/70 hover:text-red-200"/);
  // A <Button> and a <select> with a real <label>: no hover-only affordance.
  assert.match(recoveryView, /htmlFor="replacement-node"/);
  assert.match(recoveryView, /id="replacement-node"/);
  assert.match(recoveryView, /aria-labelledby="replacement-recovery-heading"/);
  assert.equal(recoveryView.match(/id="replacement-recovery-heading"/g)?.length, 1);
});

void test('wide content scrolls inside its own container, not the page', () => {
  assert.match(recoveryView, /overflow-x-auto/);
  assert.ok(!/w-\[\d{3,}px\]|min-w-\[\d{4,}px\]/.test(recoveryView), 'nothing forces the page wider');
});

// ---------------------------------------------------------------------------
// The CLI argument parser, actually executed.
//
// Every earlier test here read the dispatch branch and the usage text out of
// the source and was satisfied. None of them ran the parser, so a runtime
// allowlist that had drifted from its own type union went unnoticed until an
// end-to-end run tried the command for real: `BackupAction` accepted 'import'
// while `BACKUP_ACTIONS` did not, and the cast at the call site hid it from
// tsc. These invoke the built Agent and read what it actually does.
// ---------------------------------------------------------------------------

const AGENT_BUNDLE = new URL(
  `../public/agent/ysd-node-agent-${CURRENT_AGENT_VERSION}.mjs`, import.meta.url);

function runAgent(args: string[]): { code: number; out: string; err: string } {
  const result = spawnSync(process.execPath, [fileURLToPath(AGENT_BUNDLE), ...args], {
    encoding: 'utf8',
    timeout: 60_000,
    // A config path that cannot exist, so nothing here can touch a real
    // credential; every verb below fails after parsing, never before it.
    env: { ...process.env, YSD_NODE_CONFIG: join(tmpdir(), 'ysd-parser-test-absent.json') },
  });
  return { code: result.status ?? -1, out: result.stdout ?? '', err: result.stderr ?? '' };
}

/**
 * A rejected verb produces the usage banner and nothing else. An accepted one
 * always fails later with a reason code or a runtime error, so "only the
 * banner" is what distinguishes them.
 */
function rejectedByParser(result: { out: string; err: string }): boolean {
  const text = `${result.out}${result.err}`.trim();
  return text.startsWith('YSD Node Agent') && !/[a-z_]+:/.test(text.slice(14));
}

void test('the built Agent exists to be parsed', () => {
  assert.ok(existsSync(fileURLToPath(AGENT_BUNDLE)), `${CURRENT_AGENT_VERSION} bundle must be built`);
});

void test('every backup verb in the type union is accepted by the parser', () => {
  // `create` needs flags, the others need a bundle path; all of them are
  // supplied something that fails *later*, which is exactly the point -- the
  // parser must let them through first.
  const cases: [string, string[]][] = [
    ['create', ['artifact', 'backup', 'create', '--artifact', `art_${'1'.repeat(24)}`, '--output',
      tmpdir()]],
    ['verify', ['artifact', 'backup', 'verify', join(tmpdir(), 'ysd-absent.ysdbak')]],
    ['restore', ['artifact', 'backup', 'restore', join(tmpdir(), 'ysd-absent.ysdbak')]],
    ['import', ['artifact', 'backup', 'import', join(tmpdir(), 'ysd-absent.ysdbak')]],
  ];
  for (const [verb, args] of cases) {
    const result = runAgent(args);
    assert.equal(rejectedByParser(result), false,
      `${verb} must reach its command path, not the usage banner`);
  }
});

void test('import reaches the import path rather than being rejected as a verb', () => {
  const result = runAgent(['artifact', 'backup', 'import', join(tmpdir(), 'ysd-absent.ysdbak')]);
  assert.equal(rejectedByParser(result), false);
  // It fails on the missing bundle, which proves it got as far as reading one.
  assert.match(`${result.out}${result.err}`, /bundle_unreadable|preflight_unavailable|ENOENT/i);
  assert.notEqual(result.code, 0);
});

void test('an unknown backup verb is still rejected by the parser', () => {
  for (const unknown of ['bogus', 'imports', 'Import', '']) {
    const result = runAgent(['artifact', 'backup', unknown, join(tmpdir(), 'x.ysdbak')]);
    assert.equal(rejectedByParser(result), true, `"${unknown}" must not be accepted`);
  }
});

void test('the parser allowlist and its type union cannot drift again unnoticed', () => {
  const cli = source('agent/cli.ts');
  const union = cli.match(/type BackupAction =([^;]+);/)?.[1] ?? '';
  const runtime = cli.match(/const BACKUP_ACTIONS: BackupAction\[\] = \[([^\]]+)\]/)?.[1] ?? '';
  const verbs = (text: string) => [...text.matchAll(/'([a-z-]+)'/g)].map((m) => m[1]).sort();
  assert.deepEqual(verbs(runtime), verbs(union),
    'BACKUP_ACTIONS must list exactly the verbs BackupAction allows');
  const autostartUnion = cli.match(/type AutostartAction =([\s\S]*?);/)?.[1] ?? '';
  const autostartRuntime = cli.match(/const AUTOSTART_ACTIONS: AutostartAction\[\] = \[([\s\S]*?)\]/)?.[1] ?? '';
  assert.deepEqual(verbs(autostartRuntime), verbs(autostartUnion),
    'AUTOSTART_ACTIONS must list exactly the verbs AutostartAction allows');
});

// ---------------------------------------------------------------------------
// The import reservation's lifecycle.
//
// It used to be a queued job, which meant ordinary Agent polling could pick it
// up -- for an operation the Agent has no executor for -- while the real import
// ran from the operator's CLI. One record was trying to be two things. It is
// now held for the node that will do the work and only becomes succeeded once
// the bytes are proven, which is also what lets Phase 18 recover it.
// ---------------------------------------------------------------------------

void test('the reservation is held, never offered to a polling Agent', () => {
  const body = fn('readArtifactImportPreflight');
  assert.match(body, /SET state = 'leased', assignedNodeId = \?, leaseExpiresAt = \?/);
  assert.match(body, /appRuntimeLeaseDuration\('import'\)/);
  // A held job is invisible to the claim query, which selects only queued work.
  assert.match(nodes, /WHERE workspaceId = \? AND state = 'queued'/);
  assert.ok(!/claimSignature/.test(body), 'no claim signature: this is never handed to a poller');
});

void test('a repaired reservation is held on the same terms', () => {
  const repair = fn('readArtifactImportPreflight');
  const adopt = repair.slice(repair.indexOf('async function adoptExistingReservation'));
  assert.match(adopt, /SET state = 'leased', assignedNodeId = \?/);
  assert.match(adopt, /appRuntimeLeaseDuration\('import'\)/);
});

void test('the Agent has no import executor, which is why it must never lease one', () => {
  const runtime = source('agent/app-runtime.ts');
  assert.ok(!/operation === 'import'|case 'import'/.test(runtime));
});

void test('import-complete finalizes exactly one held job and one action', () => {
  const body = fn('confirmArtifactImport');
  assert.match(body, /SET state = 'succeeded', leaseExpiresAt = NULL, completedAt = \?/);
  assert.match(body, /AND state = 'leased'/);
  assert.match(body, /SET state = 'succeeded', completedAt = \?[\s\S]{0,200}kind = 'import'\s*\n\s*AND state = 'queued'/);
  assert.equal(body.match(/UPDATE node_job/g)?.length, 1);
  assert.equal(body.match(/UPDATE app_deployment_action/g)?.length, 1);
});

void test('the succeeded record is scoped to the node that holds the artifact', () => {
  const body = fn('confirmArtifactImport');
  const finalize = body.slice(body.indexOf('UPDATE node_job'), body.indexOf('const tenant'));
  assert.match(finalize, /nodeId = \? AND kind = 'import'/);
  assert.match(finalize, /context\.node\.id/);
});

void test('finalization happens only after the bytes and the pointer are proven', () => {
  const body = fn('confirmArtifactImport');
  const verify = body.indexOf("SET state = 'verified', checksum = ?");
  const flip = body.indexOf('SET currentArtifactId = ?');
  const finalize = body.indexOf('UPDATE node_job');
  assert.ok(verify < flip && flip < finalize,
    'artifact verified, then pointer moved, then history recorded');
  // Every refusal above returns before reaching the finalization.
  const refusals = body.slice(0, verify).match(/return \{ ok: false/g)?.length ?? 0;
  assert.ok(refusals >= 6, `expected the checksum/node/revision refusals to precede it, saw ${refusals}`);
});

void test("the succeeded payload is the one Phase 18's prior-job lookup reads", () => {
  // Phase 18 joins succeeded app-runtime jobs to actions on the deployment's
  // own node and replays the payload's contract. The import payload carries it.
  assert.match(nodes, /FROM node_job j\s*\n\s*JOIN app_deployment_action a ON a\.jobId = j\.id[\s\S]{0,200}j\.state = 'succeeded'/);
  const preflight = fn('readArtifactImportPreflight');
  const payload = preflight.slice(preflight.indexOf('payload: {'), preflight.indexOf('targetNodeId:'));
  for (const field of [/contract: prior\.contract/, /memoryMb: prior\.memoryMb/,
    /environmentCiphertext: await sealNodeEnvironment/,
    /artifactId: replacementArtifactId/, /targetArtifactId: row\.sourceArtifactId/,
    /expectedDesiredRevision: row\.desiredRevision/]) {
    assert.match(payload, field);
  }
  assert.match(preflight, /targetNodeId: context\.node\.id/);
});

void test('a replay finalizes nothing twice', () => {
  const body = fn('confirmArtifactImport');
  const replay = body.indexOf('replayed: true');
  assert.ok(replay < body.indexOf('UPDATE node_job'),
    'the replay path returns before the finalization runs');
  // And the finalization itself is conditional on the pre-finalized state.
  assert.match(body, /AND state = 'leased'/);
  assert.match(body, /AND state = 'queued'/);
});

void test('ordinary deploy, recover and restore semantics are untouched', () => {
  const deployments = source('lib/server/deployments.ts');
  assert.match(deployments, /'deploy', 'queued'/);
  const recover = nodes.slice(nodes.indexOf("'recover', 'queued'") - 200);
  assert.match(recover.slice(0, 400), /'recover', 'queued'/);
  assert.ok(!/evaluateImportIdentity/.test(fn('confirmArtifactRestore')));
});

void test('the harness stops polling when recovery has refused', () => {
  const harness = source('phase22-recovery-acceptance.py');
  assert.match(harness, /def wait_recovered\(client, deployment_id, limit=180\)/);
  assert.match(harness, /row\.get\("recoveryStatus"\) == "blocked"/);
  assert.match(harness, /RECOVERY_BLOCKED=/);
  assert.match(harness, /recovered = wait_recovered\(operator, deployment_id, limit=180\)/);
  // The budget is unchanged.
  assert.ok(!/limit=(?!180)\d+/.test(harness.slice(harness.indexOf('def wait_recovered'),
    harness.indexOf('def wait_recovered') + 900)));
});

// ---------------------------------------------------------------------------
// The public exposure follows the deployment, and stays shut.
//
// The 0011 trigger requires an exposure's node to be the deployment's node and
// its artifact to live on that node. Ownership transfer alone cannot satisfy
// that -- at transfer time the current artifact is still the lost node's -- so
// the exposure moves later, once the imported bytes exist, in a single
// statement that never passes through a half-valid pair.
// ---------------------------------------------------------------------------

void test('the trigger that enforces exposure targeting is untouched', () => {
  const migration = source('db/migrations/0011_public_exposure.sql');
  assert.match(migration, /public_exposure_tenant_update_guard/);
  assert.equal(migration.match(/RAISE\(ABORT, 'public exposure tenant or target mismatch'\)/g)?.length, 2);
  assert.match(migration, /d\.nodeId = NEW\.targetNodeId/);
  assert.match(migration, /a\.nodeId = NEW\.targetNodeId/);
});

void test('ownership transfer does not touch the exposure target', () => {
  const body = fn('transferDeploymentOwnership');
  assert.ok(!/targetNodeId|targetArtifactId/.test(body),
    'retargeting here would produce N2 with A1, which the trigger rejects');
});

void test('declare-lost still fails the exposure closed', () => {
  const body = fn('declareNodeLost');
  assert.match(body, /UPDATE public_exposure/);
  assert.match(body, /healthState = 'revoked'/);
  assert.match(body, /status = CASE WHEN mode = 'private' THEN 'disabled' ELSE 'unavailable_zero_mode' END/);
});

void test('both target columns move together, never one at a time', () => {
  const body = fn('confirmArtifactImport');
  const move = body.slice(body.indexOf('UPDATE public_exposure'));
  assert.match(move, /SET targetNodeId = \?, targetArtifactId = \?, updatedAt = \?/);
  assert.equal(body.match(/UPDATE public_exposure/g)?.length, 1);
  assert.ok(!/SET targetNodeId = \?, updatedAt|SET targetArtifactId = \?, updatedAt/.test(body));
});

void test('the retarget proves the deployment, artifact and revision first', () => {
  const body = fn('confirmArtifactImport');
  const move = body.slice(body.indexOf('async function retargetRecoveredExposure'),
    body.indexOf('const now = Date.now()'));
  assert.match(move, /d\.nodeId = \? AND d\.currentArtifactId = \? AND d\.desiredRevision = \?/);
  assert.match(move, /a\.state = 'verified' AND a\.availabilityState = 'present'/);
  assert.match(move, /a\.nodeId = \?/);
  assert.match(move, /d\.deletedAt IS NULL/);
});

void test('the exposure is never enabled, renamed or recreated by recovery', () => {
  const body = fn('confirmArtifactImport');
  const move = body.slice(body.indexOf('async function retargetRecoveredExposure'),
    body.indexOf('const now = Date.now()'));
  for (const forbidden of [/INSERT INTO public_exposure/, /status = /, /healthState = /,
    /assignedHostname/, /mode = /, /routePath/, /transport = /]) {
    assert.ok(!forbidden.test(move), `${forbidden} must not appear in a recovery retarget`);
  }
  assert.ok(!/desiredState/.test(move));
});

void test('an exposure already on the right target is left alone', () => {
  const body = fn('confirmArtifactImport');
  const move = body.slice(body.indexOf('async function retargetRecoveredExposure'));
  assert.match(move, /targetNodeId IS NOT \? OR targetArtifactId IS NOT \?/);
  assert.match(move, /if \(stale\.length === 0\) return false;/);
});

void test('a replay repairs a stale exposure instead of returning early', () => {
  const body = fn('confirmArtifactImport');
  const replay = body.slice(body.indexOf("row.replacementState === 'verified'"),
    body.indexOf('replayed: true') + 40);
  assert.match(replay, /await retargetRecoveredExposure\(\)/);
  // Availability is deliberately no longer part of this gate; the durable
  // completion record is what proves the import already finished.
  assert.match(replay, /a\.state = 'succeeded' AND j\.state = 'succeeded'/);
  assert.match(replay, /replacementNodeId !== context\.node\.id/);
  // Both the first confirmation and the replay reach it.
  assert.equal(body.match(/await retargetRecoveredExposure\(\)/g)?.length, 2);
});

void test('recovery still starts, builds and fetches nothing', () => {
  const body = fn('confirmArtifactImport');
  assert.ok(!/enqueueJob|'start'|github|npm |buildArtifact/i.test(body));
});

void test('Phase 18 recovery logic is unchanged', () => {
  // The reconcile query still keys on the deployment's own node and succeeded
  // history; nothing in Phase 22 rewrites it.
  assert.match(nodes, /WHERE d\.workspaceId = \? AND d\.nodeId = \? AND d\.deletedAt IS NULL/);
  assert.match(nodes, /j\.state = 'succeeded'/);
});

void test('the operator is told the exposure stays disabled', () => {
  assert.match(recoveryView, /Public exposure stays disabled after disaster recovery/);
  assert.match(recoveryView, /re-enable exposure when you are ready/);
  assert.ok(!/automatically re-?enabl/i.test(recoveryView));
});

void test('the harness stops on a recover job that has given up', () => {
  const harness = source('phase22-recovery-acceptance.py');
  assert.match(harness, /RECOVERY_FAILED=/);
  assert.match(harness, /job\["state"\] in \("failed", "timed_out"\)/);
  assert.match(harness, /\(job\["attempts"\] or 0\) >= \(job\["maxAttempts"\] or 1\)/);
  assert.match(harness, /"lastError": \(job\["lastError"\] or ""\)\[:200\]/);
  // Still the same budget, and still stops on a blocked recovery too.
  assert.match(harness, /def wait_recovered\(client, deployment_id, limit=180\)/);
  assert.match(harness, /row\.get\("recoveryStatus"\) == "blocked"/);
});

// ---------------------------------------------------------------------------
// Completion and replay ask different questions.
//
// Completion asks whether these bytes are here and correct right now, so it
// insists the artifact be present. Replay asks whether the import already
// finished -- and a later recover attempt that fails legitimately moves the
// artifact back to `unknown`, which says nothing about the import. Tying the
// replay to availability turned a durable success into a 409.
// ---------------------------------------------------------------------------

void test('first completion still refuses an artifact that is not present', () => {
  const body = fn('confirmArtifactImport');
  const finalize = body.slice(body.indexOf('const verified = await execute'));
  assert.match(finalize, /availabilityState = 'present'/);
  // The write itself only matches a still-building row, so nothing can be
  // finalized twice or finalized without having been reserved.
  assert.match(finalize, /AND state = 'building' AND deletedAt IS NULL/);
  assert.match(body, /constantTimeEqual\(checksum, row\.sourceChecksum\)/);
});

void test('a completed replay does not depend on later availability', () => {
  const body = fn('confirmArtifactImport');
  const replay = body.slice(body.indexOf("row.replacementState === 'verified'"),
    body.indexOf('replayed: true') + 40);
  assert.ok(!/replacementAvailability/.test(replay),
    'a failed recovery must not turn a completed import into a conflict');
  assert.match(replay, /replacementNodeId !== context\.node\.id/);
});

void test('replay rests on the durable record of the import itself', () => {
  const body = fn('confirmArtifactImport');
  const replay = body.slice(body.indexOf("row.replacementState === 'verified'"),
    body.indexOf('replayed: true') + 40);
  assert.match(replay, /FROM app_deployment_action a/);
  assert.match(replay, /JOIN node_job j ON j\.id = a\.jobId/);
  assert.match(replay, /a\.state = 'succeeded' AND j\.state = 'succeeded'/);
  assert.match(replay, /a\.kind = 'import'/);
  assert.match(replay, /No completed import is recorded for this deployment/);
});

void test('an import that never completed cannot use the replay path', () => {
  const body = fn('confirmArtifactImport');
  const replay = body.slice(body.indexOf("row.replacementState === 'verified'"),
    body.indexOf('replayed: true') + 40);
  const guard = replay.indexOf('if (!completed)');
  assert.notEqual(guard, -1);
  assert.ok(guard < replay.indexOf('retargetRecoveredExposure'),
    'the completion record is checked before anything else happens');
});

void test('replay reads availability and never writes it', () => {
  const body = fn('confirmArtifactImport');
  const replay = body.slice(body.indexOf("row.replacementState === 'verified'"),
    body.indexOf('replayed: true') + 40);
  assert.ok(!/UPDATE app_artifact/.test(replay), 'a replay must not repair availability');
  assert.ok(!/INSERT INTO/.test(replay), 'a replay creates nothing');
});

void test('wrong checksum, node or revision are still rejected on replay', () => {
  const body = fn('confirmArtifactImport');
  const before = body.slice(0, body.indexOf("row.replacementState === 'verified'"));
  assert.match(before, /row\.desiredRevision !== expectedDesiredRevision/);
  assert.match(before, /constantTimeEqual\(checksum, row\.sourceChecksum\)/);
  assert.match(before, /row\.replacementNodeId !== context\.node\.id/);
});

// ---------------------------------------------------------------------------
// Harness: what counts as a secret, and keeping the evidence that explains a
// failed recovery.
// ---------------------------------------------------------------------------

void test('a public node id on an authenticated page is not treated as a secret', () => {
  const harness = source('phase22-recovery-acceptance.py');
  const check = harness.slice(harness.indexOf('L2 the page renders no secret material'),
    harness.indexOf('L2 the page renders no secret material') + 500);
  assert.ok(!/node_\[a-f0-9\]\{24\}/.test(check),
    'the recovery card renders node ids on purpose');
  for (const kept of [/ysdp_/, /Authorization/, /Set-Cookie/, /agent\\\.key/,
    /environmentCiphertext/, /tokenCiphertext/]) {
    assert.match(check, kept);
  }
});

void test('a failed recovery captures the replacement node evidence before cleanup', () => {
  const harness = source('phase22-recovery-acceptance.py');
  assert.match(harness, /def replacement_diagnostic\(row\)/);
  assert.match(harness, /DIAGNOSTIC_REPLACEMENT_AGENT_LOG_TAIL=/);
  assert.match(harness, /DIAGNOSTIC_REPLACEMENT_RECOVERY=/);
  // It runs in section I, before the finally block that deletes the home.
  const call = harness.indexOf('replacement_diagnostic(recovered or {})');
  assert.notEqual(call, -1);
  assert.ok(call < harness.indexOf('\nfinally:'), 'evidence is captured before cleanup');
  assert.match(harness, /if \(recovered or \{\}\)\.get\("state"\) != "healthy":/);
});

void test('the captured diagnostic carries the facts and none of the secrets', () => {
  const harness = source('phase22-recovery-acceptance.py');
  const diagnostic = harness.slice(harness.indexOf('def replacement_diagnostic'),
    harness.indexOf('def run_agent_on'));
  for (const field of ['recoveryStatus', 'recoveryReasonCode', 'recoverJob',
    'artifactDirectoryPresent', 'runtimeManifestPresent', 'portListening',
    'currentArtifactId', 'localPort']) {
    assert.ok(diagnostic.includes(field), field);
  }
  assert.match(diagnostic, /redact\(tail\)/);
  assert.match(harness, /def redact\(text\)/);
  for (const secret of [/authorization/, /cookie/, /token/, /agent\[_-\]\?key/, /ciphertext/]) {
    assert.match(harness.slice(harness.indexOf('REDACTIONS = ['),
      harness.indexOf('def redact')), secret);
  }
});

void test('the fail-fast paths are still in place and the budget is unchanged', () => {
  const harness = source('phase22-recovery-acceptance.py');
  assert.match(harness, /def wait_recovered\(client, deployment_id, limit=180\)/);
  assert.match(harness, /row\.get\("recoveryStatus"\) == "blocked"/);
  assert.match(harness, /job\["state"\] in \("failed", "timed_out"\)/);
  assert.match(harness, /RECOVERY_FAILED=/);
});

void test('the import payload seals the environment for the node that will run it', () => {
  const body = fn('readArtifactImportPreflight');
  // An environment envelope is sealed to a node token, exactly like the runtime
  // manifest signature Phase 21 refuses to carry across machines. Copying the
  // source node's envelope hands the replacement something only the lost
  // machine could open, and recovery fails opening it.
  assert.match(body, /environmentCiphertext: await sealNodeEnvironment\(context\.token, await scopedEnvironment\(/);
  assert.ok(!/environmentCiphertext: prior\.environmentCiphertext/.test(body),
    'the source node envelope must never be replayed to another node');
  assert.match(body, /names: prior\.contract\.envNames/);
  assert.match(body, /workspaceId: context\.node\.workspaceId/);
});

void test('the secret-scoping rule has exactly one definition', () => {
  const deployments = source('lib/server/deployments.ts');
  assert.ok(!/async function scopedEnvironment/.test(deployments),
    'two copies of which secrets a deployment may read is one too many');
  assert.match(deployments, /import \{ enqueueJob, scopedEnvironment, type WorkflowJobContext \} from '\.\/nodes'/);
  assert.match(nodes, /export async function scopedEnvironment\(input: \{/);
  assert.equal(nodes.match(/async function scopedEnvironment/g)?.length, 1);
});

// ---------------------------------------------------------------------------
// The import gates must not depend on a marker reconciliation can overwrite.
//
// Production found this: after a transfer, Phase 18 reconciles on the
// replacement node, correctly observes that the artifact is not there yet, and
// writes `artifact_missing` over `awaiting_import`. Every gate that keyed on
// that marker then refused the import permanently. The durable fact is
// structural -- this deployment is mine, and the artifact it still points at
// belongs to another node that is revoked -- and no reconciliation can rewrite
// it. Local timing hid the defect because the harness imported within seconds.
// ---------------------------------------------------------------------------

void test('no import gate keys on the mutable awaiting_import marker', () => {
  for (const name of ['readArtifactImportPreflight', 'confirmArtifactImport',
    'clearReplacementImportBlock']) {
    const body = fn(name);
    assert.ok(!/recoveryReasonCode\s*(!==|===)\s*'awaiting_import'/.test(body),
      `${name} must not gate on the marker`);
    assert.ok(!/recoveryReasonCode = 'awaiting_import'`/.test(body),
      `${name} must not gate on the marker in SQL`);
  }
  const guard = nodes.slice(nodes.indexOf("appPayload.payload.operation === 'import'"),
    nodes.indexOf("appPayload.payload.operation === 'recover'"));
  assert.ok(!/recoveryReasonCode = 'awaiting_import'/.test(guard),
    'the lease guard must not gate on the marker either');
});

void test('the import gates rest on the structural transfer facts instead', () => {
  const preflight = fn('readArtifactImportPreflight');
  assert.match(preflight, /row\.sourceNodeId === context\.node\.id/);
  assert.match(preflight, /row\.sourceRevokedAt === null/);
  assert.match(preflight, /d\.nodeId = \?/);
  const guard = nodes.slice(nodes.indexOf("appPayload.payload.operation === 'import'"),
    nodes.indexOf("appPayload.payload.operation === 'recover'"));
  assert.match(guard, /source\.nodeId <> d\.nodeId/);
  assert.match(guard, /lost\.revokedAt IS NOT NULL/);
});

void test('the transfer still writes the marker for the operator to read', () => {
  // It is useful in the UI; it is simply not evidence.
  assert.match(fn('transferDeploymentOwnership'), /recoveryReasonCode = 'awaiting_import'/);
});

void test('clearing the block answers whatever condition is standing', () => {
  const body = fn('clearReplacementImportBlock');
  assert.match(body, /row\.recoveryStatus === null/);
  assert.match(body, /AND recoveryStatus IS NOT NULL/);
  // The evidence requirements are unchanged and still strict.
  assert.match(body, /artifactState !== 'verified'/);
  assert.match(body, /availabilityState !== 'present'/);
  assert.match(body, /artifactNodeId !== context\.node\.id/);
  assert.match(body, /row\.localPort === null/);
});
