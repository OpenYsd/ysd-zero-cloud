/**
 * Phase 20: managed Agent safe upgrade and local rollback.
 *
 * These tests exercise the real managed install, the real generated launcher,
 * and the real local ownership channel. The launcher cases spawn the launcher
 * that ships, not a re-implementation of it, because the launcher is the only
 * component that decides which Agent binary starts.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import * as managed from '../agent/autostart.ts';
import { renderLaunchAgent, renderSystemdUserUnit, renderWindowsTask } from '../agent/autostart.ts';
import { acquireAgentOwnership, acquireMaintenanceOwnership, requestManagedUpgradeShutdown } from '../agent/instance-lock.ts';
import {
  CURRENT_AGENT_VERSION,
  MINIMUM_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  agentVersionSupported,
  compareStrictVersions,
  parseAutostartCapability,
  parseStrictVersion,
} from '../lib/nodes.ts';

const hash = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');

const KNOWN_GOOD = '0.6.0';
const CANDIDATE = '0.7.0';

async function temporaryRoot(label: string): Promise<string> {
  return await mkdtemp(path.join(os.tmpdir(), `ysd-phase20-${label}-`));
}

/**
 * A managed install rooted in a real directory, with a real known-good release
 * on disk. Everything the launcher reads is a real file.
 */
async function managedFixture(directory: string, options: { agentSource?: string } = {}) {
  const config = path.join(directory, 'credentials.json');
  await writeFile(config, '{}', { mode: 0o600 });
  const layout = await managed.managedLayout(config, 'node_phase20');
  await mkdir(layout.logDirectory, { recursive: true });
  const source = path.join(directory, 'known-good-agent.mjs');
  await writeFile(source, options.agentSource ?? 'process.exit(0);\n');
  const release = await managed.copyManagedRelease(layout, source, KNOWN_GOOD);
  const launcher = managed.buildManagedLauncherSource();
  await writeFile(layout.launcherPath, launcher);
  const install: managed.ManagedInstall = {
    version: 1,
    installSchema: managed.MANAGED_INSTALL_SCHEMA,
    instanceId: layout.instanceId,
    agentVersion: KNOWN_GOOD,
    protocolVersion: NODE_PROTOCOL_VERSION,
    previousVersion: null,
    previousRelease: null,
    upgrade: managed.idleUpgrade(),
    nodeExecutable: process.execPath,
    releasePath: release.releasePath,
    releaseHash: release.hash,
    launcherPath: layout.launcherPath,
    launcherHash: hash(launcher),
    credentialPath: layout.credentialPath,
    agentHome: directory,
    origin: 'http://localhost:3000',
    manager: 'windows-task-scheduler',
    scope: 'user-session',
    registrationId: '\\YSD Zero Cloud Node Agent phase20',
    registrationFingerprint: 'c'.repeat(64),
    workingDirectory: layout.managedRoot,
    updatedAt: Date.now(),
  };
  const status: managed.ManagedStatus = {
    version: 1,
    enabled: true,
    manager: 'windows-task-scheduler',
    scope: 'user-session',
    state: 'enabled',
    agentVersion: KNOWN_GOOD,
    lastStartAt: null,
    lastExitAt: null,
    restartCount: 0,
    registrationFingerprint: 'c'.repeat(64),
    crashFailures: [],
  };
  await writeFile(layout.installPath, `${JSON.stringify(install)}\n`);
  await writeFile(layout.statusPath, `${JSON.stringify(status)}\n`);
  return { config, layout, install, status, release };
}

/** Stage a candidate release directly on disk, the way staging leaves it. */
async function stageCandidate(
  layout: managed.ManagedLayout,
  directory: string,
  version: string,
  source: string,
): Promise<managed.ManagedRelease> {
  const file = path.join(directory, `candidate-${version}.mjs`);
  await writeFile(file, source);
  const copied = await managed.copyManagedRelease(layout, file, version);
  return { version, releasePath: copied.releasePath, releaseHash: copied.hash };
}

function runLauncher(layout: managed.ManagedLayout) {
  return spawnSync(process.execPath, [layout.launcherPath, '--install', layout.installPath], {
    cwd: layout.managedRoot,
    encoding: 'utf8',
  });
}

async function readInstall(layout: managed.ManagedLayout) {
  return managed.validateManagedInstall(JSON.parse(await readFile(layout.installPath, 'utf8')));
}

// ---------------------------------------------------------------------------
// Gap 9: hardened semantic version handling.
// ---------------------------------------------------------------------------

void test('managed upgrade version parsing is strict and never maps malformed input to zero', () => {
  assert.deepEqual(parseStrictVersion('0.6.0'), [0, 6, 0]);
  assert.deepEqual(parseStrictVersion('0.10.0'), [0, 10, 0]);
  for (const malformed of [
    'abc', '1', '1.2', '1..2', '', ' ', '-1.0.0', '1.-2.0', 'v1.2.3', '01.2.3',
    '1.2.3.4', '1.2.3-beta', '1.2.3+build', '1.2.3 ', '9999999.0.0',
    String(Number.MAX_SAFE_INTEGER) + '.0.0', null, undefined, 1, {}, [],
  ]) {
    assert.equal(parseStrictVersion(malformed as unknown as string), null, JSON.stringify(malformed));
  }
  // The lenient control-plane comparator maps unparsable parts to 0. The
  // upgrade comparator must refuse instead, so "abc" can never read as 0.0.0
  // and therefore never look like a valid downgrade target.
  assert.equal(compareStrictVersions('abc', '0.0.0'), null);
  assert.equal(compareStrictVersions('0.6.0', '0.7.0'), -1);
  assert.equal(compareStrictVersions('0.9.0', '0.10.0'), -1);
  assert.equal(compareStrictVersions('0.7.0', '0.7.0'), 0);
  assert.equal(compareStrictVersions('0.7.0', '0.6.0'), 1);
});

void test('upgrade policy requires a strictly newer stable candidate', () => {
  assert.equal(managed.evaluateUpgradeCandidate({ current: '0.6.0', candidate: '0.7.0' }).allowed, true);
  assert.equal(managed.evaluateUpgradeCandidate({ current: '0.6.0', candidate: '0.6.0' }).reason, 'already_current');
  assert.equal(managed.evaluateUpgradeCandidate({ current: '0.7.0', candidate: '0.6.0' }).reason, 'downgrade_refused');
  assert.equal(managed.evaluateUpgradeCandidate({ current: '0.6.0', candidate: '0.7.0-beta.1' }).reason, 'candidate_incompatible');
  assert.equal(managed.evaluateUpgradeCandidate({ current: '0.6.0', candidate: 'abc' }).reason, 'candidate_incompatible');
  // A quarantined hash needs explicit intent, and explicit intent is enough.
  const quarantine = [{ version: '0.7.0', releaseHash: 'a'.repeat(64), reason: 'candidate_start_failed' as const }];
  assert.equal(
    managed.evaluateUpgradeCandidate({ current: '0.6.0', candidate: '0.7.0', candidateHash: 'a'.repeat(64), quarantine }).reason,
    'candidate_quarantined',
  );
  assert.equal(
    managed.evaluateUpgradeCandidate({ current: '0.6.0', candidate: '0.7.0', candidateHash: 'a'.repeat(64), quarantine, retry: true }).allowed,
    true,
  );
});

// ---------------------------------------------------------------------------
// Gaps 2, 3, 5: candidate state, verifiable previous release, atomic promotion.
// ---------------------------------------------------------------------------

void test('install metadata carries candidate and previous releases without breaking the Phase 19 shape', async () => {
  const directory = await temporaryRoot('metadata');
  try {
    const { layout, install } = await managedFixture(directory);
    const staged = await stageCandidate(layout, directory, CANDIDATE, 'process.exit(0);\n');
    const trial = managed.beginTrial(install, staged, '00000000000000000000000000000000', Date.now());

    // Phase 19 top-level current stays authoritative and known-good.
    assert.equal(trial.version, 1);
    assert.equal(trial.agentVersion, KNOWN_GOOD);
    assert.equal(trial.releasePath, install.releasePath);
    assert.equal(trial.releaseHash, install.releaseHash);
    assert.equal(trial.upgrade?.state, 'trial');
    assert.equal(trial.upgrade?.candidate?.version, CANDIDATE);
    assert.ok(managed.validateManagedInstall(JSON.parse(JSON.stringify(trial))));

    const promoted = managed.promoteCandidate(trial, Date.now());
    assert.equal(promoted.agentVersion, CANDIDATE);
    assert.equal(promoted.releasePath, staged.releasePath);
    assert.equal(promoted.releaseHash, staged.releaseHash);
    // The previous release is recorded by exact path and hash, not by a bare
    // version string that nothing can verify.
    assert.equal(promoted.previousRelease?.version, KNOWN_GOOD);
    assert.equal(promoted.previousRelease?.releasePath, install.releasePath);
    assert.equal(promoted.previousRelease?.releaseHash, install.releaseHash);
    assert.equal(promoted.previousVersion, KNOWN_GOOD);
    assert.equal(promoted.upgrade?.state, 'idle');
    assert.equal(promoted.upgrade?.candidate, null);
    assert.ok(managed.validateManagedInstall(JSON.parse(JSON.stringify(promoted))));

    const rolledBack = managed.rollbackCandidate(trial, 'candidate_start_failed', Date.now());
    assert.equal(rolledBack.agentVersion, KNOWN_GOOD);
    assert.equal(rolledBack.releasePath, install.releasePath);
    assert.equal(rolledBack.upgrade?.state, 'idle');
    assert.equal(rolledBack.upgrade?.candidate, null);
    assert.deepEqual(rolledBack.upgrade?.quarantine, [
      { version: CANDIDATE, releaseHash: staged.releaseHash, reason: 'candidate_start_failed' },
    ]);
    assert.ok(rolledBack.upgrade!.generation > trial.upgrade!.generation);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test('the Phase 19 launcher contract still reads a Phase 20 install', async () => {
  const directory = await temporaryRoot('bridge');
  try {
    const { layout, install } = await managedFixture(directory);
    const staged = await stageCandidate(layout, directory, CANDIDATE, 'process.exit(0);\n');
    const trial = managed.beginTrial(install, staged, '11111111111111111111111111111111', Date.now());
    // The Phase 19 launcher validated a fixed positive shape and ignored
    // unknown keys. Reproduce exactly that check: if it fails, an interrupted
    // migration would strand a node that is still running 0.6.
    const legacy = (value: Record<string, unknown>) =>
      value.version === 1 &&
      /^[a-f0-9]{16}$/u.test(String(value.instanceId)) &&
      typeof value.agentVersion === 'string' &&
      value.protocolVersion === NODE_PROTOCOL_VERSION &&
      value.scope === 'user-session' &&
      ['nodeExecutable', 'releasePath', 'launcherPath', 'credentialPath', 'agentHome', 'workingDirectory']
        .every((key) => typeof value[key] === 'string' && path.isAbsolute(String(value[key]))) &&
      /^[a-f0-9]{64}$/u.test(String(value.releaseHash)) &&
      /^[a-f0-9]{64}$/u.test(String(value.launcherHash));
    assert.equal(legacy(JSON.parse(JSON.stringify(trial))), true);
    // ...and what it would start is the known-good Agent, never the candidate.
    assert.equal(trial.releasePath, install.releasePath);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test('release selection never starts a candidate the transaction did not authorise', async () => {
  const directory = await temporaryRoot('select');
  try {
    const { layout, install } = await managedFixture(directory);
    const staged = await stageCandidate(layout, directory, CANDIDATE, 'process.exit(0);\n');
    const candidate = staged;
    const transactionId = '22222222222222222222222222222222';

    assert.equal(managed.selectManagedRelease(install)?.release.releasePath, install.releasePath);
    assert.equal(managed.selectManagedRelease(install)?.trial, false);

    const stagedInstall = managed.stageTransaction(install, candidate, transactionId, Date.now());
    assert.equal(managed.selectManagedRelease(stagedInstall)?.release.releasePath, install.releasePath);
    assert.equal(managed.selectManagedRelease(stagedInstall)?.trial, false);

    const trial = managed.beginTrial(install, candidate, transactionId, Date.now());
    assert.equal(managed.selectManagedRelease(trial)?.release.releasePath, staged.releasePath);
    assert.equal(managed.selectManagedRelease(trial)?.trial, true);

    const rollbackPending = managed.markRollbackPending(trial, 'candidate_start_failed', Date.now());
    assert.equal(managed.selectManagedRelease(rollbackPending)?.release.releasePath, install.releasePath);
    assert.equal(managed.selectManagedRelease(rollbackPending)?.trial, false);

    // A blocked transaction starts nothing: the candidate and the previous
    // Agent share one credential, so neither is evidence the other works.
    const blocked = managed.blockTransaction(trial, 'authorization_rejected', Date.now());
    assert.equal(managed.selectManagedRelease(blocked), null);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Gap 4: candidate readiness.
// ---------------------------------------------------------------------------

void test('readiness means an accepted heartbeat and binds to one exact transaction', () => {
  const transactionId = '33333333333333333333333333333333';
  const marker = managed.buildReadinessMarker(transactionId, 4, CANDIDATE, 1_700_000_000_000);
  assert.deepEqual(Object.keys(marker).sort(), ['acceptedAt', 'agentVersion', 'generation', 'transactionId', 'version']);
  const upgrade = { transactionId, generation: 4, candidate: { version: CANDIDATE } };
  assert.equal(managed.validateReadinessMarker(marker, upgrade), true);
  assert.equal(managed.validateReadinessMarker({ ...marker, transactionId: '99999999999999999999999999999999' }, upgrade), false);
  assert.equal(managed.validateReadinessMarker({ ...marker, generation: 3 }, upgrade), false);
  assert.equal(managed.validateReadinessMarker({ ...marker, agentVersion: KNOWN_GOOD }, upgrade), false);
  assert.equal(managed.validateReadinessMarker(null, upgrade), false);
  // The marker is a local, non-secret proof. It must never carry an identity.
  const serialized = JSON.stringify(marker);
  assert.doesNotMatch(serialized, /token|cookie|Authorization|node_|ysdp_|pid|path/i);
});

// ---------------------------------------------------------------------------
// Gaps 1, 6: transactional upgrade and candidate-specific automatic rollback.
// ---------------------------------------------------------------------------

void test('only candidate-specific startup failures may roll back', () => {
  const at = (exitCode: number | null, attempts: number, controlled = false) =>
    managed.evaluateTrialOutcome({ exitCode, attempts, controlled });

  assert.equal(at(1, 1).action, 'retry');
  assert.equal(at(1, managed.UPGRADE_TRIAL_ATTEMPT_LIMIT).action, 'rollback');
  assert.equal(at(1, managed.UPGRADE_TRIAL_ATTEMPT_LIMIT).reason, 'candidate_start_failed');
  assert.equal(at(null, managed.UPGRADE_TRIAL_ATTEMPT_LIMIT).action, 'rollback');
  // A runtime the candidate cannot use will not become usable on a retry.
  assert.equal(at(managed.AGENT_EXIT.unsupportedRuntime, 1).action, 'rollback');
  assert.equal(at(managed.AGENT_EXIT.unsupportedRuntime, 1).reason, 'candidate_incompatible');
  // Shared-fate failures: the previous Agent uses the same credential and the
  // same network, so downgrading proves nothing and risks version flapping.
  assert.equal(at(managed.AGENT_EXIT.authorizationRejected, 1).action, 'block');
  assert.equal(at(managed.AGENT_EXIT.authorizationRejected, 1).reason, 'authorization_rejected');
  assert.equal(at(managed.AGENT_EXIT.credentialInvalid, 1).action, 'block');
  assert.equal(at(managed.AGENT_EXIT.credentialInvalid, 1).reason, 'credential_invalid');
  // Ownership conflicts and operator-controlled stops leave the trial intact.
  assert.equal(at(managed.AGENT_EXIT.alreadyRunning, 1).action, 'hold');
  assert.equal(at(managed.AGENT_EXIT.controlledShutdown, 1).action, 'hold');
  assert.equal(at(0, 1, true).action, 'hold');
});

void test('the launcher that ships promotes a candidate only after a real readiness proof', async () => {
  const directory = await temporaryRoot('promote');
  try {
    const { layout, install } = await managedFixture(directory);
    const transactionId = '44444444444444444444444444444444';
    // A candidate that behaves exactly like a healthy Agent: it writes the
    // readiness proof its launcher asked for, then keeps running until it is
    // stopped. The launcher must promote while it is still alive.
    const candidateSource = [
      "import { writeFileSync } from 'node:fs';",
      "import path from 'node:path';",
      "const trial = process.argv[process.argv.indexOf('--managed-trial') + 1];",
      "const generation = Number(process.argv[process.argv.indexOf('--managed-generation') + 1]);",
      `const marker = { version: 1, transactionId: trial, generation, agentVersion: ${JSON.stringify(CANDIDATE)}, acceptedAt: Date.now() };`,
      `writeFileSync(path.join(${JSON.stringify(layout.managedRoot)}, 'readiness.json'), JSON.stringify(marker));`,
      'setTimeout(() => process.exit(0), 4000);',
    ].join('\n');
    const staged = await stageCandidate(layout, directory, CANDIDATE, candidateSource);
    const trial = managed.beginTrial(install, staged, transactionId, Date.now());
    await writeFile(layout.installPath, `${JSON.stringify(trial)}\n`);

    const launched = runLauncher(layout);
    assert.equal(launched.status, 0, launched.stderr);
    const after = await readInstall(layout);
    assert.equal(after?.agentVersion, CANDIDATE, JSON.stringify(after?.upgrade));
    assert.equal(after?.releaseHash, staged.releaseHash);
    assert.equal(after?.previousRelease?.version, KNOWN_GOOD);
    assert.equal(after?.previousRelease?.releaseHash, install.releaseHash);
    assert.equal(after?.upgrade?.state, 'idle');
    assert.equal(after?.upgrade?.candidate, null);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test('the launcher that ships rolls back a failing candidate to the exact known-good release', async () => {
  const directory = await temporaryRoot('rollback');
  try {
    // The known-good Agent proves it ran by leaving a file behind, so the test
    // observes a real restart rather than only a metadata edit.
    const knownGood = [
      "import { writeFileSync } from 'node:fs';",
      `writeFileSync(${JSON.stringify(path.join(directory, 'known-good-ran.txt'))}, 'ran');`,
      'process.exit(0);',
    ].join('\n');
    const { layout, install } = await managedFixture(directory, { agentSource: knownGood });
    const staged = await stageCandidate(layout, directory, CANDIDATE, 'process.exit(7);\n');
    const transactionId = '55555555555555555555555555555555';
    const trial = managed.beginTrial(install, staged, transactionId, Date.now());
    await writeFile(layout.installPath, `${JSON.stringify(trial)}\n`);

    const launched = runLauncher(layout);
    assert.equal(launched.status, 0, launched.stderr);
    const after = await readInstall(layout);
    assert.equal(after?.agentVersion, KNOWN_GOOD);
    assert.equal(after?.releasePath, install.releasePath);
    assert.equal(after?.releaseHash, install.releaseHash);
    assert.equal(after?.upgrade?.state, 'idle');
    assert.equal(after?.upgrade?.candidate, null);
    assert.equal(after?.upgrade?.quarantine.length, 1);
    assert.equal(after?.upgrade?.quarantine[0]?.releaseHash, staged.releaseHash);
    assert.equal(after?.upgrade?.reason, 'candidate_start_failed');
    // The known-good Agent actually started after the rollback.
    await readFile(path.join(directory, 'known-good-ran.txt'), 'utf8');
    // The failed candidate is not selected again on the next manager start.
    const second = runLauncher(layout);
    assert.equal(second.status, 0);
    const settled = await readInstall(layout);
    assert.equal(settled?.agentVersion, KNOWN_GOOD);
    assert.equal(settled?.upgrade?.state, 'idle');
    assert.equal(settled?.upgrade?.quarantine.length, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test('a shared-credential rejection blocks the transaction instead of downgrading', async () => {
  const directory = await temporaryRoot('blocked');
  try {
    const { layout, install } = await managedFixture(directory);
    const staged = await stageCandidate(layout, directory, CANDIDATE, `process.exit(${managed.AGENT_EXIT.authorizationRejected});\n`);
    const trial = managed.beginTrial(install, staged, '66666666666666666666666666666666', Date.now());
    await writeFile(layout.installPath, `${JSON.stringify(trial)}\n`);

    assert.equal(runLauncher(layout).status, 0);
    const after = await readInstall(layout);
    assert.equal(after?.upgrade?.state, 'blocked');
    assert.equal(after?.upgrade?.reason, 'authorization_rejected');
    // Not rolled back, not promoted, not quarantined.
    assert.equal(after?.agentVersion, KNOWN_GOOD);
    assert.equal(after?.upgrade?.candidate?.version, CANDIDATE);
    assert.deepEqual(after?.upgrade?.quarantine, []);
    const status = JSON.parse(await readFile(layout.statusPath, 'utf8'));
    assert.equal(status.state, 'authorization_rejected');
    // A blocked transaction starts no Agent at all on the next manager start.
    const second = runLauncher(layout);
    assert.equal(second.status, 0);
    assert.equal((await readInstall(layout))?.upgrade?.state, 'blocked');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Gap 7: power-loss transaction resume.
// ---------------------------------------------------------------------------

void test('an interrupted transaction resolves to exactly one complete generation', async () => {
  const directory = await temporaryRoot('power');
  try {
    const { layout, install } = await managedFixture(directory);
    const staged = await stageCandidate(layout, directory, CANDIDATE, 'process.exit(0);\n');
    const candidate = staged;
    const transactionId = '77777777777777777777777777777777';

    // A: interrupted staging. Nothing was committed, so the candidate is not
    // selected and the known-good Agent is what starts.
    await writeFile(path.join(layout.releaseRoot, CANDIDATE, '.agent.999.tmp'), 'partial');
    assert.equal(managed.selectManagedRelease(install)?.release.releasePath, install.releasePath);

    // B: interrupted trial. The transaction is committed, so it resumes, and
    // the top-level known-good current is still what the Phase 19 shape names.
    const trial = managed.beginTrial(install, candidate, transactionId, Date.now());
    assert.equal(managed.selectManagedRelease(trial)?.trial, true);
    assert.equal(trial.agentVersion, KNOWN_GOOD);

    // A readiness proof from an older generation must never promote.
    const stale = managed.buildReadinessMarker(transactionId, trial.upgrade!.generation - 1, CANDIDATE, Date.now());
    assert.equal(managed.validateReadinessMarker(stale, trial.upgrade!), false);

    // C: interrupted promotion. Either generation is complete and valid; there
    // is no half-promoted shape in between.
    const promoted = managed.promoteCandidate(trial, Date.now());
    for (const generation of [trial, promoted]) {
      const parsed = managed.validateManagedInstall(JSON.parse(JSON.stringify(generation)));
      assert.ok(parsed);
      const selected = managed.selectManagedRelease(parsed);
      assert.ok(selected);
      assert.ok(selected.release.releasePath === install.releasePath || selected.release.releasePath === staged.releasePath);
    }

    // D: interrupted rollback. The pending marker is durable and the next
    // start finishes it deterministically without touching a file by hand.
    const pending = managed.markRollbackPending(trial, 'candidate_start_failed', Date.now());
    await writeFile(layout.installPath, `${JSON.stringify(pending)}\n`);
    assert.equal(runLauncher(layout).status, 0);
    const settled = await readInstall(layout);
    assert.equal(settled?.upgrade?.state, 'idle');
    assert.equal(settled?.agentVersion, KNOWN_GOOD);
    assert.equal(settled?.upgrade?.quarantine.length, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Gap 8: safe same-version retry and quarantine, and bounded retention.
// ---------------------------------------------------------------------------

void test('retention keeps two releases normally and three during a transaction', async () => {
  const directory = await temporaryRoot('retain');
  try {
    const { layout } = await managedFixture(directory);
    for (const version of ['0.4.0', '0.5.0', '0.6.0', '0.7.0']) {
      await mkdir(path.join(layout.releaseRoot, version), { recursive: true });
      await writeFile(path.join(layout.releaseRoot, version, 'agent.mjs'), version);
    }
    await managed.retainManagedReleases(layout, '0.6.0', '0.5.0', '0.7.0');
    assert.deepEqual((await readdir(layout.releaseRoot)).sort(), ['0.5.0', '0.6.0', '0.7.0']);
    assert.equal(managed.MANAGED_RELEASE_TRANSACTION_LIMIT, 3);
    await managed.retainManagedReleases(layout, '0.7.0', '0.6.0', null);
    assert.deepEqual((await readdir(layout.releaseRoot)).sort(), ['0.6.0', '0.7.0']);
    assert.equal(managed.MANAGED_RELEASE_LIMIT, 2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test('quarantine is bounded and records the exact failed bytes', () => {
  let upgrade = managed.idleUpgrade();
  for (let index = 0; index < managed.UPGRADE_QUARANTINE_LIMIT + 3; index += 1) {
    upgrade = managed.recordQuarantine(upgrade, {
      version: `0.7.${index}`,
      releaseHash: String(index).padStart(64, '0'),
      reason: 'candidate_start_failed',
    });
  }
  assert.equal(upgrade.quarantine.length, managed.UPGRADE_QUARANTINE_LIMIT);
  assert.equal(upgrade.quarantine.at(-1)?.version, `0.7.${managed.UPGRADE_QUARANTINE_LIMIT + 2}`);
});

// ---------------------------------------------------------------------------
// Ownership: maintenance serialisation and the upgrade handoff verb.
// ---------------------------------------------------------------------------

void test('one local maintenance transaction per node, and other nodes stay independent', async () => {
  const directory = await temporaryRoot('maintenance');
  const config = path.join(directory, 'credentials.json');
  await writeFile(config, '{}', { mode: 0o600 });
  const first = await acquireMaintenanceOwnership(config, 'node_one');
  try {
    await assert.rejects(acquireMaintenanceOwnership(config, 'node_one'), /maintenance_busy/);
    // A maintenance lock is a distinct identity from the Agent's own lock, so
    // taking it never makes a running Agent look absent.
    const agent = await acquireAgentOwnership(config, 'node_one');
    await agent.release();
    const other = await acquireMaintenanceOwnership(config, 'node_two');
    await other.release();
  } finally {
    await first.release();
  }
  const restarted = await acquireMaintenanceOwnership(config, 'node_one');
  await restarted.release();
  await rm(directory, { recursive: true, force: true });
});

void test('the upgrade handoff verb answers only for the exact active transaction', async () => {
  const directory = await temporaryRoot('handoff');
  const config = path.join(directory, 'credentials.json');
  await writeFile(config, '{}', { mode: 0o600 });
  const transactionId = '88888888888888888888888888888888';
  let asked: string | null = null;
  const ownership = await acquireAgentOwnership(config, 'node_one', async (candidate) => {
    asked = candidate;
    return candidate === transactionId;
  });
  try {
    assert.equal(await requestManagedUpgradeShutdown(config, 'node_one', 'ffffffffffffffffffffffffffffffff'), 'refused');
    assert.equal(await requestManagedUpgradeShutdown(config, 'node_one', transactionId), 'shutting_down');
    assert.equal(asked, transactionId);
  } finally {
    await ownership.release();
  }
  // No Agent holds the identity: there is nothing to hand off.
  assert.equal(await requestManagedUpgradeShutdown(config, 'node_one', transactionId), 'not_running');
  await rm(directory, { recursive: true, force: true });
});

void test('an Agent that does not understand the verb still reports ownership', async () => {
  const directory = await temporaryRoot('legacy-handoff');
  const config = path.join(directory, 'credentials.json');
  await writeFile(config, '{}', { mode: 0o600 });
  // Phase 19 answered every connection with already_running and never read a
  // command. The upgrade path must detect that and fall back to the native
  // manager rather than assuming a graceful handoff happened.
  const ownership = await acquireAgentOwnership(config, 'node_one');
  try {
    assert.equal(await requestManagedUpgradeShutdown(config, 'node_one', '00000000000000000000000000000000'), 'unsupported');
  } finally {
    await ownership.release();
  }
  await rm(directory, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Scope guards.
// ---------------------------------------------------------------------------

void test('Phase 20 adds no migration and no remote Agent upgrade surface', async () => {
  const root = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1'));
  const { readdir: read } = await import('node:fs/promises');
  const migrations = await read(path.join(root, 'db', 'migrations'));
  assert.equal(migrations.at(-1), '0020_runtime_recovery.sql');
  assert.equal(migrations.some((name) => name.startsWith('0021')), false);

  const routes = await read(path.join(root, 'app', 'api', 'nodes'));
  assert.equal(routes.includes('upgrade'), false);
  assert.equal(routes.includes('autostart'), false);
  const nodeRoutes = await read(path.join(root, 'app', 'api', 'nodes', '[id]'));
  assert.equal(nodeRoutes.includes('upgrade'), false);

  // Nothing the browser can reach may name a local release path or start a
  // local executable, and the Nodes UI must not offer to do it remotely.
  const view = await readFile(path.join(root, 'components', 'nodes-view.tsx'), 'utf8');
  assert.doesNotMatch(view, /Upgrade now|upgradeAgent|releasePath|candidatePath|transactionId|child_process|spawn\(|execFile|exec\(/);
  assert.match(view, /Update available/);
  for (const forbidden of [/automatically updates?/i, /zero.downtime/i, /publisher.signed/i, /code.signed/i]) {
    assert.doesNotMatch(view, forbidden);
  }
});

void test('the shipped Agent release carries no failure fixture and stays checksum-honest', async () => {
  const root = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1'));
  const build = await readFile(path.join(root, 'scripts', 'build-agent.mjs'), 'utf8');
  assert.match(build, /YSD_TEST_ONLY_FAILING_AGENT/);
  const manifest = JSON.parse(await readFile(path.join(root, 'public', 'agent', 'manifest.json'), 'utf8'));
  assert.equal(manifest.version, CURRENT_AGENT_VERSION);
  assert.equal(manifest.protocolVersion, NODE_PROTOCOL_VERSION);
  const bundle = await readFile(path.join(root, 'public', 'agent', manifest.filename), 'utf8');
  assert.doesNotMatch(bundle, /YSD_TEST_ONLY_FAILING_AGENT/);
  assert.equal(hash(Buffer.from(bundle, 'utf8')), manifest.sha256);
  // Integrity wording stays accurate: a published checksum is not a signature.
  const release = await readFile(path.join(root, 'lib', 'agent-release.ts'), 'utf8');
  assert.doesNotMatch(release.replace(/\/\*[\s\S]*?\*\//g, ''), /tamper.proof|publisher.signed/i);
});

// ---------------------------------------------------------------------------
// Compatibility in both directions, and the platforms this machine cannot run.
// ---------------------------------------------------------------------------

void test('0.20 keeps accepting Agent 0.6, and 0.7 stays inside Protocol 1', () => {
  // Product first, then nodes. A control plane that required the new Agent on
  // the day it shipped would strand every node that had not upgraded yet.
  assert.equal(MINIMUM_AGENT_VERSION, '0.3.0');
  assert.equal(agentVersionSupported(KNOWN_GOOD), true);
  assert.equal(agentVersionSupported(CURRENT_AGENT_VERSION), true);
  assert.equal(NODE_PROTOCOL_VERSION, 1);
  assert.equal(CURRENT_AGENT_VERSION, CANDIDATE);

  // And the other direction: an 0.7 node against a control plane that has been
  // rolled back. The autostart capability is the only thing Phase 19 added and
  // Phase 20 does not widen it, so the older parser still accepts it whole.
  const capability = {
    version: 1 as const,
    supported: true,
    enabled: true,
    manager: 'windows-task-scheduler' as const,
    scope: 'user-session' as const,
    state: 'enabled' as const,
  };
  assert.deepEqual(parseAutostartCapability(capability), capability);
  // Nothing local escapes to the control plane: no transaction, no candidate,
  // no path, no launcher, no failure journal.
  assert.equal(parseAutostartCapability({ ...capability, transactionId: 'a'.repeat(32) }), null);
  assert.equal(parseAutostartCapability({ ...capability, candidateVersion: CANDIDATE }), null);
});

void test('the Agent never reports its local upgrade transaction to the control plane', async () => {
  const root = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1'));
  const cli = await readFile(path.join(root, 'agent', 'cli.ts'), 'utf8');
  const heartbeatBody = cli.slice(cli.indexOf("pathname: '/api/nodes/agent/heartbeat'"), cli.indexOf('async function monitorClaim'));
  for (const local of ['transactionId', 'candidate', 'releasePath', 'launcherPath', 'previousRelease', 'quarantine']) {
    assert.doesNotMatch(heartbeatBody, new RegExp(local), local);
  }
  // The heartbeat gains no mandatory field either: it is the same body Phase
  // 19 sent, so a Worker that predates Phase 20 reads it unchanged.
  assert.match(heartbeatBody, /agentVersion: CURRENT_AGENT_VERSION/);
  const route = await readFile(path.join(root, 'app', 'api', 'nodes', 'agent', 'heartbeat', 'route.ts'), 'utf8');
  assert.doesNotMatch(route, /transactionId|candidate|releasePath|upgradeState/);
});

void test('an Agent upgrade cannot change a systemd or LaunchAgent registration', () => {
  const input = {
    instanceId: 'a1b2c3d4e5f60718',
    nodeExecutable: '/usr/local/bin/node',
    launcherPath: '/home/user/.ysd/managed/a1b2c3d4e5f60718/launcher.mjs',
    installPath: '/home/user/.ysd/managed/a1b2c3d4e5f60718/install.json',
    workingDirectory: '/home/user/.ysd/managed/a1b2c3d4e5f60718',
    userId: 'S-1-5-21-1000',
    userName: 'user',
    origin: 'https://example.test',
  };
  const systemd = renderSystemdUserUnit(input);
  const launchAgent = renderLaunchAgent(input);
  const windows = renderWindowsTask({ ...input, nodeExecutable: 'C:\\Program Files\\nodejs\\node.exe', launcherPath: 'C:\\m\\launcher.mjs', installPath: 'C:\\m\\install.json', workingDirectory: 'C:\\m' }).xml;
  for (const rendered of [systemd, launchAgent, windows]) {
    // The registration points at the launcher and the install file. It never
    // names a release, so switching Agent version cannot require rewriting it.
    assert.doesNotMatch(rendered, /\d+\.\d+\.\d+/);
    assert.doesNotMatch(rendered, /releases|ysd-node-agent-/);
    assert.match(rendered, /launcher\.mjs/);
    assert.match(rendered, /install\.json/);
  }
  // Still user-session only: no linger, no system unit, no LaunchDaemon.
  assert.doesNotMatch(systemd, /enable-linger|\/etc\/systemd|WantedBy=multi-user/);
  assert.match(systemd, /WantedBy=default\.target/);
  assert.doesNotMatch(launchAgent, /LaunchDaemons/);
});

void test('launcher v2 builds one command line that both Agent versions accept', () => {
  const launcher = managed.buildManagedLauncherSource();
  // The invocation is exactly what 0.6.0 already understood. The trial
  // arguments are appended only for a candidate on trial, so a restored 0.6.0
  // is never handed a flag it has never heard of.
  assert.match(launcher, /'run','--url',install\.origin,'--config',install\.credentialPath/);
  const trialLine = launcher.split('\n').find((line) => line.includes("'--managed-trial'"));
  assert.ok(trialLine, 'the trial arguments must be appended somewhere');
  assert.match(trialLine!, /if\(selection\.trial\)/);
  // And the metadata is re-read and the release re-hashed on every pass.
  assert.ok(launcher.split('\n').filter((line) => line.includes('loadInstall()')).length >= 2);
  assert.match(launcher, /hash\(bytes\)!==selection\.release\.releaseHash/);
});

void test('the headless status vocabulary is fixed and carries nothing local', () => {
  const base = managed.idleUpgrade(1);
  const candidate = { version: CANDIDATE, releasePath: 'C:\\managed\\releases\\0.7.0\\agent.mjs', releaseHash: 'a'.repeat(64) };
  const at = (upgrade: Partial<managed.ManagedUpgrade>) =>
    managed.projectUpgradeStatus({ ...base, ...upgrade } as managed.ManagedUpgrade);

  assert.equal(at({}).state, 'upgrade_idle');
  assert.equal(at({ state: 'staged', candidate }).state, 'upgrade_staged');
  assert.equal(at({ state: 'trial', candidate }).state, 'upgrade_trial');
  assert.equal(at({ state: 'blocked', reason: 'authorization_rejected' }).state, 'upgrade_blocked');
  assert.equal(at({ state: 'rollback_pending', reason: 'candidate_start_failed' }).state, 'upgrade_rolled_back');
  assert.equal(at({ reason: 'candidate_start_failed' }).state, 'upgrade_rolled_back');

  // Every published state and reason comes from a fixed list, so a raw
  // exception can never reach a status file or a support paste.
  for (const state of managed.UPGRADE_STATUS_STATES) assert.match(state, /^upgrade_[a-z_]+$/);
  for (const reason of managed.UPGRADE_REASONS) assert.match(reason, /^[a-z_]+$/);

  // And the projection names no path, no host and no process.
  const projected = at({ state: 'trial', candidate });
  assert.deepEqual(Object.keys(projected).sort(), ['candidateVersion', 'reason', 'state', 'transactionId']);
  assert.ok(managed.validateUpgradeStatus(projected));
  assert.doesNotMatch(JSON.stringify(projected), /[A-Za-z]:\\|\/home\/|pid|token/i);
});

void test('the Nodes UI never hardcodes an Agent version it might outlive', async () => {
  const root = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1'));
  const view = await readFile(path.join(root, 'components', 'nodes-view.tsx'), 'utf8');
  // Every version the page shows has to come from the release constant. A
  // literal here reads as true and goes stale on the next Agent release --
  // which is exactly how Production ended up telling people to upgrade to a
  // version older than the one it was serving.
  const literals = view.match(/(?<!\.)\b\d+\.\d+\.\d+\b/g) ?? [];
  assert.deepEqual(literals, [], `hardcoded versions: ${literals.join(', ')}`);
  assert.match(view, /Upgrade Agent to \{CURRENT_AGENT_VERSION\}/);
  assert.match(view, /`Upgrade Agent to \$\{CURRENT_AGENT_VERSION\}`/);
});
