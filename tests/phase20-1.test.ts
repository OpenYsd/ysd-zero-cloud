/**
 * Phase 20.1: a restored Agent 0.6.0 must still be able to read `status.json`.
 *
 * Agent 0.7.0 added an `upgrade` projection to that file. Agent 0.6.0 validates
 * it by comparing the whole key set to a fixed list, so one extra key -- even
 * one holding `null` -- made it reject the file and report auto-start as
 * disabled while Task Scheduler had it enabled.
 *
 * The old Agent's bytes are frozen, so the compatibility has to come from this
 * side: `status.json` is the Phase 19 contract and nothing newer may be written
 * into it. These tests hold that line using the *actual* Phase 19 parser rules,
 * read out of the commit that shipped them rather than copied by hand.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import * as managed from '../agent/autostart.ts';
import { CURRENT_AGENT_VERSION, NODE_PROTOCOL_VERSION } from '../lib/nodes.ts';

/** The commit that shipped Agent 0.6.0. Its parser is the compatibility target. */
const PHASE_19_COMMIT = '78f7ac74fcf2e0588e13a91455e1b727c620daa3';
const KNOWN_GOOD = '0.6.0';

const repoRoot = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1'));
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');

function phase19Source(): string {
  return execFileSync('git', ['show', `${PHASE_19_COMMIT}:agent/autostart.ts`], {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  });
}

/**
 * The key set Agent 0.6.0 accepts, lifted out of its own source.
 *
 * Not a copy of the list: the literal is parsed from the shipped file, so if
 * the frozen contract were ever misremembered here the test would say so.
 */
function frozenStatusKeys(): string[] {
  const source = phase19Source();
  const start = source.indexOf('export function validateManagedStatus');
  assert.ok(start > 0, 'the Phase 19 status validator must be findable');
  const block = source.slice(start, source.indexOf('\n}', start));
  const literal = /const expected = \[([\s\S]*?)\];/u.exec(block);
  assert.ok(literal, 'the Phase 19 validator must declare its expected key list');
  return [...literal[1]!.matchAll(/'([a-zA-Z]+)'/gu)].map((match) => match[1]!).sort();
}

/** Agent 0.6.0's acceptance rule: the whole key set, exactly. */
function agent060Accepts(value: Record<string, unknown>): boolean {
  return Object.keys(value).sort().join('\0') === frozenStatusKeys().join('\0');
}

const legacyStatus: managed.ManagedStatus = {
  version: 1,
  enabled: true,
  manager: 'windows-task-scheduler',
  scope: 'user-session',
  state: 'starting',
  agentVersion: KNOWN_GOOD,
  lastStartAt: 1_700_000_000_000,
  lastExitAt: null,
  restartCount: 0,
  registrationFingerprint: 'a'.repeat(64),
  crashFailures: [],
};

// ---------------------------------------------------------------------------
// The contract.
// ---------------------------------------------------------------------------

void test('the frozen status contract is exactly what Agent 0.6.0 shipped', () => {
  assert.deepEqual([...managed.LEGACY_STATUS_KEYS].sort(), frozenStatusKeys());
  // And the defect itself, stated as a rule: one extra key is fatal there.
  assert.equal(agent060Accepts(legacyStatus as unknown as Record<string, unknown>), true);
  assert.equal(agent060Accepts({ ...legacyStatus, upgrade: null } as unknown as Record<string, unknown>), false);
});

void test('every status this Agent produces stays readable by Agent 0.6.0', () => {
  const shapes: Record<string, managed.ManagedStatus> = {
    enabled: legacyStatus,
    disabled: { ...legacyStatus, enabled: false, state: 'disabled' },
    promoted: { ...legacyStatus, agentVersion: CURRENT_AGENT_VERSION },
    limited: { ...legacyStatus, state: 'restart_limited', restartCount: 3, crashFailures: [1, 2, 3] },
  };
  for (const [label, shape] of Object.entries(shapes)) {
    const written = managed.legacyManagedStatus(shape);
    assert.equal(agent060Accepts(written as unknown as Record<string, unknown>), true, label);
    assert.equal(Object.hasOwn(written, 'upgrade'), false, label);
  }
  // A status left behind by Agent 0.7.0 is still readable here, and is
  // normalised on the way through so it can be written back safely.
  const fromSevenZero = { ...legacyStatus, upgrade: { state: 'upgrade_succeeded', reason: null, transactionId: '0'.repeat(32), candidateVersion: '0.7.0' } };
  const parsed = managed.validateManagedStatus(fromSevenZero);
  assert.ok(parsed, 'a 0.7.0 status file must not be discarded');
  assert.equal(Object.hasOwn(parsed, 'upgrade'), false);
  assert.equal(agent060Accepts(parsed as unknown as Record<string, unknown>), true);
  assert.equal(parsed.crashFailures.length, 0);
  // Anything genuinely unknown is still refused.
  assert.equal(managed.validateManagedStatus({ ...legacyStatus, somethingElse: 1 }), null);
  assert.equal(managed.validateManagedStatus({ ...legacyStatus, upgrade: { bogus: true } }), null);
});

void test('the generated launcher writes the legacy key set and nothing else', () => {
  const launcher = managed.buildManagedLauncherSource();
  // It projects before writing, and it normalises whatever it read.
  assert.match(launcher, /const legacyStatus=\(value\)=>/);
  assert.match(launcher, /await atomic\(statusPath,status\)/);
  assert.doesNotMatch(launcher, /upgrade:\{state:'upgrade_/);
  const publish = launcher.split('\n').find((line) => line.startsWith('const publish='));
  assert.ok(publish);
  assert.match(publish!, /status=legacyStatus\(\{\.\.\.status,\.\.\.patch\}\)/);
  // The one runtime observation that used to live in the status file is now an
  // annotation on the transaction, which is where the install file already
  // keeps every other reason.
  assert.match(launcher, /reason:'network_unavailable'/);
  assert.match(launcher, /await atomic\(installPath,install\);await queueLog\(logDirectory,'candidate trial waiting/);
});

void test('the transaction projection comes from the install file alone', () => {
  const idle = managed.idleUpgrade(1);
  const candidate = { version: '0.7.1', releasePath: 'C:\\m\\r\\0.7.1\\a.mjs', releaseHash: 'b'.repeat(64) };
  assert.equal(managed.projectUpgradeStatus({ ...idle, state: 'trial', candidate }).state, 'upgrade_trial');
  assert.equal(
    managed.projectUpgradeStatus({ ...idle, state: 'trial', candidate, reason: 'network_unavailable' }).state,
    'upgrade_waiting_for_network',
  );
  assert.equal(managed.projectUpgradeStatus({ ...idle, state: 'blocked', reason: 'authorization_rejected' }).state, 'upgrade_blocked');
  // Status reporting must not be able to change the transaction.
  const report = managed.projectUpgradeStatus({ ...idle, state: 'trial', candidate });
  assert.deepEqual(Object.keys(report).sort(), ['candidateVersion', 'reason', 'state', 'transactionId']);
});

// ---------------------------------------------------------------------------
// The real launcher, end to end.
// ---------------------------------------------------------------------------

void test('a real launcher run leaves a status file Agent 0.6.0 can read', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ysd-p201-'));
  try {
    const config = path.join(directory, 'credentials.json');
    await writeFile(config, '{}', { mode: 0o600 });
    const layout = await managed.managedLayout(config, 'node_p201');
    await mkdir(layout.logDirectory, { recursive: true });
    const source = path.join(directory, 'agent.mjs');
    await writeFile(source, 'process.exit(0);\n');
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
      registrationId: '\\YSD Zero Cloud Node Agent p201',
      registrationFingerprint: 'c'.repeat(64),
      workingDirectory: layout.managedRoot,
      updatedAt: Date.now(),
    };
    await writeFile(layout.installPath, `${JSON.stringify(install)}\n`);
    // Seed the exact file Agent 0.7.0 used to leave behind.
    await writeFile(layout.statusPath, `${JSON.stringify({ ...legacyStatus, upgrade: { state: 'upgrade_succeeded', reason: null, transactionId: '0'.repeat(32), candidateVersion: '0.7.0' } })}\n`);

    const run = spawnSync(process.execPath, [layout.launcherPath, '--install', layout.installPath], {
      cwd: layout.managedRoot,
      encoding: 'utf8',
    });
    assert.equal(run.status, 0, run.stderr);
    const written = JSON.parse(await readFile(layout.statusPath, 'utf8')) as Record<string, unknown>;
    assert.equal(agent060Accepts(written), true, `keys written: ${Object.keys(written).sort().join(', ')}`);
    assert.equal(Object.hasOwn(written, 'upgrade'), false);
    // The crash-budget history survived the normalisation rather than resetting.
    assert.equal(written.version, 1);
    assert.equal(written.enabled, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Manager truth.
// ---------------------------------------------------------------------------

void test('the heartbeat observation asks the native manager, not a status file', async () => {
  const source = await readFile(path.join(repoRoot, 'agent', 'autostart.ts'), 'utf8');
  const block = source.slice(
    source.indexOf('export async function readAutostartCapability'),
    source.indexOf('\n}', source.indexOf('export async function readAutostartCapability')),
  );
  // It used to project a status file straight into the capability, which is how
  // a deleted scheduled task could still read as "enabled". It now goes through
  // the same check `autostart status` performs.
  assert.match(block, /await statusAutostart\(credentialPath\)/);
  assert.doesNotMatch(block, /readFile\(layout\.statusPath/);
  // Bounded: the heartbeat runs every 25 seconds and this costs a process spawn.
  assert.match(block, /AUTOSTART_CAPABILITY_TTL_MS/);
  assert.ok(managed.AUTOSTART_CAPABILITY_TTL_MS >= 30_000);
  // And `autostart status` still consults the live registration itself.
  const statusBlock = source.slice(
    source.indexOf('export async function statusAutostart'),
    source.indexOf('\nexport async function disableAutostart'),
  );
  assert.match(statusBlock, /windowsTaskXml\(install\.registrationId\)/);
  assert.match(statusBlock, /if \(!live\) return \{ \.\.\.base, enabled: false, state: 'disabled' \}/);
});

void test('restoring an older Agent normalises the status file before switching', async () => {
  const source = await readFile(path.join(repoRoot, 'agent', 'autostart.ts'), 'utf8');
  const block = source.slice(source.indexOf('export async function restorePreviousAutostart'));
  const normalise = block.indexOf('writeManagedStatus(layout.statusPath, existingStatus)');
  const switchOver = block.indexOf('atomicWrite(layout.installPath');
  assert.ok(normalise > 0, 'restore must normalise the status file');
  assert.ok(switchOver > normalise, 'the normalisation must happen before the switch');
  // Fail before the switch: a status file that cannot be made readable stops
  // the restore instead of handing an older Agent something it will reject.
  assert.match(block, /return refuse\('transaction_interrupted'\)/);
});

// ---------------------------------------------------------------------------
// Scope.
// ---------------------------------------------------------------------------

void test('Phase 20.1 is a compatibility hotfix and nothing more', async () => {
  const { readdir } = await import('node:fs/promises');
  const migrations = await readdir(path.join(repoRoot, 'db', 'migrations'));
  assert.equal(migrations.at(-1), '0020_runtime_recovery.sql');
  assert.equal(migrations.some((name) => name.startsWith('0021')), false);
  assert.equal(CURRENT_AGENT_VERSION, '0.7.1');
  assert.equal(NODE_PROTOCOL_VERSION, 1);
  assert.equal(JSON.parse(await readFile(path.join(repoRoot, 'package.json'), 'utf8')).version, '0.20.1');
  // The retained Phase 19 Agent is untouched: this fix lives entirely on the
  // newer side, which is the only side that can still be changed.
  const phase19 = phase19Source();
  assert.doesNotMatch(phase19, /LEGACY_STATUS_KEYS|legacyManagedStatus/);
});

void test('the install file stays the transaction authority, and 0.6.0 cannot read it', () => {
  // Agent 0.6.0 validates `install.json` by exact key set too, and Phase 20
  // adds three keys to it. Unlike the status file this cannot be given back:
  // `previousRelease` is the exact release a rollback restores, and dropping it
  // to satisfy an older parser would throw away the thing that makes the
  // rollback verifiable.
  //
  // So the boundary is deliberate and bounded: a node restored to 0.6.0 keeps a
  // truthful auto-start badge -- the heartbeat reads `status.json`, which is
  // now the Phase 19 shape -- while 0.6.0's own `autostart status`, `disable`
  // and `uninstall` cannot manage that install. The newer bundle does.
  const source = phase19Source();
  const start = source.indexOf('export function validateManagedInstall');
  const block = source.slice(start, source.indexOf(String.fromCharCode(10) + '}', start));
  const literal = /const expected = \[([\s\S]*?)\];/u.exec(block);
  assert.ok(literal, 'the Phase 19 install validator must declare its key list');
  const frozen = [...literal[1]!.matchAll(/'([a-zA-Z]+)'/gu)].map((m) => m[1]!);
  for (const added of ['installSchema', 'previousRelease', 'upgrade']) {
    assert.equal(frozen.includes(added), false, `${added} is a Phase 20 addition`);
  }
  // The rule itself: the whole key set, compared exactly.
  assert.match(block, /Object\.keys\(value\)\.sort\(\)\.join\([^)]*\) !== expected\.sort\(\)/);
});
