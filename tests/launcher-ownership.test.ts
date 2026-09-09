/**
 * Phase 21 hardening: only one launcher may supervise a managed node.
 *
 * The defect these cover is not hypothetical. Two launcher generations for one
 * node each read `state: trial`, each incremented the same attempt counter and
 * each spawned a candidate; the loser exited `already_running`, the trial
 * budget was gone, and the upgrade could never finish.
 *
 * The concurrency case uses a barrier rather than a start-both-and-hope race:
 * the second launcher begins only once the first one's candidate is provably
 * running. Started simultaneously, process-start jitter lets the first finish
 * its read-modify-write and the defect hides; with the barrier the pre-fix
 * launcher spawns a second candidate and spends the second attempt every run.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { buildManagedLauncherSource, LAUNCHER_PIPE_PREFIX, LAUNCHER_SOCKET_PREFIX } from '../agent/managed-launcher.ts';
import { waitForLauncherVisible, waitForManagedGenerationGone } from '../agent/autostart.ts';
import { deriveManagedIdentity } from '../agent/managed-upgrade.ts';
import { NODE_PROTOCOL_VERSION } from '../lib/nodes.ts';

const repoRoot = path.join(path.dirname(new URL(import.meta.url).pathname.slice(1)), '..');
const sha256 = (value: string | Buffer): string => createHash('sha256').update(value).digest('hex');
const hex = (bytes: number): string => sha256(randomBytes(32)).slice(0, bytes * 2);

/** A stand-in Agent that records the fact it was started, then exits. */
const CANDIDATE = `import { appendFile } from 'node:fs/promises';
await appendFile(process.env.YSD_SPAWN_LOG, process.pid + '\\n');
await new Promise((resolve) => setTimeout(resolve, Number(process.env.YSD_CANDIDATE_HOLD_MS ?? 300)));
process.exit(Number(process.env.YSD_CANDIDATE_EXIT ?? 0));
`;

type Harness = {
  root: string;
  identity: string;
  installPath: string;
  launcherPath: string;
  spawnLog: string;
  cleanup: () => Promise<void>;
};

async function harness(state: 'trial' | 'idle' = 'trial'): Promise<Harness> {
  const base = await mkdtemp(path.join(os.tmpdir(), 'ysd-launcher-test-'));
  const identity = hex(8);
  const root = path.join(base, 'managed', identity);
  await mkdir(path.join(root, 'releases'), { recursive: true });

  const agentPath = path.join(root, 'releases', 'agent.mjs');
  await writeFile(agentPath, CANDIDATE);
  const launcherPath = path.join(root, 'launcher.mjs');
  await writeFile(launcherPath, buildManagedLauncherSource());
  const credentialPath = path.join(base, 'credentials.json');
  await writeFile(credentialPath, '{}');

  const release = {
    version: '0.8.0',
    releasePath: agentPath,
    releaseHash: sha256(await readFile(agentPath)),
  };
  const install = {
    version: 1,
    instanceId: identity,
    agentVersion: state === 'trial' ? '0.6.0' : '0.8.0',
    protocolVersion: NODE_PROTOCOL_VERSION,
    manager: 'windows-task-scheduler',
    scope: 'user-session',
    nodeExecutable: process.execPath,
    releasePath: agentPath,
    releaseHash: release.releaseHash,
    launcherPath,
    launcherHash: sha256(await readFile(launcherPath)),
    credentialPath,
    agentHome: base,
    workingDirectory: base,
    registrationFingerprint: sha256('registration'),
    registrationId: 'ysd-test',
    origin: 'http://127.0.0.1:1',
    upgrade: state === 'trial'
      ? {
          state: 'trial',
          transactionId: hex(16),
          generation: 1,
          candidate: release,
          attempts: 0,
          reason: null,
          quarantine: [],
          updatedAt: Date.now(),
        }
      : null,
    previousRelease: null,
    updatedAt: Date.now(),
  };
  const installPath = path.join(root, 'install.json');
  await writeFile(installPath, `${JSON.stringify(install)}\n`);

  return {
    root,
    identity,
    installPath,
    launcherPath,
    spawnLog: path.join(root, 'spawns.log'),
    cleanup: () => rm(base, { recursive: true, force: true }),
  };
}

function runLauncher(item: Harness, extra: Record<string, string> = {}): Promise<number | null> {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      [item.launcherPath, '--install', item.installPath],
      {
        env: {
          ...process.env,
          YSD_SPAWN_LOG: item.spawnLog,
          YSD_CANDIDATE_EXIT: '0',
          ...extra,
        },
        stdio: 'ignore',
      },
    );
    child.once('exit', (code) => resolve(code));
    child.once('error', () => resolve(null));
  });
}

async function spawnCount(item: Harness): Promise<number> {
  const text = await readFile(item.spawnLog, 'utf8').catch(() => '');
  return text.split('\n').filter((line) => line.trim().length > 0).length;
}

async function installOf(item: Harness): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(item.installPath, 'utf8')) as Record<string, unknown>;
}


/** The endpoint a launcher for this credential/node would bind. */
async function launcherEndpointFor(credentialPath: string, nodeId: string): Promise<string> {
  const identity = await deriveManagedIdentity(credentialPath, nodeId);
  return process.platform === 'win32'
    ? `${LAUNCHER_PIPE_PREFIX}${identity}`
    : path.join(path.dirname(credentialPath), `${LAUNCHER_SOCKET_PREFIX}${identity}.sock`);
}

/** Resolves once the first candidate is actually running. */
async function awaitFirstSpawn(item: Harness, limitMs = 15_000): Promise<void> {
  const deadline = Date.now() + limitMs;
  while (Date.now() < deadline) {
    if (await spawnCount(item) > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('the first launcher never started a candidate');
}

void test('a second launcher cannot start a second candidate', async (t) => {
  const item = await harness('trial');
  t.after(() => item.cleanup());

  // The barrier is the thing that makes this deterministic rather than a race
  // the test might lose: launcher B is started only once launcher A's
  // candidate is demonstrably running. That is precisely the real situation --
  // one launcher supervising a live trial while the manager starts another --
  // and against the pre-fix launcher B reads the same `trial` plan, spends the
  // second attempt and spawns a second candidate every time.
  const first = runLauncher(item, { YSD_CANDIDATE_HOLD_MS: '4000' });
  await awaitFirstSpawn(item);
  const second = await runLauncher(item, { YSD_CANDIDATE_HOLD_MS: '4000' });
  const firstCode = await first;

  assert.equal(await spawnCount(item), 1, 'exactly one candidate may be spawned');
  const upgrade = (await installOf(item)).upgrade as { attempts: number } | null;
  assert.equal(upgrade?.attempts, 1, 'exactly one trial attempt may be spent');
  assert.equal(second, 0, 'the launcher that cannot take ownership exits cleanly');
  assert.equal(firstCode, 0);

  const log = await readFile(path.join(item.root, 'logs', 'agent.log'), 'utf8').catch(() => '');
  assert.match(log, /launcher_already_running/u, 'the losing launcher says so plainly');
  assert.equal((log.match(/candidate trial started/gu) ?? []).length, 1);
});

void test('a second launcher writes no metadata at all', async (t) => {
  const item = await harness('trial');
  t.after(() => item.cleanup());

  // Hold ownership from the test itself, so the launcher under test is
  // deterministically the loser rather than probabilistically.
  const endpoint = process.platform === 'win32'
    ? `${LAUNCHER_PIPE_PREFIX}${item.identity}`
    : path.join(item.root, `${LAUNCHER_SOCKET_PREFIX}${item.identity}.sock`);
  const holder = net.createServer((socket) => socket.end());
  await new Promise<void>((resolve, reject) => {
    holder.once('error', reject);
    holder.listen(endpoint, resolve);
  });

  const before = await readFile(item.installPath, 'utf8');
  const code = await runLauncher(item);
  const after = await readFile(item.installPath, 'utf8');

  await new Promise<void>((resolve) => holder.close(() => resolve()));

  assert.equal(code, 0, 'the losing launcher exits cleanly');
  assert.equal(after, before, 'it must not touch install metadata');
  assert.equal(await spawnCount(item), 0, 'it must not spawn an Agent');
});

void test('ownership is released when a launcher goes away', async (t) => {
  const item = await harness('trial');
  t.after(() => item.cleanup());

  // A launcher that has finished must leave nothing behind that a later one
  // has to be repaired out of.
  const first = await runLauncher(item);
  assert.equal(first, 0);
  const afterFirst = await spawnCount(item);

  // Reset the trial so the second launcher has legitimate work to do.
  const install = await installOf(item);
  const upgrade = install.upgrade as Record<string, unknown>;
  await writeFile(item.installPath, `${JSON.stringify({
    ...install,
    upgrade: { ...upgrade, state: 'trial', attempts: 0, reason: null },
  })}\n`);

  const second = await runLauncher(item);
  assert.equal(second, 0);
  assert.ok(await spawnCount(item) > afterFirst, 'a later launcher may take ownership');
  const log = await readFile(path.join(item.root, 'logs', 'agent.log'), 'utf8').catch(() => '');
  assert.equal((log.match(/launcher_already_running/gu) ?? []).length, 0,
    'no stale ownership survives a clean exit');
});

void test('two different nodes are supervised independently', async (t) => {
  const one = await harness('trial');
  const two = await harness('trial');
  t.after(() => Promise.all([one.cleanup(), two.cleanup()]));

  assert.notEqual(one.identity, two.identity);
  const [a, b] = await Promise.all([runLauncher(one), runLauncher(two)]);
  assert.equal(a, 0);
  assert.equal(b, 0);
  // Neither may be starved by the other: ownership is per node identity, not
  // a machine-wide serialisation.
  assert.equal(await spawnCount(one), 1);
  assert.equal(await spawnCount(two), 1);
});

void test('the generated launcher names the same endpoint the lock does', async () => {
  // The launcher is standalone and cannot import the lock helpers, so the two
  // agree by construction here and are pinned by this test.
  const lock = await readFile(
    path.join(path.dirname(new URL(import.meta.url).pathname.slice(1)), '..', 'agent', 'instance-lock.ts'),
    'utf8',
  );
  assert.match(lock, /ysd-zero-cloud-\$\{kind\}-\$\{identity\}/u);
  assert.match(lock, /\.ysd-\$\{kind\}-\$\{identity\}\.sock/u);
  assert.equal(LAUNCHER_PIPE_PREFIX, '\\\\.\\pipe\\ysd-zero-cloud-launcher-');
  assert.equal(LAUNCHER_SOCKET_PREFIX, '.ysd-launcher-');
  const source = buildManagedLauncherSource();
  assert.ok(source.includes(JSON.stringify(LAUNCHER_PIPE_PREFIX)));
});

void test('an ownership conflict does not spend the candidate trial budget', async (t) => {
  const item = await harness('trial');
  t.after(() => item.cleanup());

  // Exit 20 is "another Agent already holds this identity". That says nothing
  // about whether the candidate works, so it must not consume its budget.
  await runLauncher(item, { YSD_CANDIDATE_EXIT: '20', YSD_CANDIDATE_HOLD_MS: '10' });
  const upgrade = (await installOf(item)).upgrade as { attempts: number; reason: string | null } | null;
  assert.ok((upgrade?.attempts ?? 99) < 2, 'a conflict must not exhaust the trial budget');
  const log = await readFile(path.join(item.root, 'logs', 'agent.log'), 'utf8').catch(() => '');
  assert.match(log, /ownership_conflict/u);
  // Bounded, though: it must not retry for ever.
  assert.ok((log.match(/candidate trial started/gu) ?? []).length <= 2);
});

void test('a missing readiness marker is never reported as a network fault', async () => {
  const source = buildManagedLauncherSource();
  // The marker is written on the candidate's first accepted heartbeat. Its
  // absence means "not ready yet"; calling that a network failure sends
  // whoever reads it looking in the wrong place.
  assert.match(source, /waiting_for_readiness/u);
  const notice = source.slice(source.indexOf('noticed=true'), source.indexOf('noticed=true') + 400);
  assert.doesNotMatch(notice, /network_unavailable/u);
});

void test('a candidate that proves readiness is still promoted', async (t) => {
  const item = await harness('trial');
  t.after(() => item.cleanup());

  // The whole point of the trial is that a candidate which reaches an accepted
  // heartbeat gets promoted. Taking an ownership lock must not have cost that.
  const install = await installOf(item);
  const upgrade = install.upgrade as { transactionId: string; generation: number };
  const marker = JSON.stringify({
    version: 1,
    transactionId: upgrade.transactionId,
    generation: upgrade.generation,
    agentVersion: '0.8.0',
    acceptedAt: Date.now(),
  });

  // The stand-in Agent writes the readiness marker the way a real candidate
  // does -- after it starts, not before -- then stays up like an Agent would.
  await writeFile(path.join(item.root, 'releases', 'agent.mjs'), `import { appendFile, writeFile } from 'node:fs/promises';
await appendFile(process.env.YSD_SPAWN_LOG, process.pid + '\\n');
await new Promise((resolve) => setTimeout(resolve, 200));
await writeFile(process.env.YSD_READINESS, ${JSON.stringify(marker)});
await new Promise((resolve) => setTimeout(resolve, 6000));
process.exit(0);
`);
  // The release hash is checked before the candidate runs, so it moves too.
  const agentBytes = await readFile(path.join(item.root, 'releases', 'agent.mjs'));
  const rehashed = {
    ...install,
    upgrade: { ...upgrade, candidate: { version: '0.8.0', releasePath: path.join(item.root, 'releases', 'agent.mjs'), releaseHash: sha256(agentBytes) } },
  };
  await writeFile(item.installPath, `${JSON.stringify(rehashed)}\n`);

  await runLauncher(item, { YSD_READINESS: path.join(item.root, 'readiness.json') });

  const after = await installOf(item);
  assert.equal(after.agentVersion, '0.8.0', 'the proven candidate becomes current');
  assert.equal((after.upgrade as { state: string }).state, 'idle', 'the transaction closes');
  const log = await readFile(path.join(item.root, 'logs', 'agent.log'), 'utf8').catch(() => '');
  assert.match(log, /candidate promoted version=0\.8\.0/u);
});

void test('being probed for ownership does not kill the launcher', async (t) => {
  const item = await harness('trial');
  t.after(() => item.cleanup());

  // `launcherOwnershipHeld` connects and drops. The accepted socket then emits
  // an error, and an unhandled one takes the launcher down mid-trial -- taking
  // the candidate with it and leaving a trial nothing will ever finish. This
  // is the exact failure that survived the first version of the lock.
  const endpoint = process.platform === 'win32'
    ? `${LAUNCHER_PIPE_PREFIX}${item.identity}`
    : path.join(item.root, `${LAUNCHER_SOCKET_PREFIX}${item.identity}.sock`);

  const running = runLauncher(item, { YSD_CANDIDATE_HOLD_MS: '4000' });
  await awaitFirstSpawn(item);

  for (let index = 0; index < 12; index += 1) {
    await new Promise<void>((resolve) => {
      const socket = net.createConnection(endpoint);
      socket.once('connect', () => {
        // Drop it the rude way, which is what an abandoned probe looks like.
        socket.destroy();
        resolve();
      });
      socket.once('error', () => resolve());
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  const code = await running;
  assert.equal(code, 0, 'the launcher survives being probed and exits cleanly');
  const log = await readFile(path.join(item.root, 'logs', 'agent.log'), 'utf8').catch(() => '');
  assert.match(log, /agent exited code=/u, 'it lived long enough to read its child\'s exit');
});

/**
 * A trial must never be visible while an operation that can terminate the
 * task tree is still to come.
 *
 * On Windows `schtasks /Create /F` and `schtasks /End` end the task's process
 * tree with TerminateProcess. Publishing `state: trial` before those calls let
 * a launcher that was about to be killed read the plan, spend the one attempt
 * and start the candidate -- and then both died together, with no exit hook,
 * no supervisor left and a candidate that in one captured run had already
 * written a valid readiness marker nobody was alive to act on.
 */
void test('the trial is published only after every terminating manager call', async () => {
  const source = await readFile(
    path.join(repoRoot, 'agent', 'autostart.ts'),
    'utf8',
  );
  const upgrade = source.slice(
    source.indexOf('export async function upgradeAutostart'),
    source.indexOf('export async function restorePreviousAutostart'),
  );
  assert.ok(upgrade.length > 0, 'the upgrade flow is missing');

  const at = (needle: string): number => {
    const index = upgrade.indexOf(needle);
    assert.ok(index >= 0, `${needle} is missing from the upgrade flow`);
    return index;
  };

  const stop = at('stopManagedRegistration(next)');
  const idle = at('waitForManagedIdle(');
  const trial = at('beginTrial(next');
  const run = at('startManagedRegistration(next');

  // The whole ordering claim, as four inequalities.
  assert.ok(stop < trial, 'the old generation is ended before a trial exists');
  assert.ok(idle < trial, 'both ownership locks are proven free before a trial exists');
  assert.ok(trial < run, 'the trial is durable before the manager is asked to start');

  // Nothing that can end the tree may appear after publication. `/Run` starts a
  // task; it does not replace or end one.
  const afterTrial = upgrade.slice(trial);
  assert.ok(!afterTrial.includes('stopManagedRegistration'), 'no /End after the trial is published');
  assert.ok(!afterTrial.includes('registerWindows'), 'no /Create /F after the trial is published');
  assert.ok(!afterTrial.includes('installManagedAutostart'), 'no re-registration after the trial is published');
});

void test('idle is proven by ownership, never by the manager saying Ready', async () => {
  const source = await readFile(path.join(repoRoot, 'agent', 'autostart.ts'), 'utf8');
  const block = source.slice(
    source.indexOf('async function waitForManagedIdle'),
    source.indexOf('/** Waits for the launcher to finish the trial it was handed. */'),
  );
  // Task Scheduler was observed reporting `Ready` while a launcher it had
  // started was still alive and supervising, so its status alone cannot stand
  // in for "nothing is running".
  assert.match(block, /agentOwnershipHeld\(/u);
  assert.match(block, /launcherOwnershipHeld\(/u);
  assert.match(block, /!held && !supervised && managerIdle/u);
});

void test('a manager operation that would kill a live trial is refused', async () => {
  const source = await readFile(path.join(repoRoot, 'agent', 'autostart.ts'), 'utf8');
  const guard = source.slice(
    source.indexOf('async function assertNoLiveTrial'),
    source.indexOf('async function stopManagedRegistration'),
  );
  assert.ok(guard.length > 0, 'the guard is missing');
  assert.match(guard, /upgradeOf\(install\)\.state === 'trial'/u);
  assert.match(guard, /_would_terminate_live_trial/u);
  // A deliberate abort owns the transaction and is allowed through; nothing
  // else is.
  assert.match(guard, /if \(abortingTransaction\) return;/u);

  // Both terminating operations consult it, and every call site does -- an
  // unguarded one added later is the whole failure mode returning.
  const stop = source.slice(source.indexOf('async function stopManagedRegistration'));
  assert.match(stop.slice(0, 400), /assertNoLiveTrial\(/u);
  for (const call of ['registerWindows(rendered)']) {
    let from = 0;
    let found = 0;
    for (;;) {
      const index = source.indexOf(call, from);
      if (index < 0) break;
      found += 1;
      const preceding = source.slice(Math.max(0, index - 400), index);
      assert.match(preceding, /assertNoLiveTrial\(/u, `${call} is not guarded`);
      from = index + call.length;
    }
    assert.ok(found > 0, `${call} was not found`);
  }
});

/**
 * The startup blind spot, and the barrier that closes it.
 *
 * A launcher between CreateProcess and binding its ownership pipe holds no
 * lock and Task Scheduler may already report the task Ready. An operation that
 * reads "free" during that window concludes the node is idle -- and that is
 * exactly how a launcher came to claim a freshly published trial and then be
 * killed by an `/End` that was already in flight, taking its candidate with it.
 */
void test('a start is not complete until the launcher is actually visible', async (t) => {
  const item = await harness('trial');
  t.after(() => item.cleanup());
  const nodeId = `node_${'a'.repeat(24)}`;

  // Nothing has started: the barrier must time out rather than report success.
  const missed = await waitForLauncherVisible(item.installPath, nodeId, 900);
  assert.equal(missed, false, 'a start that never arrives is a failure, not a success');

  // Now a launcher takes ownership the way a real one does, a little after the
  // request -- the invisible window the bug lived in.
  const endpoint = await launcherEndpointFor(item.installPath, nodeId);
  const holder = net.createServer((socket) => { socket.on('error', () => {}); socket.end(); });
  const appear = new Promise<void>((resolve) => {
    setTimeout(() => { holder.listen(endpoint, () => resolve()); }, 400);
  });

  const seen = await waitForLauncherVisible(item.installPath, nodeId, 10_000);
  await appear;
  assert.equal(seen, true, 'the barrier waits through the startup window');
  await new Promise<void>((resolve) => holder.close(() => resolve()));
});

void test('a stop is proven by held -> free, never by a single free reading', async (t) => {
  const item = await harness('trial');
  t.after(() => item.cleanup());
  const nodeId = `node_${'b'.repeat(24)}`;
  const endpoint = await launcherEndpointFor(item.installPath, nodeId);

  // A launcher is supervising. `/End` returns immediately; Task Scheduler
  // terminates the tree later. The barrier must keep waiting through that gap.
  const holder = net.createServer((socket) => { socket.on('error', () => {}); socket.end(); });
  await new Promise<void>((resolve, reject) => {
    holder.once('error', reject);
    holder.listen(endpoint, resolve);
  });

  let released = false;
  setTimeout(() => { released = true; holder.close(); }, 1_200);

  const started = Date.now();
  const gone = await waitForManagedGenerationGone(item.installPath, nodeId, true, 15_000);
  const waited = Date.now() - started;

  assert.equal(gone, true, 'the barrier resolves once the generation is really gone');
  assert.equal(released, true, 'it did not resolve before the termination landed');
  assert.ok(waited >= 1_000, `the barrier returned after ${waited}ms, before the stop landed`);
});

void test('a free reading alone does not prove a pending start is absent', async (t) => {
  const item = await harness('trial');
  t.after(() => item.cleanup());
  const nodeId = `node_${'c'.repeat(24)}`;

  // This is the production evidence, pinned: ownership currently reads free
  // only because a launcher has not bound its pipe yet. Told that a launcher
  // was held before the stop, the barrier must refuse to accept free -> free.
  const started = Date.now();
  const gone = await waitForManagedGenerationGone(item.installPath, nodeId, true, 900);
  assert.equal(gone, false, 'free -> free is not proof that a generation ended');
  assert.ok(Date.now() - started >= 800, 'it waited for a transition it never saw');

  // When nothing was held to begin with, free is a truthful answer.
  const trivially = await waitForManagedGenerationGone(item.installPath, nodeId, false, 5_000);
  assert.equal(trivially, true, 'nothing was running, so nothing has to end');
});

void test('the upgrade crosses the barrier before it publishes a trial', async () => {
  const source = await readFile(path.join(repoRoot, 'agent', 'autostart.ts'), 'utf8');
  const upgrade = source.slice(
    source.indexOf('export async function upgradeAutostart'),
    source.indexOf('export async function restorePreviousAutostart'),
  );
  const at = (needle: string): number => {
    const index = upgrade.indexOf(needle);
    assert.ok(index >= 0, `${needle} is missing`);
    return index;
  };
  // Ownership before the stop decides what proof is required after it.
  assert.ok(at('supervisedBeforeStop') < at('stopManagedRegistration(next)'));
  assert.ok(at('waitForManagedGenerationGone(') < at('beginTrial(next'));
  assert.ok(at('beginTrial(next') < at('startManagedRegistration(next'));

  // Task Scheduler state was proven to report Ready while a launcher was still
  // alive, so it may inform but never decide.
  const barrier = source.slice(
    source.indexOf('export async function waitForManagedGenerationGone'),
    source.indexOf('/** Starts the existing registration again'),
  );
  assert.match(barrier, /launcherOwnershipHeld\(/u);
  assert.match(barrier, /agentOwnershipHeld\(/u);
  assert.doesNotMatch(barrier, /schtasks|LastTaskResult|Status:/u);
});

void test('enable and repair report success only once the launcher supervises', async () => {
  const source = await readFile(path.join(repoRoot, 'agent', 'autostart.ts'), 'utf8');
  // Both native start paths confirm visibility, and both fail loudly rather
  // than reporting a start nobody can see.
  // Sliced to the next top-level declaration: the first `\n}` lands inside the
  // parameter object type, not at the end of the function.
  const install = source.slice(source.indexOf('async function installManagedAutostart'));
  const body = install.slice(0, install.indexOf('\nasync function', 1));
  assert.match(body, /waitForLauncherVisible\(/u);
  assert.match(body, /launcher_did_not_start/u);

  const start = source.slice(source.indexOf('async function startManagedRegistration'));
  const startBody = start.slice(0, start.indexOf('\n/** Waits until no Agent holds'));
  assert.match(startBody, /waitForLauncherVisible\(/u);
  assert.match(startBody, /launcher_did_not_start/u);
});
