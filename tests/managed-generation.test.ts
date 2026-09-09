/**
 * The pre-trial native quiescence barrier.
 *
 * These pin the exact production failure. Frozen Agent 0.6.0's `autostart
 * repair` starts a launcher through Task Scheduler and returns immediately; the
 * launcher binds its ownership pipe part-way through Node startup, measured at
 * 649 ms. An upgrade that samples ownership inside that window sees nothing
 * running, issues `schtasks /End`, and publishes a trial -- and the pending
 * termination then kills the launcher that picked the trial up, along with a
 * candidate that had already written a valid readiness marker.
 *
 * Ownership alone cannot see that launcher, so the barrier also requires the
 * native generation captured before the stop to be gone. Task Scheduler's
 * `Ready` state is not used: it was observed reporting Ready while such a
 * launcher was alive.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  NATIVE_GENERATION_PROBE,
  generationCleared,
  generationPresent,
  observeManagedNativeGeneration,
  parseNativeGeneration,
  type ManagedNativeGeneration,
} from '../agent/managed-generation.ts';

const INSTANCE_A = '{0373D4D7-0DB3-4CE0-9AB6-8DBEDE7DE348}';
const INSTANCE_B = '{D28F1442-C991-4912-98C0-D13ECA65767F}';

const empty = (): ManagedNativeGeneration => ({ instances: [], launchers: [] });

/**
 * The barrier's decision, isolated from timers and from the real ownership
 * pipes. `quiescent` is the exact conjunction the upgrade requires.
 */
function quiescent(input: {
  launcherHeld: boolean;
  agentHeld: boolean;
  before: ManagedNativeGeneration;
  now: ManagedNativeGeneration;
}): boolean {
  if (input.launcherHeld || input.agentHeld) return false;
  return generationCleared(input.before, input.now);
}

void test('a started-but-invisible launcher is not quiescent', () => {
  // The production case. Task Scheduler has created the process; the ownership
  // pipe is not bound yet, so both locks read free. Pre-fix this returned
  // "idle" and the trial was published on top of a doomed launcher.
  const before: ManagedNativeGeneration = { instances: [INSTANCE_A], launchers: [4321] };
  assert.equal(
    quiescent({ launcherHeld: false, agentHeld: false, before, now: before }),
    false,
    'ownership being free must not be read as nothing running',
  );
});

void test('the barrier holds until the captured generation actually goes', () => {
  const before: ManagedNativeGeneration = { instances: [INSTANCE_A], launchers: [4321] };

  // /End returns immediately; the generation is still there.
  assert.equal(quiescent({ launcherHeld: false, agentHeld: false, before, now: before }), false);

  // The task instance ends but the process has not gone yet.
  assert.equal(
    quiescent({ launcherHeld: false, agentHeld: false, before, now: { instances: [], launchers: [4321] } }),
    false,
  );

  // The process ends but the instance is still registered as running.
  assert.equal(
    quiescent({ launcherHeld: false, agentHeld: false, before, now: { instances: [INSTANCE_A], launchers: [] } }),
    false,
  );

  // Both gone, both locks free.
  assert.equal(quiescent({ launcherHeld: false, agentHeld: false, before, now: empty() }), true);
});

void test('late ownership keeps the barrier closed -- the exact 0.6.0 repair race', () => {
  const before: ManagedNativeGeneration = { instances: [INSTANCE_A], launchers: [4321] };

  // t0: process exists, ownership not yet bound.
  assert.equal(quiescent({ launcherHeld: false, agentHeld: false, before, now: before }), false);
  // t1: the launcher finally binds the pipe -- still not quiescent.
  assert.equal(quiescent({ launcherHeld: true, agentHeld: false, before, now: before }), false);
  // t2: termination lands; ownership released and the process is gone.
  assert.equal(quiescent({ launcherHeld: false, agentHeld: false, before, now: empty() }), true);
});

void test('a task reporting Ready proves nothing while its launcher lives', () => {
  // Task Scheduler was observed at `state=Ready lastResult=0` while the
  // launcher it had started was alive and became the trial supervisor. The
  // barrier therefore never consults that state -- only instances and the
  // exact launcher process.
  const before: ManagedNativeGeneration = { instances: [], launchers: [9192] };
  assert.equal(quiescent({ launcherHeld: false, agentHeld: false, before, now: before }), false);
  assert.ok(generationPresent(before));
  assert.ok(!NATIVE_GENERATION_PROBE.includes('State -eq'), 'the probe must not branch on task state');
  assert.ok(!NATIVE_GENERATION_PROBE.includes('Ready'), 'the probe must not consult Ready');
});

void test('nothing running before the stop clears immediately', () => {
  // A generation that never existed must not be invented; an upgrade on a node
  // with nothing running has to proceed.
  assert.equal(quiescent({ launcherHeld: false, agentHeld: false, before: empty(), now: empty() }), true);
  assert.equal(generationPresent(empty()), false);
});

void test('a launcher started after the stop is the new supervisor, not an obstacle', () => {
  // Only what was captured before the stop is waited for. The launcher the
  // upgrade itself starts must never hold its own barrier closed.
  const before: ManagedNativeGeneration = { instances: [INSTANCE_A], launchers: [4321] };
  const now: ManagedNativeGeneration = { instances: [INSTANCE_B], launchers: [7777] };
  assert.equal(quiescent({ launcherHeld: false, agentHeld: false, before, now }), true);
});

void test('one node never waits on another node', async () => {
  // Two managed nodes on one machine. The probe is scoped by the registration
  // and by this install's own launcher path, so node B's launcher is not even
  // returned -- there is no machine-wide "a YSD launcher is running".
  const calls: { arguments_: string[]; environment: Record<string, string> }[] = [];
  const generation = await observeManagedNativeGeneration({
    registrationId: '\\YSD Zero Cloud Node Agent aaaa',
    launcherPath: 'C:\\home\\managed\\aaaa\\launcher.mjs',
    powershell: 'powershell.exe',
    run: async (_file, arguments_, environment) => {
      calls.push({ arguments_, environment });
      // Node B's launcher is running; the probe filters on node A's path.
      return { code: 0, stdout: '', stderr: '' };
    },
  });
  assert.deepEqual(generation, empty());
  if (process.platform === 'win32') {
    const [call] = calls;
    assert.ok(call, 'the probe should have run');
    // Identity travels in the environment: it is never script text, and never
    // even a command-line argument, so it cannot be parsed as PowerShell.
    assert.equal(call!.environment.YSD_NATIVE_TASK, '\\YSD Zero Cloud Node Agent aaaa');
    assert.match(call!.environment.YSD_NATIVE_LAUNCHER ?? '', /launcher\.mjs$/u);
    assert.ok(!call!.arguments_.some((value) => value.includes('aaaa')),
      'node identity must not appear on the command line');
    assert.ok(call!.arguments_.includes('-NoProfile') && call!.arguments_.includes('-NonInteractive'));
    assert.ok(!call!.arguments_.some((value) => /ExecutionPolicy|Bypass/u.test(value)),
      'the probe must not weaken execution policy');
  }
});

void test('the probe reads identity from the environment and returns bounded values', () => {
  // `$args` is populated by -File, not by -Command, so identity is read from
  // the environment instead -- and the body stays a fixed constant.
  assert.match(NATIVE_GENERATION_PROBE, /\$env:YSD_NATIVE_TASK/u);
  assert.match(NATIVE_GENERATION_PROBE, /\$env:YSD_NATIVE_LAUNCHER/u);
  assert.ok(!NATIVE_GENERATION_PROBE.includes('$args'), 'the probe must not rely on $args');
  // Read-only: it must not be able to stop anything.
  for (const forbidden of ['Stop-Process', 'taskkill', 'Unregister-', 'Remove-', '/End', '/Delete']) {
    assert.ok(!NATIVE_GENERATION_PROBE.includes(forbidden), `the probe must not use ${forbidden}`);
  }

  const parsed = parseNativeGeneration(
    `instance ${INSTANCE_A}\nlauncher 4321\ninstance not-a-guid\nlauncher notanumber\nnoise\n`,
  );
  assert.deepEqual(parsed.instances, [INSTANCE_A]);
  assert.deepEqual(parsed.launchers, [4321]);

  // Bounded: a flood of output cannot grow the result without limit.
  const flood = Array.from({ length: 5_000 }, () => 'launcher 1').join('\n');
  assert.ok(parseNativeGeneration(flood).launchers.length <= 256);
});

void test('a failing probe never reports a node as quiet', async () => {
  // If the observation itself fails, the honest answer is "nothing observed",
  // and the ownership locks still gate the barrier. It must not throw into the
  // upgrade path.
  const generation = await observeManagedNativeGeneration({
    registrationId: '\\task',
    launcherPath: 'C:\\x\\launcher.mjs',
    powershell: 'powershell.exe',
    run: async () => { throw new Error('probe failed'); },
  });
  assert.deepEqual(generation, empty());
});
