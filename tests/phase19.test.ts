import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  AUTOSTART_CRASH_LIMIT,
  AUTOSTART_LOG_FILES,
  AUTOSTART_LOG_MAX_BYTES,
  appendManagedLog,
  buildManagedLauncherSource,
  copyManagedRelease,
  deriveManagedIdentity,
  enableAutostart,
  evaluateCrashBudget,
  managedLayout,
  redactManagedLog,
  renderLaunchAgent,
  renderSystemdUserUnit,
  renderWindowsTask,
  retainManagedReleases,
  validateManagedInstall,
  validateManagedStatus,
} from '../agent/autostart.ts';
import { acquireAgentOwnership } from '../agent/instance-lock.ts';
import { parseCapabilities, type NodeCapabilities } from '../lib/nodes.ts';

const safe = {
  instanceId: 'a1b2c3d4e5f60718',
  nodeExecutable: 'C:\\Program Files\\nodejs\\node.exe',
  launcherPath: 'C:\\Users\\Test & Co\\launcher.mjs',
  installPath: 'C:\\Users\\Test & Co\\install.json',
  workingDirectory: 'C:\\Users\\Test & Co\\managed',
  userId: 'S-1-5-21-1000',
  userName: 'TEST\\User',
};

const hash = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');

void test('managed identities are deterministic, bounded, and isolate config identities', async () => {
  const first = await deriveManagedIdentity('C:\\Users\\Example\\one.json', 'node_one');
  assert.equal(first, await deriveManagedIdentity('C:\\Users\\Example\\one.json', 'node_one'));
  assert.notEqual(first, await deriveManagedIdentity('C:\\Users\\Example\\two.json', 'node_one'));
  assert.notEqual(first, await deriveManagedIdentity('C:\\Users\\Example\\one.json', 'node_two'));
  assert.match(first, /^[a-f0-9]{16}$/);
  assert.doesNotMatch(first, /node|example|users/i);
});

void test('managed layout is rooted beside the existing credential without moving it', async () => {
  const layout = await managedLayout('/safe/node/credentials.json', 'node_one');
  assert.equal(layout.credentialPath, path.resolve('/safe/node/credentials.json'));
  assert.equal(path.dirname(layout.managedRoot), path.join(path.dirname(path.resolve('/safe/node/credentials.json')), 'managed'));
  assert.ok(layout.releaseRoot.startsWith(layout.managedRoot));
  assert.ok(layout.statusPath.startsWith(layout.managedRoot));
  assert.ok(layout.logDirectory.startsWith(layout.managedRoot));
});

void test('managed release copy verifies bytes, refuses mutation, and retains current plus previous', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ysd-phase19-release-'));
  try {
    const config = path.join(directory, 'credentials.json');
    const source = path.join(directory, 'source-agent.mjs');
    await writeFile(source, 'console.log("managed release");\n');
    const layout = await managedLayout(config, 'node_release_test');
    const copied = await copyManagedRelease(layout, source);
    assert.equal(copied.hash, hash(await readFile(source)));
    assert.equal(hash(await readFile(copied.releasePath)), copied.hash);
    await writeFile(copied.releasePath, 'mutated\n');
    await assert.rejects(copyManagedRelease(layout, source), /immutable managed release/);

    for (const version of ['0.3.0', '0.4.0', '0.5.0']) {
      await mkdir(path.join(layout.releaseRoot, version), { recursive: true });
      await writeFile(path.join(layout.releaseRoot, version, 'agent.mjs'), version);
    }
    await retainManagedReleases(layout, '0.6.0', '0.5.0');
    assert.deepEqual((await readdir(layout.releaseRoot)).sort(), ['0.5.0', '0.6.0']);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test('native manager renderers use user scope, absolute argv, and contain no secrets', () => {
  const secret = `node_${'s'.repeat(48)}`;
  const windows = renderWindowsTask({ ...safe, origin: 'https://example.test' });
  assert.match(windows.xml, /<LogonType>InteractiveToken<\/LogonType>/);
  assert.match(windows.xml, /<RunLevel>LeastPrivilege<\/RunLevel>/);
  assert.match(windows.xml, /<MultipleInstancesPolicy>IgnoreNew<\/MultipleInstancesPolicy>/);
  assert.match(windows.xml, /<Priority>4<\/Priority>/);
  assert.match(windows.xml, /<RestartOnFailure>/);
  assert.match(windows.xml, /Test &amp; Co/);
  assert.doesNotMatch(windows.xml, /powershell|cmd\.exe|shell|LocalSystem/i);

  const systemd = renderSystemdUserUnit({ ...safe, origin: 'https://example.test' });
  assert.match(systemd, /WantedBy=default\.target/);
  assert.match(systemd, /Restart=on-failure/);
  assert.match(systemd, /\[Unit\][\s\S]*StartLimitIntervalSec=600s[\s\S]*\n\n\[Service\]/);
  assert.doesNotMatch(systemd, /\[Service\][\s\S]*StartLimitIntervalSec/);
  assert.doesNotMatch(systemd, /User=|enable-linger|\/etc\/systemd|sh -c/);

  const launchAgent = renderLaunchAgent({ ...safe, origin: 'https://example.test' });
  assert.match(launchAgent, /<key>ProgramArguments<\/key>\s*<array>/);
  assert.match(launchAgent, /<key>SuccessfulExit<\/key>\s*<false\/>/);
  assert.match(launchAgent, /Test &amp; Co/);
  assert.doesNotMatch(launchAgent, /LaunchDaemons|sh<\/string>|-c<\/string>/);

  for (const rendered of [windows.xml, systemd, launchAgent]) {
    assert.doesNotMatch(rendered, new RegExp(secret));
    assert.doesNotMatch(rendered, /YSD_NODE_AGENT_KEY|ysdp_|Authorization:|cookie=|session=/i);
  }
});

void test('hostile path characters stay data rather than becoming shell syntax', () => {
  const hostile = {
    ...safe,
    launcherPath: '/tmp/a & b;$(touch nope)`x`\nline/launcher.mjs',
    installPath: '/tmp/a & b;$(touch nope)`x`\nline/install.json',
    workingDirectory: '/tmp/a & b;$(touch nope)`x`\nline',
    nodeExecutable: '/opt/Node & Co/bin/node',
    origin: 'https://example.test',
  };
  assert.throws(() => renderWindowsTask(hostile), /control characters/);
  assert.throws(() => renderSystemdUserUnit(hostile), /control characters/);
  assert.throws(() => renderLaunchAgent(hostile), /control characters/);
});

void test('crash budget is finite, persisted-shaped, and terminal outcomes never retry', () => {
  const start = 1_000_000;
  let failures: number[] = [];
  for (let index = 0; index < AUTOSTART_CRASH_LIMIT; index += 1) {
    const decision = evaluateCrashBudget(failures, start + index * 1_000, 'unexpected_crash');
    failures = decision.failures;
    assert.equal(decision.retry, index + 1 < AUTOSTART_CRASH_LIMIT);
  }
  assert.equal(evaluateCrashBudget(failures, start + 4_000, 'unexpected_crash').retry, false);
  assert.equal(evaluateCrashBudget([], start, 'authorization_rejected').retry, false);
  assert.equal(evaluateCrashBudget([], start, 'already_running').retry, false);
});

void test('bounded logging redacts secret-shaped values and publishes fixed bounds', () => {
  const message = redactManagedLog(
    `Authorization: Bearer node_${'x'.repeat(40)} cookie=session-secret YSD_NODE_AGENT_KEY=top-secret ysdp_${'a'.repeat(32)}`,
  );
  assert.equal(AUTOSTART_LOG_FILES, 4);
  assert.equal(AUTOSTART_LOG_MAX_BYTES, 256 * 1024);
  assert.doesNotMatch(message, /session-secret|top-secret|node_x|ysdp_/);
  assert.match(message, /\[REDACTED\]/);
});

void test('managed status accepts only bounded public fields', () => {
  assert.ok(validateManagedStatus({
    version: 1,
    enabled: true,
    manager: 'windows-task-scheduler',
    scope: 'user-session',
    state: 'enabled',
    agentVersion: '0.6.0',
    lastStartAt: 100,
    lastExitAt: null,
    restartCount: 0,
    registrationFingerprint: 'a'.repeat(64),
    crashFailures: [],
  }));
  assert.equal(validateManagedStatus({ version: 1, enabled: true, manager: 'evil' }), null);
  assert.equal(validateManagedStatus({
    version: 1, enabled: true, manager: 'windows-task-scheduler', scope: 'user-session',
    state: 'enabled', agentVersion: '0.6.0', lastStartAt: 1, lastExitAt: null,
    restartCount: 0, registrationFingerprint: 'a'.repeat(64), crashFailures: [],
    localPath: 'C:\\secret',
  }), null);
});

void test('managed install metadata is strict, path-safe, and contains no credential value', () => {
  const install = {
    version: 1,
    instanceId: safe.instanceId,
    agentVersion: '0.6.0',
    protocolVersion: 1,
    previousVersion: null,
    nodeExecutable: safe.nodeExecutable,
    releasePath: 'C:\\Users\\Test & Co\\releases\\0.6.0\\agent.mjs',
    releaseHash: 'a'.repeat(64),
    launcherPath: safe.launcherPath,
    launcherHash: 'b'.repeat(64),
    credentialPath: 'C:\\Users\\Test & Co\\credentials.json',
    agentHome: 'C:\\Users\\Test & Co',
    origin: 'https://example.test',
    manager: 'windows-task-scheduler' as const,
    scope: 'user-session' as const,
    registrationId: `\\YSD Zero Cloud Node Agent ${safe.instanceId}`,
    registrationFingerprint: 'c'.repeat(64),
    workingDirectory: safe.workingDirectory,
    updatedAt: 123,
  };
  assert.deepEqual(validateManagedInstall(install), install);
  assert.equal(validateManagedInstall({ ...install, token: `node_${'x'.repeat(40)}` }), null);
  assert.equal(validateManagedInstall({ ...install, releasePath: 'relative-agent.mjs' }), null);
  assert.equal(validateManagedInstall({ ...install, origin: 'https://user:secret@example.test' }), null);
});

void test('external environment keys are never copied into a managed registration', async () => {
  const previous = process.env.YSD_NODE_AGENT_KEY;
  process.env.YSD_NODE_AGENT_KEY = 'test-only-secret-value';
  try {
    await assert.rejects(
      enableAutostart({ credentialPath: 'C:\\does-not-matter.json', origin: 'https://example.test' }),
      /credential_key_unavailable/,
    );
  } finally {
    if (previous === undefined) delete process.env.YSD_NODE_AGENT_KEY;
    else process.env.YSD_NODE_AGENT_KEY = previous;
  }
});

void test('standalone launcher persists terminal outcomes and a finite crash budget', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ysd-phase19-launcher-'));
  try {
    const launcherPath = path.join(directory, 'launcher.mjs');
    const releasePath = path.join(directory, 'agent.mjs');
    const installPath = path.join(directory, 'install.json');
    const statusPath = path.join(directory, 'status.json');
    await mkdir(path.join(directory, 'logs'));
    await writeFile(launcherPath, buildManagedLauncherSource());
    const install = {
      version: 1, instanceId: 'a'.repeat(16), agentVersion: '0.6.0', protocolVersion: 1,
      previousVersion: null, nodeExecutable: process.execPath, releasePath,
      releaseHash: '', launcherPath, launcherHash: hash(await readFile(launcherPath)),
      credentialPath: path.join(directory, 'credentials.json'), agentHome: directory,
      origin: 'http://localhost:3000', manager: 'windows-task-scheduler', scope: 'user-session',
      registrationId: '\\YSD Zero Cloud Node Agent aaaaaaaaaaaaaaaa',
      registrationFingerprint: 'c'.repeat(64), workingDirectory: directory, updatedAt: Date.now(),
    };
    const initial = {
      version: 1, enabled: true, manager: 'windows-task-scheduler', scope: 'user-session',
      state: 'enabled', agentVersion: '0.6.0', lastStartAt: null, lastExitAt: null,
      restartCount: 0, registrationFingerprint: 'c'.repeat(64), crashFailures: [],
    };

    await writeFile(releasePath, 'process.exit(21);\n');
    install.releaseHash = hash(await readFile(releasePath));
    await writeFile(installPath, JSON.stringify(install));
    await writeFile(statusPath, JSON.stringify(initial));
    let launched = spawnSync(process.execPath, [launcherPath, '--install', installPath], { cwd: directory });
    assert.equal(launched.status, 0);
    assert.equal(JSON.parse(await readFile(statusPath, 'utf8')).state, 'authorization_rejected');

    await writeFile(releasePath, 'process.exit(1);\n');
    install.releaseHash = hash(await readFile(releasePath));
    await writeFile(installPath, JSON.stringify(install));
    await writeFile(statusPath, JSON.stringify(initial));
    launched = spawnSync(process.execPath, [launcherPath, '--install', installPath], { cwd: directory });
    assert.equal(launched.status, 0);
    const limited = JSON.parse(await readFile(statusPath, 'utf8'));
    assert.equal(limited.state, 'restart_limited');
    assert.equal(limited.restartCount, AUTOSTART_CRASH_LIMIT);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test('standalone launcher distinguishes missing Node, missing Agent, and corrupt Agent', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ysd-phase19-validation-'));
  try {
    const launcherPath = path.join(directory, 'launcher.mjs');
    const releasePath = path.join(directory, 'agent.mjs');
    const installPath = path.join(directory, 'install.json');
    const statusPath = path.join(directory, 'status.json');
    await writeFile(launcherPath, buildManagedLauncherSource());
    await writeFile(releasePath, 'process.exit(0);\n');
    const install = {
      version: 1, instanceId: 'b'.repeat(16), agentVersion: '0.6.0', protocolVersion: 1,
      previousVersion: null, nodeExecutable: process.execPath, releasePath,
      releaseHash: hash(await readFile(releasePath)), launcherPath,
      launcherHash: hash(await readFile(launcherPath)), credentialPath: path.join(directory, 'credentials.json'),
      agentHome: directory, origin: 'http://localhost:3000', manager: 'windows-task-scheduler',
      scope: 'user-session', registrationId: '\\YSD Zero Cloud Node Agent bbbbbbbbbbbbbbbb',
      registrationFingerprint: 'd'.repeat(64), workingDirectory: directory, updatedAt: Date.now(),
    };
    const invoke = async (mutation: Record<string, unknown>) => {
      await writeFile(installPath, JSON.stringify({ ...install, ...mutation }));
      await rm(statusPath, { force: true });
      const result = spawnSync(process.execPath, [launcherPath, '--install', installPath], { cwd: directory });
      assert.equal(result.status, 0);
      return JSON.parse(await readFile(statusPath, 'utf8')).state;
    };
    assert.equal(await invoke({ nodeExecutable: path.join(directory, 'missing-node.exe') }), 'node_runtime_missing');
    assert.equal(await invoke({ releasePath: path.join(directory, 'missing-agent.mjs') }), 'agent_missing');
    assert.equal(await invoke({ releaseHash: '0'.repeat(64) }), 'registration_invalid');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test('headless log rotation is capped and redacts every synthetic credential', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ysd-phase19-logs-'));
  try {
    const secret = `node_${'z'.repeat(40)}`;
    for (let index = 0; index < 7; index += 1) {
      await appendManagedLog(directory, `${secret} YSD_NODE_AGENT_KEY=fixture-secret ${'x'.repeat(150_000)}\n`);
    }
    await appendManagedLog(directory, '🙂'.repeat(AUTOSTART_LOG_MAX_BYTES));
    const names = (await readdir(directory)).sort();
    assert.deepEqual(names, ['agent.1.log', 'agent.2.log', 'agent.3.log', 'agent.log']);
    for (const name of names) {
      assert.ok((await stat(path.join(directory, name))).size <= AUTOSTART_LOG_MAX_BYTES);
      const contents = await readFile(path.join(directory, name), 'utf8');
      assert.doesNotMatch(contents, /fixture-secret|node_z/);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test('one node identity has one local ownership winner and a clean restart', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ysd-phase19-lock-'));
  const config = path.join(directory, 'credentials.json');
  await writeFile(config, '{}', { mode: 0o600 });
  const first = await acquireAgentOwnership(config, 'node_one');
  try {
    await assert.rejects(acquireAgentOwnership(config, 'node_one'), /already_running/);
    const other = await acquireAgentOwnership(config, 'node_two');
    await other.release();
  } finally {
    await first.release();
  }
  const restarted = await acquireAgentOwnership(config, 'node_one');
  await restarted.release();
  await rm(directory, { recursive: true, force: true });
});

void test('Protocol 1 capabilities carry a narrow optional autostart observation', () => {
  const capabilities: NodeCapabilities = {
    cpu: { cores: 2, model: 'test' },
    memory: { totalBytes: 1024, freeBytes: 512 },
    gpu: { available: false, model: null, vramBytes: null },
    disk: { totalBytes: 1024, freeBytes: 512 },
    docker: { available: false },
    ai: { runtimes: [], cachedModels: [], maxConcurrentJobs: 1 },
    gameServers: { minecraftJavaAvailable: false, javaVersion: null, activeServers: 0, maxConcurrentServers: 1 },
    contracts: { ai: false, gameServers: false, autostart: true },
    autostart: {
      version: 1, supported: true, enabled: true,
      manager: 'windows-task-scheduler', scope: 'user-session', state: 'enabled',
    },
  };
  assert.deepEqual(parseCapabilities(capabilities)?.autostart, capabilities.autostart);
  assert.equal(parseCapabilities({ ...capabilities, autostart: { ...capabilities.autostart, manager: 'service' } }), null);
});

void test('Phase 19 adds no migration and no remote autostart mutation route', async () => {
  const root = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1'));
  const migrations = await import('node:fs/promises').then(({ readdir }) => readdir(path.join(root, 'db', 'migrations')));
  assert.equal(migrations.at(-1), '0020_runtime_recovery.sql');
  assert.equal(migrations.some((name) => name.startsWith('0021')), false);
  const routes = await import('node:fs/promises').then(({ readdir }) => readdir(path.join(root, 'app', 'api', 'nodes')));
  assert.equal(routes.includes('autostart'), false);
  assert.doesNotMatch(await readFile(path.join(root, 'lib', 'nodes.ts'), 'utf8'), /node_job[^\n]*autostart|autostart[^\n]*node_job/i);
});

void test('central recovery harness owns exact processes and never broad-kills Node', async () => {
  const root = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1'));
  const harness = await readFile(path.join(root, 'phase19-recovery-acceptance.py'), 'utf8');
  assert.match(harness, /control_plane = subprocess\.Popen/);
  assert.match(harness, /free_loopback_port\(\)/);
  assert.match(harness, /wait_task_idle\(task_name, install\)/);
  assert.match(harness, /taskkill\.exe", "\/PID", str\(control_plane\.pid\)/);
  assert.match(harness, /row\.get\("ParentProcessId"\) == launchers\[0\]\.get\("ProcessId"\)/);
  assert.doesNotMatch(harness, /def agent_pid|remaining_agent|taskkill[^\n]*(?:node\.exe|\/IM)/i);
});

void test('App Runtime confirms child creation before entering recovery health checks', async () => {
  const root = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1'));
  const source = await readFile(path.join(root, 'agent', 'app-runtime.ts'), 'utf8');
  const spawnConfirmation = source.indexOf("child.once('spawn', resolve)");
  const managedRegistration = source.indexOf('managedApps.set(app.deploymentId, app)', spawnConfirmation);
  assert.ok(spawnConfirmation > 0 && managedRegistration > spawnConfirmation);
});

void test('App Runtime keeps protocol stdout JSON-only while managed diagnostics use stderr', async () => {
  const root = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1'));
  const runtime = await readFile(path.join(root, 'agent', 'app-runtime.ts'), 'utf8');
  const launcher = buildManagedLauncherSource();
  assert.match(runtime, /console\.error\('App Runtime start:/);
  assert.match(runtime, /console\.error\(`App Runtime recovery phase:/);
  assert.match(runtime, /console\.error\(`App Runtime recovery diagnostic:/);
  assert.doesNotMatch(runtime, /console\.log\([^\n]*App Runtime (?:start|recovery)/);
  assert.match(launcher, /child\.stdout\.on\('data',[^\n]*queueLog/);
  assert.match(launcher, /child\.stderr\.on\('data',[^\n]*queueLog/);
});
