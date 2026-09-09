import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  appendFile,
  chmod,
  copyFile,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  statfs,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { loadCredentials } from './credentials.ts';
import { agentHomeDirectory } from './agent-key.ts';
import {
  CURRENT_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  isStrictVersion,
  type AutostartCapability,
} from '../lib/nodes.ts';
import {
  AUTOSTART_CRASH_LIMIT,
  AUTOSTART_CRASH_WINDOW_MS,
  AUTOSTART_LOG_FILES,
  AUTOSTART_LOG_MAX_BYTES,
  LEGACY_STATUS_KEYS,
  MANAGERS,
  MANAGED_INSTALL_SCHEMA,
  MANAGED_RELEASE_TRANSACTION_LIMIT,
  STATES,
  UPGRADE_MINIMUM_FREE_BYTES,
  beginTrial,
  buildReadinessMarker,
  currentRelease,
  deriveManagedIdentity,
  evaluateRestoreTarget,
  evaluateUpgradeCandidate,
  idleUpgrade,
  canonicalCredentialPath,
  isManagedRelease,
  projectUpgradeStatus,
  resetTransaction,
  stageTransaction,
  upgradeOf,
  validateManagedUpgrade,
  validateUpgradeStatus,
  type AutostartManager,
  type AutostartState,
  type ManagedRelease,
  type ManagedUpgrade,
  type UpgradeReason,
  type UpgradeStatus,
} from './managed-upgrade.ts';
import { buildManagedLauncherSource } from './managed-launcher.ts';
import {
  generationCleared,
  observeManagedNativeGeneration,
  type ManagedNativeGeneration,
} from './managed-generation.ts';
import {
  acquireMaintenanceOwnership,
  agentOwnershipHeld,
  launcherOwnershipHeld,
  requestManagedUpgradeShutdown,
} from './instance-lock.ts';

export * from './managed-upgrade.ts';
export { buildManagedLauncherSource } from './managed-launcher.ts';

export type ManagedLayout = {
  instanceId: string;
  credentialPath: string;
  agentHome: string;
  managedRoot: string;
  releaseRoot: string;
  launcherPath: string;
  installPath: string;
  statusPath: string;
  readinessPath: string;
  logDirectory: string;
};

export type ManagedInstall = {
  /**
   * Stays `1`. This is the shape the Phase 19 launcher validates, and a
   * launcher that refuses the file cannot start the Agent that is already
   * working. Phase 20 adds fields instead of changing this number, and marks
   * the revision with `installSchema` for anything that wants to know.
   */
  version: 1;
  installSchema?: typeof MANAGED_INSTALL_SCHEMA;
  instanceId: string;
  agentVersion: string;
  protocolVersion: number;
  previousVersion: string | null;
  /** The exact Agent to restore to: version, path and hash, all verified. */
  previousRelease?: ManagedRelease | null;
  /** The in-flight upgrade transaction, if any. Absent means idle. */
  upgrade?: ManagedUpgrade | null;
  nodeExecutable: string;
  releasePath: string;
  releaseHash: string;
  launcherPath: string;
  launcherHash: string;
  credentialPath: string;
  agentHome: string;
  origin: string;
  manager: AutostartManager;
  scope: 'user-session';
  registrationId: string;
  registrationFingerprint: string;
  workingDirectory: string;
  updatedAt: number;
};

export type ManagedStatus = {
  version: 1;
  enabled: boolean;
  manager: AutostartManager;
  scope: 'user-session';
  state: AutostartState;
  agentVersion: string;
  lastStartAt: number | null;
  lastExitAt: number | null;
  restartCount: number;
  registrationFingerprint: string | null;
  crashFailures: number[];
};

/**
 * What `autostart status` prints. The transaction projection lives here, on
 * the command's own response, rather than in `status.json` -- that file is the
 * Phase 19 contract and an Agent restored to 0.6.0 has to keep reading it.
 */
export type ManagedStatusReport = ManagedStatus & {
  upgrade: UpgradeStatus | null;
};

type ManagerInput = {
  instanceId: string;
  nodeExecutable: string;
  launcherPath: string;
  installPath: string;
  workingDirectory: string;
  origin: string;
  userId: string;
  userName: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sha256Bytes(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

async function hashFile(file: string): Promise<string> {
  return sha256Bytes(await readFile(file));
}

export async function managedLayout(
  credentialPath: string,
  nodeId: string,
): Promise<ManagedLayout> {
  const resolved = path.resolve(credentialPath);
  const instanceId = await deriveManagedIdentity(resolved, nodeId);
  const managedRoot = path.join(path.dirname(resolved), 'managed', instanceId);
  return {
    instanceId,
    credentialPath: resolved,
    agentHome: agentHomeDirectory(),
    managedRoot,
    releaseRoot: path.join(managedRoot, 'releases'),
    launcherPath: path.join(managedRoot, 'launcher.mjs'),
    installPath: path.join(managedRoot, 'install.json'),
    statusPath: path.join(managedRoot, 'status.json'),
    readinessPath: path.join(managedRoot, 'readiness.json'),
    logDirectory: path.join(managedRoot, 'logs'),
  };
}

function assertSafePath(value: string, label: string): string {
  if (!path.isAbsolute(value) || value.includes(String.fromCharCode(0)) || /[\r\n]/u.test(value)) {
    throw new Error(`${label} must be an absolute path without control characters.`);
  }
  return value;
}

function xml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function windowsArgument(value: string): string {
  if (!/[\s"]/u.test(value)) return value;
  return `"${value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/g, '$1$1')}"`;
}

function systemdArgument(value: string): string {
  assertSafePath(value, 'systemd argument');
  return `"${value
    .replaceAll('\\', '\\\\')
    .replaceAll('"', '\\"')
    .replaceAll('%', '%%')}"`;
}

function registrationShape(input: ManagerInput, manager: AutostartManager) {
  return {
    version: 1,
    manager,
    instanceId: input.instanceId,
    nodeExecutable: input.nodeExecutable,
    launcherPath: input.launcherPath,
    installPath: input.installPath,
    workingDirectory: input.workingDirectory,
    scope: 'user-session',
    userId: input.userId,
    restartCount: AUTOSTART_CRASH_LIMIT,
    restartInterval: 60,
  };
}

export function renderWindowsTask(input: ManagerInput): {
  id: string;
  xml: string;
  fingerprint: string;
} {
  for (const [label, value] of [
    ['Node executable', input.nodeExecutable],
    ['Launcher', input.launcherPath],
    ['Install metadata', input.installPath],
    ['Working directory', input.workingDirectory],
  ] as const) assertSafePath(value, label);
  if (!/^S-\d(?:-\d+)+$/u.test(input.userId)) throw new Error('A Windows user SID is required.');
  // Keep the task at the root so stock Windows can register it without first
  // creating a custom Task Scheduler folder.
  const id = `\\YSD Zero Cloud Node Agent ${input.instanceId}`;
  const arguments_ = [input.launcherPath, '--install', input.installPath]
    .map(windowsArgument)
    .join(' ');
  const shape = registrationShape(input, 'windows-task-scheduler');
  const document = [
    '<?xml version="1.0" encoding="UTF-16"?>',
    '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
    '  <RegistrationInfo><Description>YSD Zero Cloud user-session Compute Node Agent</Description></RegistrationInfo>',
    '  <Triggers><LogonTrigger><Enabled>true</Enabled>',
    `    <UserId>${xml(input.userId)}</UserId><Delay>PT15S</Delay>`,
    '  </LogonTrigger></Triggers>',
    '  <Principals><Principal id="Author">',
    `    <UserId>${xml(input.userId)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel>`,
    '  </Principal></Principals>',
    '  <Settings>',
    '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>',
    '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>',
    '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>',
    '    <AllowHardTerminate>true</AllowHardTerminate>',
    '    <StartWhenAvailable>true</StartWhenAvailable>',
    '    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>',
    '    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>',
    '    <Priority>4</Priority>',
    `    <RestartOnFailure><Interval>PT1M</Interval><Count>${AUTOSTART_CRASH_LIMIT}</Count></RestartOnFailure>`,
    '  </Settings>',
    '  <Actions Context="Author"><Exec>',
    `    <Command>${xml(input.nodeExecutable)}</Command>`,
    `    <Arguments>${xml(arguments_)}</Arguments>`,
    `    <WorkingDirectory>${xml(input.workingDirectory)}</WorkingDirectory>`,
    '  </Exec></Actions>',
    '</Task>',
  ].join('\r\n');
  return { id, xml: document, fingerprint: sha256Bytes(JSON.stringify(shape)) };
}

export function renderSystemdUserUnit(input: ManagerInput): string {
  const executable = systemdArgument(input.nodeExecutable);
  const launcher = systemdArgument(input.launcherPath);
  const install = systemdArgument(input.installPath);
  const workingDirectory = systemdArgument(input.workingDirectory);
  return [
    '[Unit]',
    'Description=YSD Zero Cloud user-session Compute Node Agent',
    'After=network-online.target',
    'StartLimitIntervalSec=600s',
    `StartLimitBurst=${AUTOSTART_CRASH_LIMIT}`,
    '',
    '[Service]',
    'Type=simple',
    `WorkingDirectory=${workingDirectory}`,
    `ExecStart=${executable} ${launcher} --install ${install}`,
    'Restart=on-failure',
    'RestartSec=60s',
    'RestartPreventExitStatus=20 21 22 23 24',
    'NoNewPrivileges=true',
    '',
    '[Install]',
    'WantedBy=default.target',
    '',
  ].join('\n');
}

export function renderLaunchAgent(input: ManagerInput): string {
  for (const [label, value] of [
    ['Node executable', input.nodeExecutable],
    ['Launcher', input.launcherPath],
    ['Install metadata', input.installPath],
    ['Working directory', input.workingDirectory],
  ] as const) assertSafePath(value, label);
  const label = `com.openysd.ysd-zero-cloud.node-agent.${input.instanceId}`;
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0"><dict>',
    `<key>Label</key><string>${xml(label)}</string>`,
    '<key>ProgramArguments</key><array>',
    `<string>${xml(input.nodeExecutable)}</string>`,
    `<string>${xml(input.launcherPath)}</string>`,
    '<string>--install</string>',
    `<string>${xml(input.installPath)}</string>`,
    '</array>',
    `<key>WorkingDirectory</key><string>${xml(input.workingDirectory)}</string>`,
    '<key>RunAtLoad</key><true/>',
    '<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>',
    '<key>ThrottleInterval</key><integer>60</integer>',
    '<key>ProcessType</key><string>Background</string>',
    '</dict></plist>',
    '',
  ].join('\n');
}

export function redactManagedLog(value: string): string {
  return value
    .replace(/\bAuthorization\s*:\s*[^\r\n]+/giu, 'Authorization: [REDACTED]')
    .replace(/\b(cookie|session)\s*[=:]\s*[^\s;]+/giu, '$1=[REDACTED]')
    .replace(/\bYSD_NODE_AGENT_KEY\s*=\s*[^\s]+/giu, 'YSD_NODE_AGENT_KEY=[REDACTED]')
    .replace(/\bysdp_[A-Za-z0-9_-]{16,}/gu, '[REDACTED]')
    .replace(/\bnode_[A-Za-z0-9_.-]{20,}/gu, '[REDACTED]');
}

function boundedUtf8Tail(value: string, maximumBytes: number): string {
  const bytes = Buffer.from(value);
  if (bytes.length <= maximumBytes) return value;
  let start = bytes.length - maximumBytes;
  while (start < bytes.length && (bytes[start]! & 0xc0) === 0x80) start += 1;
  return bytes.subarray(start).toString('utf8');
}

export function evaluateCrashBudget(
  previous: number[],
  now: number,
  outcome: string,
): { retry: boolean; failures: number[] } {
  if (outcome !== 'unexpected_crash') return { retry: false, failures: previous };
  const failures = previous
    .filter((timestamp) => Number.isSafeInteger(timestamp) && timestamp >= now - AUTOSTART_CRASH_WINDOW_MS && timestamp <= now)
    .concat(now)
    .slice(-AUTOSTART_CRASH_LIMIT);
  return { retry: failures.length < AUTOSTART_CRASH_LIMIT, failures };
}

/**
 * Reads a managed status file and normalises it to the Phase 19 shape.
 *
 * Liberal in what it accepts, conservative in what it writes. Agent 0.7.0
 * shipped an extra `upgrade` key here; tolerating it on read means a node
 * upgraded by 0.7.0 keeps its crash-budget history instead of starting over,
 * and {@link legacyManagedStatus} guarantees that whatever this process writes
 * back is a file Agent 0.6.0 can still parse.
 */
export function validateManagedStatus(value: unknown): ManagedStatus | null {
  if (!isRecord(value)) return null;
  const expected = [...LEGACY_STATUS_KEYS];
  // Exactly one historical key is tolerated, and it is dropped from the
  // result. Nothing else is: an unknown key still means an unknown file.
  const required = Object.keys(value).filter((key) => key !== 'upgrade');
  if (required.sort().join('\0') !== expected.sort().join('\0')) return null;
  if (value.upgrade !== undefined && value.upgrade !== null && !validateUpgradeStatus(value.upgrade)) return null;
  if (
    value.version !== 1 ||
    typeof value.enabled !== 'boolean' ||
    !MANAGERS.includes(value.manager as AutostartManager) ||
    value.scope !== 'user-session' ||
    !STATES.includes(value.state as AutostartState) ||
    typeof value.agentVersion !== 'string' || value.agentVersion.length > 32 ||
    !(value.lastStartAt === null || (Number.isSafeInteger(value.lastStartAt) && Number(value.lastStartAt) >= 0)) ||
    !(value.lastExitAt === null || (Number.isSafeInteger(value.lastExitAt) && Number(value.lastExitAt) >= 0)) ||
    !Number.isSafeInteger(value.restartCount) || Number(value.restartCount) < 0 || Number(value.restartCount) > AUTOSTART_CRASH_LIMIT ||
    !(value.registrationFingerprint === null || (typeof value.registrationFingerprint === 'string' && /^[a-f0-9]{64}$/u.test(value.registrationFingerprint))) ||
    !Array.isArray(value.crashFailures) || value.crashFailures.length > AUTOSTART_CRASH_LIMIT ||
    value.crashFailures.some((entry) => !Number.isSafeInteger(entry) || Number(entry) < 0)
  ) return null;
  return legacyManagedStatus(value as ManagedStatus);
}

/** Projects a status onto exactly the keys Agent 0.6.0 accepts, in order. */
export function legacyManagedStatus(status: ManagedStatus): ManagedStatus {
  const source = status as unknown as Record<string, unknown>;
  const legacy: Record<string, unknown> = {};
  for (const key of LEGACY_STATUS_KEYS) legacy[key] = source[key];
  return legacy as unknown as ManagedStatus;
}

/**
 * The only place this process writes `status.json`.
 *
 * Everything goes through the legacy projection, so no future field can leak
 * into a file that an older Agent has to parse.
 */
async function writeManagedStatus(statusPath: string, status: ManagedStatus): Promise<void> {
  await atomicWrite(statusPath, `${JSON.stringify(legacyManagedStatus(status))}\n`);
}

export function validateManagedInstall(value: unknown): ManagedInstall | null {
  if (!isRecord(value)) return null;
  const expected = [
    'agentHome', 'agentVersion', 'credentialPath', 'instanceId', 'launcherHash',
    'launcherPath', 'manager', 'nodeExecutable', 'origin', 'previousVersion',
    'protocolVersion', 'registrationFingerprint', 'registrationId', 'releaseHash',
    'releasePath', 'scope', 'updatedAt', 'version', 'workingDirectory',
  ];
  const optional = new Set(['installSchema', 'previousRelease', 'upgrade']);
  const required = Object.keys(value).filter((key) => !optional.has(key));
  if (required.sort().join('\0') !== expected.sort().join('\0')) return null;
  if (value.installSchema !== undefined && value.installSchema !== MANAGED_INSTALL_SCHEMA) return null;
  if (value.previousRelease !== undefined && value.previousRelease !== null && !isManagedRelease(value.previousRelease)) return null;
  if (value.upgrade !== undefined && value.upgrade !== null && !validateManagedUpgrade(value.upgrade)) return null;
  if (
    value.version !== 1 ||
    typeof value.instanceId !== 'string' || !/^[a-f0-9]{16}$/u.test(value.instanceId) ||
    typeof value.agentVersion !== 'string' || !/^\d+\.\d+\.\d+$/u.test(value.agentVersion) ||
    value.protocolVersion !== NODE_PROTOCOL_VERSION ||
    !(value.previousVersion === null || (typeof value.previousVersion === 'string' && /^\d+\.\d+\.\d+$/u.test(value.previousVersion))) ||
    !MANAGERS.includes(value.manager as AutostartManager) ||
    value.scope !== 'user-session' ||
    typeof value.origin !== 'string' || value.origin.length > 2048 ||
    typeof value.registrationId !== 'string' || value.registrationId.length > 256 ||
    typeof value.registrationFingerprint !== 'string' || !/^[a-f0-9]{64}$/u.test(value.registrationFingerprint) ||
    typeof value.releaseHash !== 'string' || !/^[a-f0-9]{64}$/u.test(value.releaseHash) ||
    typeof value.launcherHash !== 'string' || !/^[a-f0-9]{64}$/u.test(value.launcherHash) ||
    !Number.isSafeInteger(value.updatedAt) || Number(value.updatedAt) < 0
  ) return null;
  for (const key of ['nodeExecutable', 'releasePath', 'launcherPath', 'credentialPath', 'agentHome', 'workingDirectory'] as const) {
    if (typeof value[key] !== 'string' || !path.isAbsolute(value[key]) || value[key].includes(String.fromCharCode(0)) || /[\r\n]/u.test(value[key])) return null;
  }
  try {
    const parsed = new URL(value.origin);
    const local = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    if ((parsed.protocol !== 'https:' && !(local && parsed.protocol === 'http:')) || parsed.origin !== value.origin) return null;
  } catch { return null; }
  return value as ManagedInstall;
}

async function atomicWrite(file: string, contents: string, mode = 0o600): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  const handle = await open(temporary, 'wx', mode);
  try {
    await handle.writeFile(contents, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, file);
  if (process.platform !== 'win32') await chmod(file, mode);
}

export async function appendManagedLog(logDirectory: string, message: string): Promise<void> {
  await mkdir(logDirectory, { recursive: true, mode: 0o700 });
  const safe = boundedUtf8Tail(redactManagedLog(message), AUTOSTART_LOG_MAX_BYTES);
  const current = path.join(logDirectory, 'agent.log');
  let size = 0;
  try { size = (await stat(current)).size; } catch { /* First write. */ }
  if (size + Buffer.byteLength(safe) > AUTOSTART_LOG_MAX_BYTES) {
    await rm(path.join(logDirectory, `agent.${AUTOSTART_LOG_FILES - 1}.log`), { force: true });
    for (let index = AUTOSTART_LOG_FILES - 2; index >= 1; index -= 1) {
      try {
        await rename(path.join(logDirectory, `agent.${index}.log`), path.join(logDirectory, `agent.${index + 1}.log`));
      } catch { /* A rotation slot may not exist yet. */ }
    }
    try { await rename(current, path.join(logDirectory, 'agent.1.log')); } catch { /* No current log yet. */ }
  }
  await appendFile(current, safe, { encoding: 'utf8', mode: 0o600 });
}

/**
 * The absolute path to a Windows system tool.
 *
 * Never the bare name: `spawn` without a shell searches the working directory
 * and then PATH, so whichever `schtasks.exe` appears first there would be the
 * one that registers this machine's auto-start. These are always the ones in
 * System32.
 */
function systemExecutable(name: string): string {
  if (process.platform !== 'win32') return name;
  const root = process.env.SystemRoot ?? process.env.windir ?? 'C:\\Windows';
  return path.join(root, 'System32', name);
}

async function runFile(
  file: string,
  arguments_: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; timeoutMs?: number } = {},
): Promise<{ code: number; stdout: string; stderr: string }> {
  return await new Promise((resolve, reject) => {
    const child = spawn(file, arguments_, {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      ...(options.cwd ? { cwd: options.cwd } : {}),
      ...(options.env ? { env: options.env } : {}),
    });
    let stdout = '';
    let stderr = '';
    const timer = options.timeoutMs
      ? setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* Already gone. */ } }, options.timeoutMs)
      : null;
    const settle = (value: { code: number; stdout: string; stderr: string }) => {
      if (timer) clearTimeout(timer);
      resolve(value);
    };
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => { stdout += chunk.slice(0, 4096); });
    child.stderr.on('data', (chunk: string) => { stderr += chunk.slice(0, 4096); });
    child.once('error', (error) => { if (timer) clearTimeout(timer); reject(error); });
    child.once('exit', (code) => settle({ code: code ?? 1, stdout, stderr }));
  });
}

async function currentWindowsIdentity(): Promise<{ sid: string; name: string }> {
  const result = await runFile(systemExecutable('whoami.exe'), ['/user', '/fo', 'csv', '/nh']);
  if (result.code !== 0) throw new Error('Could not resolve the current Windows identity.');
  const match = result.stdout.match(/^"([^"]+)","(S-\d(?:-\d+)+)"\s*$/mu);
  if (!match) throw new Error('Could not parse the current Windows identity.');
  return { name: match[1]!, sid: match[2]! };
}

function managerForPlatform(platform = process.platform): AutostartManager | null {
  if (platform === 'win32') return 'windows-task-scheduler';
  if (platform === 'linux') return 'systemd-user';
  if (platform === 'darwin') return 'launchagent';
  return null;
}

function unitName(instanceId: string): string {
  return `ysd-zero-cloud-node-agent-${instanceId}.service`;
}

function launchLabel(instanceId: string): string {
  return `com.openysd.ysd-zero-cloud.node-agent.${instanceId}`;
}

async function registerWindows(rendered: ReturnType<typeof renderWindowsTask>): Promise<void> {
  const directory = await import('node:fs/promises').then(({ mkdtemp }) => mkdtemp(path.join(os.tmpdir(), 'ysd-task-')));
  const taskFile = path.join(directory, 'task.xml');
  try {
    await writeFile(taskFile, `\uFEFF${rendered.xml}`, { encoding: 'utf16le', flag: 'wx', mode: 0o600 });
    const result = await runFile(systemExecutable('schtasks.exe'), ['/Create', '/TN', rendered.id, '/XML', taskFile, '/F']);
    if (result.code !== 0) throw new Error(`Task Scheduler registration failed (${result.code}).`);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function windowsTaskXml(id: string): Promise<string | null> {
  const result = await runFile(systemExecutable('schtasks.exe'), ['/Query', '/TN', id, '/XML']);
  return result.code === 0 ? result.stdout : null;
}

function unxml(value: string): string {
  return value
    .replaceAll('&quot;', '"').replaceAll('&apos;', "'")
    .replaceAll('&gt;', '>').replaceAll('&lt;', '<').replaceAll('&amp;', '&');
}

function xmlValue(document: string, name: string): string {
  return unxml(document.match(new RegExp(`<${name}>([\\s\\S]*?)<\\/${name}>`, 'u'))?.[1]?.trim() ?? '');
}

export function fingerprintWindowsTaskXml(document: string, input: ManagerInput): string | null {
  const expectedArguments = [input.launcherPath, '--install', input.installPath].map(windowsArgument).join(' ');
  const userIds = [...document.matchAll(/<UserId>([\s\S]*?)<\/UserId>/gu)]
    .map((match) => unxml(match[1]?.trim() ?? ''));
  const runLevel = xmlValue(document, 'RunLevel');
  const networkOnly = xmlValue(document, 'RunOnlyIfNetworkAvailable');
  if (
    !document.includes('<LogonTrigger>') ||
    userIds.length < 2 ||
    !userIds.includes(input.userId) ||
    userIds.some((value) => value !== input.userId && value.toLowerCase() !== input.userName.toLowerCase()) ||
    xmlValue(document, 'Delay') !== 'PT15S' ||
    xmlValue(document, 'LogonType') !== 'InteractiveToken' ||
    (runLevel !== '' && runLevel !== 'LeastPrivilege') ||
    xmlValue(document, 'MultipleInstancesPolicy') !== 'IgnoreNew' ||
    (networkOnly !== '' && networkOnly !== 'false') ||
    xmlValue(document, 'Command') !== input.nodeExecutable ||
    xmlValue(document, 'Arguments') !== expectedArguments ||
    xmlValue(document, 'WorkingDirectory') !== input.workingDirectory ||
    xmlValue(document, 'Priority') !== '4' ||
    xmlValue(document, 'Interval') !== 'PT1M' ||
    xmlValue(document, 'Count') !== String(AUTOSTART_CRASH_LIMIT)
  ) return null;
  return sha256Bytes(JSON.stringify(registrationShape(input, 'windows-task-scheduler')));
}

async function registerSystemd(input: ManagerInput, unit: string): Promise<string> {
  const directory = path.join(process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), '.config'), 'systemd', 'user');
  const file = path.join(directory, unitName(input.instanceId));
  await atomicWrite(file, unit);
  for (const args of [['--user', 'daemon-reload'], ['--user', 'enable', '--now', unitName(input.instanceId)]]) {
    const result = await runFile('systemctl', args);
    if (result.code !== 0) throw new Error(`systemd user registration failed (${result.code}).`);
  }
  return file;
}

async function registerLaunchAgent(input: ManagerInput, plist: string): Promise<string> {
  const directory = path.join(os.homedir(), 'Library', 'LaunchAgents');
  const file = path.join(directory, `${launchLabel(input.instanceId)}.plist`);
  await atomicWrite(file, plist);
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error('Could not resolve the current macOS user.');
  await runFile('launchctl', ['bootout', `gui/${uid}/${launchLabel(input.instanceId)}`]);
  const result = await runFile('launchctl', ['bootstrap', `gui/${uid}`, file]);
  if (result.code !== 0) throw new Error(`LaunchAgent registration failed (${result.code}).`);
  return file;
}

async function verifyRegularFile(file: string, label: string): Promise<void> {
  const details = await lstat(file);
  if (!details.isFile() || details.isSymbolicLink()) throw new Error(`${label} must be a regular file.`);
}

async function validateWindowsAcl(directory: string): Promise<void> {
  if (process.platform !== 'win32') return;
  const result = await runFile(systemExecutable('icacls.exe'), [directory]);
  if (result.code !== 0) throw new Error('Could not validate the managed directory ACL.');
  for (const line of result.stdout.split(/\r?\n/u)) {
    if (/\\(?:Everyone|Users|Authenticated Users):.*\((?:F|M|W)\)/iu.test(line)) {
      throw new Error('The managed directory is writable by an untrusted broad principal.');
    }
  }
}

export async function copyManagedRelease(
  layout: ManagedLayout,
  source: string,
  version: string = CURRENT_AGENT_VERSION,
): Promise<{ hash: string; releasePath: string }> {
  await verifyRegularFile(source, 'Agent source');
  if (!isStrictVersion(version)) throw new Error('candidate_incompatible');
  const hash = await hashFile(source);
  const directory = path.join(layout.releaseRoot, version);
  const releasePath = path.join(directory, `ysd-node-agent-${version}.mjs`);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  try {
    await verifyRegularFile(releasePath, 'Managed Agent release');
    if (await hashFile(releasePath) !== hash) throw new Error('An immutable managed release has an unexpected hash.');
  } catch (error) {
    if (!(error instanceof Error) || !('code' in error) || (error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    const temporary = path.join(directory, `.agent.${process.pid}.${Date.now()}.tmp`);
    await copyFile(source, temporary, 1);
    if (process.platform !== 'win32') await chmod(temporary, 0o600);
    if (await hashFile(temporary) !== hash) {
      await rm(temporary, { force: true });
      throw new Error('Managed Agent destination hash mismatch.');
    }
    await rename(temporary, releasePath);
  }
  return { hash, releasePath };
}

async function cleanupReleases(layout: ManagedLayout, keep: Set<string>): Promise<void> {
  let names: string[] = [];
  try { names = await readdir(layout.releaseRoot); } catch { return; }
  for (const name of names) {
    if (!keep.has(name) && /^\d+\.\d+\.\d+$/u.test(name)) {
      await rm(path.join(layout.releaseRoot, name), { recursive: true, force: true });
    }
  }
}

/**
 * Keeps current and previous, plus the candidate while one is in flight.
 *
 * Three is the ceiling, and it is temporary. Nothing prunes the release a
 * rollback would need in order to make room for a candidate -- that trade is
 * exactly backwards, and staging refuses on low disk instead.
 */
export async function retainManagedReleases(
  layout: ManagedLayout,
  currentVersion: string,
  previousVersion: string | null,
  candidateVersion: string | null = null,
): Promise<void> {
  const keep = [currentVersion, previousVersion, candidateVersion].filter(Boolean) as string[];
  if (keep.length > MANAGED_RELEASE_TRANSACTION_LIMIT) throw new Error('retention_overflow');
  await cleanupReleases(layout, new Set(keep));
}

async function previousInstall(file: string): Promise<ManagedInstall | null> {
  try {
    return validateManagedInstall(JSON.parse(await readFile(file, 'utf8')));
  } catch { return null; }
}

async function managerInput(layout: ManagedLayout, origin: string): Promise<ManagerInput> {
  const identity = process.platform === 'win32'
    ? await currentWindowsIdentity()
    : { sid: 'S-1-0-0', name: 'user' };
  return {
    instanceId: layout.instanceId,
    nodeExecutable: assertSafePath(path.resolve(process.execPath), 'Node executable'),
    launcherPath: layout.launcherPath,
    installPath: layout.installPath,
    workingDirectory: layout.managedRoot,
    origin,
    userId: identity.sid,
    userName: identity.name,
  };
}

function initialStatus(manager: AutostartManager, fingerprint: string): ManagedStatus {
  return {
    version: 1,
    enabled: true,
    manager,
    scope: 'user-session',
    state: 'enabled',
    agentVersion: CURRENT_AGENT_VERSION,
    lastStartAt: null,
    lastExitAt: null,
    restartCount: 0,
    registrationFingerprint: fingerprint,
    crashFailures: [],
  };
}

/**
 * Serialises every local maintenance action for one node.
 *
 * Enable, disable, repair, uninstall, upgrade and restore all rewrite the same
 * install file and all talk to the same OS registration, so exactly one of them
 * runs at a time. Other nodes on the same machine are unaffected: the lock is
 * per managed identity, like everything else here.
 */
async function withMaintenanceLock<T>(credentialPath: string, run: () => Promise<T>): Promise<T> {
  if (process.env.YSD_NODE_AGENT_KEY?.trim()) throw new Error('credential_key_unavailable');
  const credentials = await loadCredentials(credentialPath);
  const maintenance = await acquireMaintenanceOwnership(credentialPath, credentials.nodeId);
  try {
    return await run();
  } finally {
    await maintenance.release();
  }
}

export async function enableAutostart(input: {
  credentialPath: string;
  origin: string;
  sourcePath?: string;
}): Promise<ManagedStatus> {
  return await withMaintenanceLock(input.credentialPath, () => installManagedAutostart(input));
}

async function installManagedAutostart(input: {
  credentialPath: string;
  origin: string;
  sourcePath?: string;
}): Promise<ManagedStatus> {
  const credentials = await loadCredentials(input.credentialPath);
  if (credentials.origin !== input.origin) throw new Error('The credential belongs to a different origin.');
  const manager = managerForPlatform();
  if (!manager) throw new Error('manager_missing');
  const layout = await managedLayout(input.credentialPath, credentials.nodeId);
  await mkdir(layout.logDirectory, { recursive: true, mode: 0o700 });
  await validateWindowsAcl(layout.managedRoot);
  const source = path.resolve(input.sourcePath ?? process.argv[1] ?? '');
  const release = await copyManagedRelease(layout, source);
  const old = await previousInstall(layout.installPath);
  const launcher = buildManagedLauncherSource();
  await atomicWrite(layout.launcherPath, launcher);
  const launcherHash = sha256Bytes(launcher);
  const managerConfig = await managerInput(layout, input.origin);
  let registrationId = '';
  let registrationFingerprint = '';
  if (manager === 'windows-task-scheduler') {
    const rendered = renderWindowsTask(managerConfig);
    registrationId = rendered.id;
    registrationFingerprint = rendered.fingerprint;
  } else if (manager === 'systemd-user') {
    registrationId = unitName(layout.instanceId);
    registrationFingerprint = sha256Bytes(renderSystemdUserUnit(managerConfig));
  } else {
    registrationId = launchLabel(layout.instanceId);
    registrationFingerprint = sha256Bytes(renderLaunchAgent(managerConfig));
  }
  // Enable and repair are explicit operator actions that re-establish the
  // install from the bundle in front of them, so any transaction in flight is
  // abandoned rather than resumed. The quarantine survives: a candidate that
  // failed is still a candidate that failed.
  const priorUpgrade = old ? upgradeOf(old) : idleUpgrade();
  const previousRelease: ManagedRelease | null =
    old && old.agentVersion !== CURRENT_AGENT_VERSION && isStrictVersion(old.agentVersion)
      ? currentRelease(old)
      : old?.previousRelease ?? null;
  const install: ManagedInstall = {
    version: 1,
    installSchema: MANAGED_INSTALL_SCHEMA,
    instanceId: layout.instanceId,
    agentVersion: CURRENT_AGENT_VERSION,
    protocolVersion: NODE_PROTOCOL_VERSION,
    previousVersion: previousRelease?.version ?? null,
    previousRelease,
    upgrade: {
      ...idleUpgrade(Date.now()),
      generation: priorUpgrade.generation + 1,
      quarantine: priorUpgrade.quarantine,
    },
    nodeExecutable: managerConfig.nodeExecutable,
    releasePath: release.releasePath,
    releaseHash: release.hash,
    launcherPath: layout.launcherPath,
    launcherHash,
    credentialPath: layout.credentialPath,
    agentHome: agentHomeDirectory(),
    origin: input.origin,
    manager,
    scope: 'user-session',
    registrationId,
    registrationFingerprint,
    workingDirectory: layout.managedRoot,
    updatedAt: Date.now(),
  };
  await atomicWrite(layout.installPath, `${JSON.stringify(install)}\n`);
  await writeManagedStatus(layout.statusPath, initialStatus(manager, registrationFingerprint));
  if (manager === 'windows-task-scheduler') {
    const rendered = renderWindowsTask(managerConfig);
    // `/Create /F` replaces a registration, and replacing one that is running
    // ends its process tree. Repair before a trial, never during one.
    await assertNoLiveTrial(layout.installPath, 'register');
    await registerWindows(rendered);
    const live = await windowsTaskXml(rendered.id);
    if (!live || fingerprintWindowsTaskXml(live, managerConfig) !== rendered.fingerprint) {
      throw new Error('registration_invalid');
    }
    const started = await runFile(systemExecutable('schtasks.exe'), ['/Run', '/TN', rendered.id]);
    if (started.code !== 0) throw new Error('Task Scheduler could not start the managed Agent.');
    // Not "the command returned 0" -- that only says the request was accepted.
    // A start is finished when the launcher is visible to everyone else, so
    // the next operation cannot mistake it for an idle node.
    if (!(await waitForLauncherVisible(layout.credentialPath, credentials.nodeId))) {
      throw new Error('launcher_did_not_start');
    }
  } else if (manager === 'systemd-user') {
    await registerSystemd(managerConfig, renderSystemdUserUnit(managerConfig));
  } else {
    await registerLaunchAgent(managerConfig, renderLaunchAgent(managerConfig));
  }
  await retainManagedReleases(layout, CURRENT_AGENT_VERSION, install.previousVersion);
  return initialStatus(manager, registrationFingerprint);
}

async function loadContext(credentialPath: string): Promise<{
  layout: ManagedLayout;
  install: ManagedInstall | null;
  status: ManagedStatus | null;
}> {
  const credentials = await loadCredentials(credentialPath);
  const layout = await managedLayout(credentialPath, credentials.nodeId);
  const install = await previousInstall(layout.installPath);
  let status: ManagedStatus | null = null;
  try { status = validateManagedStatus(JSON.parse(await readFile(layout.statusPath, 'utf8'))); } catch { /* Missing status. */ }
  return { layout, install, status };
}

export async function statusAutostart(credentialPath: string): Promise<ManagedStatusReport> {
  if (process.env.YSD_NODE_AGENT_KEY?.trim()) {
    return { ...initialStatus(managerForPlatform() ?? 'systemd-user', ''.padStart(64, '0')), enabled: false, state: 'credential_key_unavailable', registrationFingerprint: null, upgrade: null };
  }
  const { layout, install, status } = await loadContext(credentialPath);
  const manager = managerForPlatform();
  if (!manager) return { ...initialStatus('systemd-user', ''.padStart(64, '0')), enabled: false, state: 'manager_missing', registrationFingerprint: null, upgrade: null };
  const observed = status ?? { ...initialStatus(manager, ''.padStart(64, '0')), enabled: false, state: 'disabled' as const, registrationFingerprint: null };
  // The transaction comes from the install file and nowhere else. `status.json`
  // no longer carries it, which is what lets Agent 0.6.0 still read that file.
  const base: ManagedStatusReport = {
    ...observed,
    upgrade: install ? projectUpgradeStatus(upgradeOf(install)) : null,
  };
  if (!install) return { ...base, enabled: false, state: 'disabled', registrationFingerprint: null };
  try { await verifyRegularFile(install.nodeExecutable, 'Node executable'); } catch { return { ...base, state: 'node_runtime_missing' }; }
  try {
    await verifyRegularFile(install.releasePath, 'Managed Agent release');
    if (await hashFile(install.releasePath) !== install.releaseHash || await hashFile(layout.launcherPath) !== install.launcherHash) {
      return { ...base, state: 'registration_invalid' };
    }
  } catch { return { ...base, state: 'agent_missing' }; }
  const input: ManagerInput = {
    instanceId: layout.instanceId,
    nodeExecutable: install.nodeExecutable,
    launcherPath: install.launcherPath,
    installPath: layout.installPath,
    workingDirectory: install.workingDirectory,
    origin: install.origin,
    ...(process.platform === 'win32'
      ? await currentWindowsIdentity().then((identity) => ({ userId: identity.sid, userName: identity.name }))
      : { userId: 'S-1-0-0', userName: 'user' }),
  };
  if (manager === 'windows-task-scheduler') {
    const live = await windowsTaskXml(install.registrationId);
    if (!live) return { ...base, enabled: false, state: 'disabled' };
    if (fingerprintWindowsTaskXml(live, input) !== install.registrationFingerprint) return { ...base, state: 'registration_invalid' };
  } else if (manager === 'systemd-user') {
    const query = await runFile('systemctl', ['--user', 'is-enabled', install.registrationId]);
    if (query.code !== 0) return { ...base, enabled: false, state: 'disabled' };
  } else {
    const uid = process.getuid?.();
    if (uid === undefined) return { ...base, state: 'manager_missing' };
    const query = await runFile('launchctl', ['print', `gui/${uid}/${install.registrationId}`]);
    if (query.code !== 0) return { ...base, enabled: false, state: 'disabled' };
  }
  return { ...base, enabled: true, state: base.state === 'restart_limited' || base.state === 'authorization_rejected' ? base.state : 'enabled', registrationFingerprint: install.registrationFingerprint };
}

export async function disableAutostart(credentialPath: string, stop = false): Promise<ManagedStatus> {
  return await withMaintenanceLock(credentialPath, () => removeManagedAutostart(credentialPath, stop));
}

async function removeManagedAutostart(credentialPath: string, stop: boolean): Promise<ManagedStatus> {
  const { layout, install, status } = await loadContext(credentialPath);
  const manager = install?.manager ?? managerForPlatform() ?? 'systemd-user';
  if (install?.manager === 'windows-task-scheduler') {
    if (stop) {
      await runFile(systemExecutable('schtasks.exe'), ['/Change', '/TN', install.registrationId, '/Disable']);
      await runFile(systemExecutable('schtasks.exe'), ['/End', '/TN', install.registrationId]);
    }
    await runFile(systemExecutable('schtasks.exe'), ['/Delete', '/TN', install.registrationId, '/F']);
  } else if (install?.manager === 'systemd-user') {
    await runFile('systemctl', ['--user', 'disable', '--now', install.registrationId]);
  } else if (install?.manager === 'launchagent') {
    const uid = process.getuid?.();
    if (uid !== undefined) await runFile('launchctl', ['bootout', `gui/${uid}/${install.registrationId}`]);
    const plist = path.join(os.homedir(), 'Library', 'LaunchAgents', `${install.registrationId}.plist`);
    await rm(plist, { force: true });
  }
  // Turning auto-start off must not leave a transaction that a later launcher
  // would resume behind the user's back. The candidate bytes stay on disk so
  // an upgrade can be retried deliberately; only the intent is cleared.
  if (install && upgradeOf(install).state !== 'idle') {
    await atomicWrite(layout.installPath, `${JSON.stringify(resetTransaction(install, Date.now()))}\n`);
  }
  const next: ManagedStatus = {
    ...(status ?? initialStatus(manager, install?.registrationFingerprint ?? ''.padStart(64, '0'))),
    enabled: false,
    state: 'disabled',
    registrationFingerprint: install?.registrationFingerprint ?? null,
  };
  await writeManagedStatus(layout.statusPath, next);
  return next;
}

export async function repairAutostart(input: { credentialPath: string; origin: string; sourcePath?: string }): Promise<ManagedStatus> {
  return await enableAutostart(input);
}

export async function uninstallAutostart(credentialPath: string): Promise<void> {
  const { layout } = await loadContext(credentialPath);
  await disableAutostart(credentialPath, true);
  await rm(layout.managedRoot, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Phase 20: the local upgrade transaction.
// ---------------------------------------------------------------------------

/**
 * Merges what the metadata knows with the one thing only the launcher can see.
 *
 * The install file is the authority for which release is current and what the
 * transaction is doing. It cannot know that a live candidate has been up for
 * two minutes without reaching the control plane, because that is a runtime
 * observation -- so exactly that one observation is taken from `status.json`,
 * and only while it is describing the same transaction.
 */
export type UpgradeOutcome =
  | 'promoted'
  | 'rolled_back'
  | 'blocked'
  | 'trial'
  | 'restored'
  | 'refused';

export type UpgradeResult = {
  outcome: UpgradeOutcome;
  reason: UpgradeReason | null;
  transactionId: string | null;
  currentVersion: string;
  previousVersion: string | null;
  candidateVersion: string | null;
  handoff: string | null;
};

/** Free bytes on the volume holding the managed directory, when knowable. */
async function freeBytes(directory: string): Promise<number | null> {
  try {
    const stats = await statfs(directory);
    return Number(stats.bsize) * Number(stats.bavail);
  } catch {
    return null;
  }
}

/**
 * Asks a candidate bundle what it is.
 *
 * `--version` prints two fixed lines and exits; it opens no credential, no
 * socket and no managed directory. Reading the version from the bundle rather
 * than assuming the running process's own constant is what makes the answer
 * true when a bundle is named explicitly, and it doubles as proof that the
 * candidate can at least start on this machine's Node runtime.
 */
async function probeCandidate(
  nodeExecutable: string,
  source: string,
  workingDirectory: string,
): Promise<{ version: string; protocolVersion: number } | null> {
  const environment: NodeJS.ProcessEnv = { ...process.env };
  delete environment.YSD_NODE_AGENT_KEY;
  delete environment.YSD_NODE_PAIRING_CODE;
  let result: { code: number; stdout: string };
  try {
    result = await runFile(nodeExecutable, [source, '--version'], {
      cwd: workingDirectory,
      env: environment,
      timeoutMs: 30_000,
    });
  } catch {
    return null;
  }
  if (result.code !== 0) return null;
  const version = /^YSD Node Agent (\S+)\s*$/mu.exec(result.stdout)?.[1] ?? '';
  const protocolVersion = Number(/^Protocol (\d+)\s*$/mu.exec(result.stdout)?.[1] ?? Number.NaN);
  if (!isStrictVersion(version) || !Number.isSafeInteger(protocolVersion)) return null;
  return { version, protocolVersion };
}

/**
 * Stops the managed Agent through the manager that already owns it.
 *
 * This is the manager's own stop verb -- `schtasks /End`, `systemctl --user
 * stop`, `launchctl kill` -- not a re-registration. The task, unit and plist
 * are byte-identical before and after.
 */
/**
 * Refuses a manager operation that would terminate a live trial.
 *
 * On Windows both `schtasks /Create /F` and `schtasks /End` end the task's
 * process tree with TerminateProcess -- no signal, no Node shutdown, no exit
 * hook. Run against a published trial they kill the supervising launcher and
 * the candidate together, leaving a spent attempt, a candidate that may
 * already have proved itself, and nobody left to promote it. That is not a
 * hypothetical: it is the failure this guard exists to make unrepeatable.
 *
 * Ordering alone fixed the one path that had it wrong. This makes the rule
 * enforceable rather than remembered, because the next person to add a
 * registration repair will not know it. A deliberate abort passes
 * `abortingTransaction` -- it owns the transaction and means to end it.
 */
async function assertNoLiveTrial(
  installPath: string,
  operation: string,
  abortingTransaction = false,
): Promise<void> {
  if (abortingTransaction) return;
  const install = await previousInstall(installPath);
  if (!install) return;
  if (upgradeOf(install).state === 'trial') {
    throw new Error(`${operation}_would_terminate_live_trial`);
  }
}

async function stopManagedRegistration(
  install: ManagedInstall,
  abortingTransaction = false,
): Promise<void> {
  await assertNoLiveTrial(
    path.join(path.dirname(install.launcherPath), 'install.json'),
    'end_registration',
    abortingTransaction,
  );
  if (install.manager === 'windows-task-scheduler') {
    await runFile(systemExecutable('schtasks.exe'), ['/End', '/TN', install.registrationId]);
  } else if (install.manager === 'systemd-user') {
    await runFile('systemctl', ['--user', 'stop', install.registrationId]);
  } else {
    const uid = process.getuid?.();
    if (uid !== undefined) {
      await runFile('launchctl', ['kill', 'SIGTERM', `gui/${uid}/${install.registrationId}`]);
    }
  }
}


/**
 * How long a managed launcher is given to become visible after a start.
 *
 * This is not a settling delay -- nothing waits for it in the good case. It is
 * the bound on a start that never arrives, so a broken registration fails
 * loudly instead of hanging.
 */
const LAUNCHER_VISIBLE_LIMIT_MS = 30_000;

/**
 * Waits for a started launcher to actually take orchestration ownership.
 *
 * Between `CreateProcess` and the moment a launcher binds its ownership pipe
 * it is invisible: it holds no lock, and Task Scheduler may already report the
 * task `Ready`. A caller that returns from `/Run` during that window leaves
 * behind a start it cannot see, and the next operation reasonably concludes
 * nothing is running. That is precisely how a launcher came to claim a freshly
 * published trial and then be killed by an `/End` that was already in flight.
 *
 * So a start is complete when the launcher is visible, never before.
 */
export async function waitForLauncherVisible(
  credentialPath: string,
  nodeId: string,
  limitMs = LAUNCHER_VISIBLE_LIMIT_MS,
): Promise<boolean> {
  const deadline = Date.now() + limitMs;
  while (Date.now() < deadline) {
    // Either answer means the manager did its job. A launcher that starts,
    // finds an Agent already holding this node and stands down is behaving
    // correctly -- and it can do all of that between two polls, so requiring
    // the launcher itself to be caught in the act would call a healthy node a
    // failed start. What matters is that the identity is owned.
    if (await launcherOwnershipHeld(credentialPath, nodeId)) return true;
    if (await agentOwnershipHeld(credentialPath, nodeId)) return true;
    await delay(200);
  }
  return false;
}

/**
 * Waits for a managed generation to be gone, from ownership alone.
 *
 * `schtasks /End` returns before the termination lands, and Task Scheduler was
 * observed reporting `Ready` while the launcher it started was still alive and
 * about to become the supervisor. So its status is supplementary evidence at
 * best; the authority is the ownership pipe.
 *
 * When the caller saw ownership held before stopping, a `held -> free`
 * transition has to be observed. Reading `free` at the first poll proves
 * nothing in that case -- it is the same reading a launcher still inside its
 * startup window produces.
 */
/** The managed generation Task Scheduler is running for this node, right now. */
export async function managedNativeGeneration(
  install: Pick<ManagedInstall, 'manager' | 'registrationId' | 'launcherPath'>,
): Promise<ManagedNativeGeneration> {
  if (install.manager !== 'windows-task-scheduler') return { instances: [], launchers: [] };
  return await observeManagedNativeGeneration({
    registrationId: install.registrationId,
    launcherPath: install.launcherPath,
    powershell: systemExecutable('WindowsPowerShell\\v1.0\\powershell.exe'),
    run: (file, arguments_, environment) => runFile(file, arguments_, {
      timeoutMs: 30_000,
      env: { ...process.env, ...environment },
    }),
  });
}

export async function waitForManagedGenerationGone(
  credentialPath: string,
  nodeId: string,
  wasHeld: boolean,
  limitMs = 90_000,
  native?: {
    before: ManagedNativeGeneration;
    install: Pick<ManagedInstall, 'manager' | 'registrationId' | 'launcherPath'>;
  },
): Promise<boolean> {
  const deadline = Date.now() + limitMs;
  let observedHeld = !wasHeld;
  while (Date.now() < deadline) {
    const held = await launcherOwnershipHeld(credentialPath, nodeId);
    if (held) observedHeld = true;
    if (!held && observedHeld && !(await agentOwnershipHeld(credentialPath, nodeId))) {
      // The ownership locks are satisfied. On Windows that is not yet enough:
      // a launcher the manager has already created, but which has not reached
      // the line that binds its pipe, satisfies them too. Whatever the manager
      // was running before the stop has to be gone as well.
      if (!native) return true;
      const now = await managedNativeGeneration(native.install);
      if (generationCleared(native.before, now)) return true;
    }
    await delay(200);
  }
  return false;
}

/** Starts the existing registration again. Same command line, same task. */
async function startManagedRegistration(
  install: ManagedInstall,
  confirm?: { credentialPath: string; nodeId: string },
): Promise<void> {
  if (install.manager === 'windows-task-scheduler') {
    const started = await runFile(systemExecutable('schtasks.exe'), ['/Run', '/TN', install.registrationId]);
    if (started.code !== 0) throw new Error('registration_invalid');
  } else if (install.manager === 'systemd-user') {
    const started = await runFile('systemctl', ['--user', 'start', install.registrationId]);
    if (started.code !== 0) throw new Error('registration_invalid');
  } else {
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error('manager_missing');
    const started = await runFile('launchctl', ['kickstart', `gui/${uid}/${install.registrationId}`]);
    if (started.code !== 0) throw new Error('registration_invalid');
  }
  // Returning here while the launcher is still invisible is what let a later
  // operation believe nothing was running.
  if (confirm && !(await waitForLauncherVisible(confirm.credentialPath, confirm.nodeId))) {
    throw new Error('launcher_did_not_start');
  }
}

/** Waits until no Agent holds the node identity and the manager is idle. */
async function waitForManagedIdle(
  credentialPath: string,
  nodeId: string,
  install: ManagedInstall,
  limitMs = 90_000,
): Promise<boolean> {
  const deadline = Date.now() + limitMs;
  while (Date.now() < deadline) {
    const held = await agentOwnershipHeld(credentialPath, nodeId);
    // A launcher between children holds no Agent lock and its task instance
    // already reads Ready, yet it is very much still supervising and about to
    // start something. Waiting only on those two is what allowed a second
    // launcher to be started underneath the first, with both then spending
    // the same trial budget. A launcher that predates this lock holds nothing,
    // so the v1 -> v2 bridge answers exactly as it did before.
    const supervised = await launcherOwnershipHeld(credentialPath, nodeId);
    let managerIdle = true;
    if (install.manager === 'windows-task-scheduler') {
      const query = await runFile(systemExecutable('schtasks.exe'), ['/Query', '/TN', install.registrationId, '/FO', 'LIST']);
      managerIdle = query.code === 0 && /^Status:\s+Ready\s*$/mu.test(query.stdout);
    }
    if (!held && !supervised && managerIdle) return true;
    await delay(500);
  }
  return false;
}

/** Waits for the launcher to finish the trial it was handed. */
async function awaitTransactionSettled(
  layout: ManagedLayout,
  transactionId: string,
  limitMs: number,
): Promise<ManagedInstall | null> {
  const deadline = Date.now() + limitMs;
  let latest: ManagedInstall | null = null;
  while (Date.now() < deadline) {
    latest = await previousInstall(layout.installPath);
    if (latest) {
      const plan = upgradeOf(latest);
      const settled = plan.state === 'idle' || plan.state === 'blocked';
      if (settled && (plan.transactionId === transactionId || plan.state === 'blocked')) return latest;
    }
    await delay(1_000);
  }
  return latest;
}

function describeTransaction(
  install: ManagedInstall,
  transactionId: string,
  candidateVersion: string,
  handoff: string | null,
): UpgradeResult {
  const plan = upgradeOf(install);
  const quarantined = plan.quarantine.some((entry) => entry.version === candidateVersion);
  const outcome: UpgradeOutcome =
    plan.state === 'blocked' ? 'blocked'
      : install.agentVersion === candidateVersion ? 'promoted'
        : quarantined ? 'rolled_back'
          : 'trial';
  return {
    outcome,
    reason: plan.reason,
    transactionId,
    currentVersion: install.agentVersion,
    previousVersion: install.previousRelease?.version ?? install.previousVersion,
    candidateVersion,
    handoff,
  };
}

/**
 * Answers the local upgrade handoff verb.
 *
 * The running Agent agrees to stand down only for the transaction its own
 * managed install currently names. That is not an authentication boundary --
 * see `instance-lock.ts` -- but it does mean a stale or invented transaction
 * id cannot talk a healthy Agent into stopping.
 */
export async function acceptManagedUpgradeRequest(
  credentialPath: string,
  nodeId: string,
  transactionId: string,
): Promise<boolean> {
  try {
    const layout = await managedLayout(credentialPath, nodeId);
    const install = await previousInstall(layout.installPath);
    if (!install) return false;
    const plan = upgradeOf(install);
    return (
      plan.transactionId === transactionId
      && (plan.state === 'trial' || plan.state === 'staged')
      && plan.candidate !== null
    );
  } catch {
    return false;
  }
}

/**
 * Records that this Agent's first signed heartbeat was accepted.
 *
 * Written only after the control plane answers a signed heartbeat with a
 * success, because that is the milestone that actually proves the whole chain:
 * the process started, the credential decrypted, the ownership lock was taken,
 * the request signed, and the control plane accepted it. Anything earlier --
 * the process existing, a banner on stdout, surviving five seconds -- proves
 * only that the file parses.
 *
 * The marker carries no token, no node key, no path and no process id. It is a
 * local, non-secret statement that one transaction reached one milestone.
 */
export async function writeReadinessMarker(input: {
  credentialPath: string;
  nodeId: string;
  transactionId: string;
  generation: number;
  agentVersion: string;
}): Promise<void> {
  const layout = await managedLayout(input.credentialPath, input.nodeId);
  const marker = buildReadinessMarker(
    input.transactionId,
    input.generation,
    input.agentVersion,
    Date.now(),
  );
  await atomicWrite(layout.readinessPath, `${JSON.stringify(marker)}\n`);
}

/**
 * Stages a verified candidate and hands the machine to it for a trial.
 *
 * The order is chosen so that every interruption lands somewhere safe:
 *
 *   1. verify the candidate completely, while the current Agent keeps running;
 *   2. copy it into an immutable release directory and re-verify the bytes;
 *   3. write `staged` -- an interruption here is invisible, because a staged
 *      transaction still starts the known-good Agent;
 *   4. install launcher v2 next to the running v1, which never re-reads it;
 *   5. write `trial` -- the first point at which anything would start the
 *      candidate, and the top-level release is still the known-good one;
 *   6. stop the running Agent, wait for the manager to go idle, start the
 *      same registration again.
 *
 * Nothing here downloads anything and nothing here is reachable from the
 * browser. The candidate is a file already on this machine.
 */
export async function upgradeAutostart(input: {
  credentialPath: string;
  sourcePath?: string;
  retry?: boolean;
  settleMs?: number;
}): Promise<UpgradeResult> {
  const credentials = await loadCredentials(input.credentialPath);
  const layout = await managedLayout(input.credentialPath, credentials.nodeId);
  const existing = await previousInstall(layout.installPath);
  if (!existing) throw new Error('autostart_not_enabled');

  const refuse = (reason: UpgradeReason, candidateVersion: string | null = null): UpgradeResult => ({
    outcome: 'refused',
    reason,
    transactionId: null,
    currentVersion: existing.agentVersion,
    previousVersion: existing.previousRelease?.version ?? existing.previousVersion,
    candidateVersion,
    handoff: null,
  });

  let locked: Awaited<ReturnType<typeof acquireMaintenanceOwnership>>;
  try {
    if (process.env.YSD_NODE_AGENT_KEY?.trim()) throw new Error('credential_key_unavailable');
    locked = await acquireMaintenanceOwnership(input.credentialPath, credentials.nodeId);
  } catch (error) {
    if (error instanceof Error && error.message === 'maintenance_busy') return refuse('maintenance_busy');
    throw error;
  }

  try {
    const install = (await previousInstall(layout.installPath)) ?? existing;
    await validateWindowsAcl(layout.managedRoot);
    const source = path.resolve(input.sourcePath ?? process.argv[1] ?? '');
    await verifyRegularFile(source, 'Agent source');

    // The runtime the launcher will use has to still be there. Finding this
    // out after the running Agent has been stopped turns a refusal into an
    // outage, so it is checked before anything is disturbed.
    try {
      await verifyRegularFile(install.nodeExecutable, 'Node executable');
    } catch {
      return refuse('node_runtime_missing');
    }

    const probe = await probeCandidate(install.nodeExecutable, source, layout.managedRoot);
    if (!probe || probe.protocolVersion !== NODE_PROTOCOL_VERSION) return refuse('candidate_incompatible');

    const sourceHash = await hashFile(source);
    const plan = upgradeOf(install);
    const decision = evaluateUpgradeCandidate({
      current: install.agentVersion,
      candidate: probe.version,
      candidateHash: sourceHash,
      quarantine: plan.quarantine,
      retry: input.retry ?? false,
    });
    if (!decision.allowed) return refuse(decision.reason ?? 'candidate_incompatible', probe.version);

    const size = (await stat(source)).size;
    const free = await freeBytes(layout.managedRoot);
    if (free !== null && free < size * 3 + UPGRADE_MINIMUM_FREE_BYTES) return refuse('low_disk', probe.version);

    const copied = await copyManagedRelease(layout, source, probe.version);
    if (copied.hash !== sourceHash) return refuse('candidate_hash_mismatch', probe.version);
    const candidate: ManagedRelease = {
      version: probe.version,
      releasePath: copied.releasePath,
      releaseHash: copied.hash,
    };
    const transactionId = randomUUID().replaceAll('-', '');

    // The migration point: an install first written by Agent 0.6.0 is carried
    // forward, not rebuilt, so this is where it picks up the revision marker.
    let next = stageTransaction(
      { ...install, installSchema: MANAGED_INSTALL_SCHEMA },
      candidate,
      transactionId,
      Date.now(),
    );
    await atomicWrite(layout.installPath, `${JSON.stringify(next)}\n`);
    await retainManagedReleases(
      layout,
      next.agentVersion,
      next.previousRelease?.version ?? next.previousVersion,
      candidate.version,
    );
    await appendManagedLog(
      layout.logDirectory,
      `Upgrade staged version=${candidate.version}\nCandidate verified\n`,
    );

    // Launcher v2 goes down while v1 is still supervising the running Agent.
    // v1 read its own copy at startup and never looks again, so this cannot
    // disturb it; the next start by the existing registration picks up v2.
    const launcher = buildManagedLauncherSource();
    const launcherHash = sha256Bytes(launcher);
    if (launcherHash !== next.launcherHash) {
      await atomicWrite(layout.launcherPath, launcher);
      next = { ...next, launcherHash, updatedAt: Date.now() };
    }

    // The transaction stays `staged` across everything below. A launcher only
    // acts on `trial`, so while the plan says staged there is nothing for a
    // doomed generation to pick up.
    //
    // This ordering is the fix for a real failure, and it is worth stating why
    // it is not merely tidier. `schtasks /End` -- and `/Create /F`, which the
    // registration writer uses -- terminate the task's process tree with
    // TerminateProcess. No signal, no Node shutdown, no exit hook. Publishing
    // the trial before that call meant an older launcher could read it, start
    // the candidate, and then have both itself and that candidate killed
    // outright, leaving a trial with a spent attempt, no supervisor, and
    // nothing left alive to promote the candidate that had already proved
    // itself. Every destructive manager operation happens here, first.
    // Whether a launcher was supervising *before* the stop decides what
    // counts as proof afterwards. If one was, only a `held -> free` transition
    // shows the stop landed; `free` on its own is also what a launcher still
    // inside its startup window looks like.
    const supervisedBeforeStop = await launcherOwnershipHeld(
      input.credentialPath,
      credentials.nodeId,
    );
    // Captured before the stop, and only to answer one question afterwards:
    // has what the manager was running actually gone? The frozen 0.6.0 repair
    // that precedes this upgrade starts a launcher through Task Scheduler and
    // returns immediately, so `supervisedBeforeStop` can be false while a
    // launcher is very much on its way up. This is the evidence that exists
    // during that window. Local and ephemeral -- never written to the install
    // file, never sent anywhere.
    const nativeBeforeStop = await managedNativeGeneration(next);
    const handoff = await requestManagedUpgradeShutdown(
      input.credentialPath,
      credentials.nodeId,
      transactionId,
    );
    if (handoff !== 'shutting_down') {
      // Either no Agent is running, or the running one predates the verb --
      // a managed 0.6.0 answers exactly as it always did. The manager's own
      // stop is what guarantees the old launcher exits too.
      await stopManagedRegistration(next);
    }
    if (!(await waitForManagedGenerationGone(
      input.credentialPath, credentials.nodeId, supervisedBeforeStop, 90_000,
      { before: nativeBeforeStop, install: next },
    )) || !(await waitForManagedIdle(input.credentialPath, credentials.nodeId, next))) {
      // Something still owns the node. Starting the candidate now would mean
      // two Agents, so the transaction stays staged and the Agent that is
      // already running keeps the machine.
      await atomicWrite(
        layout.installPath,
        `${JSON.stringify(stageTransaction(next, candidate, transactionId, Date.now()))}\n`,
      );
      return { ...refuse('ownership_conflict', candidate.version), transactionId, handoff };
    }
    await appendManagedLog(layout.logDirectory, 'Current Agent stopped for upgrade\n');

    // Idle here is proven by the two ownership locks, not by the manager's own
    // status: the investigation showed Task Scheduler reporting `Ready` while
    // a launcher it had started was still alive and supervising.
    //
    // Only now does the trial become visible, and from this line until the
    // transaction resolves nothing may re-register or end the native task.
    // The single `startManagedRegistration` below is the only manager call
    // left, and it starts a task rather than replacing or ending one.
    next = beginTrial(next, candidate, transactionId, Date.now());
    await atomicWrite(layout.installPath, `${JSON.stringify(next)}\n`);

    await startManagedRegistration(next, {
      credentialPath: input.credentialPath,
      nodeId: credentials.nodeId,
    });
    const settled = await awaitTransactionSettled(layout, transactionId, input.settleMs ?? 180_000);
    return describeTransaction(settled ?? next, transactionId, candidate.version, handoff);
  } finally {
    await locked.release();
  }
}

/**
 * Restores the exact Agent recorded as previous.
 *
 * Only that one release, verified by hash before anything stops. There is no
 * version argument and no search of the filesystem, because a downgrade path
 * that accepts an arbitrary local bundle is a downgrade attack with extra
 * steps. The launcher stays at v2 -- regenerating it from the older Agent
 * would remove the transaction support that makes this recoverable at all.
 */
export async function restorePreviousAutostart(input: {
  credentialPath: string;
}): Promise<UpgradeResult> {
  const credentials = await loadCredentials(input.credentialPath);
  const layout = await managedLayout(input.credentialPath, credentials.nodeId);
  const existing = await previousInstall(layout.installPath);
  if (!existing) throw new Error('autostart_not_enabled');

  const refuse = (reason: UpgradeReason): UpgradeResult => ({
    outcome: 'refused',
    reason,
    transactionId: null,
    currentVersion: existing.agentVersion,
    previousVersion: existing.previousRelease?.version ?? existing.previousVersion,
    candidateVersion: null,
    handoff: null,
  });

  let locked: Awaited<ReturnType<typeof acquireMaintenanceOwnership>>;
  try {
    if (process.env.YSD_NODE_AGENT_KEY?.trim()) throw new Error('credential_key_unavailable');
    locked = await acquireMaintenanceOwnership(input.credentialPath, credentials.nodeId);
  } catch (error) {
    if (error instanceof Error && error.message === 'maintenance_busy') return refuse('maintenance_busy');
    throw error;
  }

  try {
    const install = (await previousInstall(layout.installPath)) ?? existing;
    const previous = install.previousRelease ?? null;
    let observedHash: string | null = null;
    if (previous) {
      try {
        await verifyRegularFile(previous.releasePath, 'Previous Agent release');
        observedHash = await hashFile(previous.releasePath);
      } catch {
        observedHash = null;
      }
    }
    const decision = evaluateRestoreTarget({
      current: install.agentVersion,
      previous,
      observedHash,
    });
    if (!decision.allowed || !previous) return refuse(decision.reason ?? 'previous_missing');
    try {
      await verifyRegularFile(install.nodeExecutable, 'Node executable');
    } catch {
      return refuse('node_runtime_missing');
    }

    // Fail before the switch, not after. Execution is about to be handed to an
    // Agent that validates `status.json` by exact key set, so a file left by
    // 0.7.0 -- which carried an extra key -- is rewritten in the shape that
    // Agent understands first. If that write fails, nothing is switched and the
    // current Agent keeps the machine.
    try {
      const existingStatus = validateManagedStatus(JSON.parse(await readFile(layout.statusPath, 'utf8')));
      if (existingStatus) await writeManagedStatus(layout.statusPath, existingStatus);
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') return refuse('transaction_interrupted');
    }

    const now = Date.now();
    const restored: ManagedInstall = {
      ...resetTransaction(install, now),
      installSchema: MANAGED_INSTALL_SCHEMA,
      agentVersion: previous.version,
      releasePath: previous.releasePath,
      releaseHash: previous.releaseHash,
      previousVersion: install.agentVersion,
      previousRelease: currentRelease(install),
      updatedAt: now,
    };
    await atomicWrite(layout.installPath, `${JSON.stringify(restored)}\n`);

    const handoff = await requestManagedUpgradeShutdown(
      input.credentialPath,
      credentials.nodeId,
      upgradeOf(restored).transactionId,
    );
    if (handoff !== 'shutting_down') await stopManagedRegistration(restored);
    if (!(await waitForManagedIdle(input.credentialPath, credentials.nodeId, restored))) {
      await atomicWrite(layout.installPath, `${JSON.stringify(install)}\n`);
      return { ...refuse('ownership_conflict'), handoff };
    }
    await startManagedRegistration(restored);
    await retainManagedReleases(layout, restored.agentVersion, restored.previousRelease?.version ?? null);
    await appendManagedLog(
      layout.logDirectory,
      `Previous Agent restored version=${restored.agentVersion}\n`,
    );
    return {
      outcome: 'restored',
      reason: null,
      transactionId: null,
      currentVersion: restored.agentVersion,
      previousVersion: restored.previousRelease?.version ?? null,
      candidateVersion: null,
      handoff,
    };
  } finally {
    await locked.release();
  }
}

/**
 * How long a native-manager check is reused for the heartbeat observation.
 *
 * The heartbeat runs every 25 seconds and this costs a process spawn, so the
 * answer is cached. A minute of staleness on a badge is not worth a
 * `schtasks` invocation every heartbeat, and a person who wants the current
 * answer runs `autostart status`, which never caches.
 */
export const AUTOSTART_CAPABILITY_TTL_MS = 60_000;

let capabilityCache: { key: string; at: number; value: AutostartCapability } | null = null;

/** Test seam: drops the cached native-manager observation. */
export function resetAutostartCapabilityCache(): void {
  capabilityCache = null;
}

/**
 * What the heartbeat reports about auto-start.
 *
 * This used to read `status.json` alone, which meant it could keep saying
 * "enabled" after the scheduled task had been deleted -- the file says what the
 * launcher last wrote, not what the operating system is actually configured to
 * do. It now asks the same question `autostart status` asks, so a missing or
 * altered registration is reported as such instead of being papered over.
 */
export async function readAutostartCapability(
  credentialPath: string,
  nodeId?: string,
): Promise<AutostartCapability> {
  const manager = managerForPlatform();
  if (!manager) return { version: 1, supported: false, enabled: false, manager: null, scope: 'none', state: 'unsupported' };
  const disabled: AutostartCapability = { version: 1, supported: true, enabled: false, manager, scope: 'user-session', state: 'disabled' };
  try {
    const resolvedNodeId = nodeId ?? (await loadCredentials(credentialPath)).nodeId;
    const key = `${canonicalCredentialPath(credentialPath)}\0${resolvedNodeId}`;
    const now = Date.now();
    if (capabilityCache && capabilityCache.key === key && now - capabilityCache.at < AUTOSTART_CAPABILITY_TTL_MS) {
      return capabilityCache.value;
    }
    const report = await statusAutostart(credentialPath);
    const publicState: AutostartCapability['state'] =
      report.state === 'starting' || report.state === 'stopped' || report.state === 'already_running'
        ? report.enabled ? 'enabled' : 'disabled'
        : report.state;
    const value: AutostartCapability = {
      version: 1,
      supported: true,
      enabled: report.enabled,
      manager,
      scope: 'user-session',
      state: publicState,
    };
    capabilityCache = { key, at: now, value };
    return value;
  } catch {
    return disabled;
  }
}
