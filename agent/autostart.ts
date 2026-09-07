import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
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
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { loadCredentials } from './credentials.ts';
import { agentHomeDirectory } from './agent-key.ts';
import {
  CURRENT_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  type AutostartCapability,
} from '../lib/nodes.ts';

export const AUTOSTART_CRASH_LIMIT = 3;
export const AUTOSTART_CRASH_WINDOW_MS = 10 * 60_000;
export const AUTOSTART_RESTART_DELAY_MS = 2_000;
export const AUTOSTART_LOG_FILES = 4;
export const AUTOSTART_LOG_MAX_BYTES = 256 * 1024;

export const AGENT_EXIT = {
  clean: 0,
  alreadyRunning: 20,
  authorizationRejected: 21,
  credentialInvalid: 22,
  unsupportedRuntime: 23,
  controlledShutdown: 24,
} as const;

export type AutostartManager =
  | 'windows-task-scheduler'
  | 'systemd-user'
  | 'launchagent';

export type AutostartState =
  | 'enabled'
  | 'disabled'
  | 'manager_missing'
  | 'agent_missing'
  | 'node_runtime_missing'
  | 'registration_invalid'
  | 'upgrade_required'
  | 'credential_key_unavailable'
  | 'restart_limited'
  | 'authorization_rejected'
  | 'already_running'
  | 'stopped'
  | 'starting';

export type ManagedLayout = {
  instanceId: string;
  credentialPath: string;
  agentHome: string;
  managedRoot: string;
  releaseRoot: string;
  launcherPath: string;
  installPath: string;
  statusPath: string;
  logDirectory: string;
};

export type ManagedInstall = {
  version: 1;
  instanceId: string;
  agentVersion: string;
  protocolVersion: number;
  previousVersion: string | null;
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

const MANAGERS = [
  'windows-task-scheduler',
  'systemd-user',
  'launchagent',
] as const;

const STATES = [
  'enabled',
  'disabled',
  'manager_missing',
  'agent_missing',
  'node_runtime_missing',
  'registration_invalid',
  'upgrade_required',
  'credential_key_unavailable',
  'restart_limited',
  'authorization_rejected',
  'already_running',
  'stopped',
  'starting',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sha256Bytes(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

async function hashFile(file: string): Promise<string> {
  return sha256Bytes(await readFile(file));
}

function canonicalCredentialPath(value: string): string {
  const absolute = path.resolve(value);
  return process.platform === 'win32' ? absolute.toLowerCase() : absolute;
}

export async function deriveManagedIdentity(
  credentialPath: string,
  nodeId: string,
): Promise<string> {
  return sha256Bytes(`${canonicalCredentialPath(credentialPath)}\0${nodeId}`).slice(0, 16);
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

export function validateManagedStatus(value: unknown): ManagedStatus | null {
  if (!isRecord(value)) return null;
  const expected = [
    'agentVersion', 'crashFailures', 'enabled', 'lastExitAt', 'lastStartAt',
    'manager', 'registrationFingerprint', 'restartCount', 'scope', 'state', 'version',
  ];
  if (Object.keys(value).sort().join('\0') !== expected.sort().join('\0')) return null;
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
  return value as ManagedStatus;
}

export function validateManagedInstall(value: unknown): ManagedInstall | null {
  if (!isRecord(value)) return null;
  const expected = [
    'agentHome', 'agentVersion', 'credentialPath', 'instanceId', 'launcherHash',
    'launcherPath', 'manager', 'nodeExecutable', 'origin', 'previousVersion',
    'protocolVersion', 'registrationFingerprint', 'registrationId', 'releaseHash',
    'releasePath', 'scope', 'updatedAt', 'version', 'workingDirectory',
  ];
  if (Object.keys(value).sort().join('\0') !== expected.sort().join('\0')) return null;
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

async function runFile(file: string, arguments_: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return await new Promise((resolve, reject) => {
    const child = spawn(file, arguments_, { shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => { stdout += chunk; });
    child.stderr.on('data', (chunk: string) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

async function currentWindowsIdentity(): Promise<{ sid: string; name: string }> {
  const result = await runFile('whoami.exe', ['/user', '/fo', 'csv', '/nh']);
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
    const result = await runFile('schtasks.exe', ['/Create', '/TN', rendered.id, '/XML', taskFile, '/F']);
    if (result.code !== 0) throw new Error(`Task Scheduler registration failed (${result.code}).`);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function windowsTaskXml(id: string): Promise<string | null> {
  const result = await runFile('schtasks.exe', ['/Query', '/TN', id, '/XML']);
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

export function buildManagedLauncherSource(): string {
  // Kept self-contained: the installed launcher must run without this repository.
  return `import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFile, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';
const MAX=${AUTOSTART_LOG_MAX_BYTES}, FILES=${AUTOSTART_LOG_FILES}, LIMIT=${AUTOSTART_CRASH_LIMIT}, WINDOW=${AUTOSTART_CRASH_WINDOW_MS}, RETRY_DELAY=${AUTOSTART_RESTART_DELAY_MS};
const terminal=new Set([${AGENT_EXIT.alreadyRunning},${AGENT_EXIT.authorizationRejected},${AGENT_EXIT.credentialInvalid},${AGENT_EXIT.unsupportedRuntime},${AGENT_EXIT.controlledShutdown}]);
const hash=(value)=>createHash('sha256').update(value).digest('hex');
const redact=(value)=>value.replace(/\\bAuthorization\\s*:\\s*[^\\r\\n]+/giu,'Authorization: [REDACTED]').replace(/\\b(cookie|session)\\s*[=:]\\s*[^\\s;]+/giu,'$1=[REDACTED]').replace(/\\bYSD_NODE_AGENT_KEY\\s*=\\s*[^\\s]+/giu,'YSD_NODE_AGENT_KEY=[REDACTED]').replace(/\\bysdp_[A-Za-z0-9_-]{16,}/gu,'[REDACTED]').replace(/\\bnode_[A-Za-z0-9_.-]{20,}/gu,'[REDACTED]');
const bounded=(value)=>{const bytes=Buffer.from(value);if(bytes.length<=MAX)return value;let start=bytes.length-MAX;while(start<bytes.length&&(bytes[start]&0xc0)===0x80)start++;return bytes.subarray(start).toString('utf8');};
const states=new Set(['enabled','disabled','manager_missing','agent_missing','node_runtime_missing','registration_invalid','upgrade_required','credential_key_unavailable','restart_limited','authorization_rejected','already_running','stopped','starting']);
const managers=new Set(['windows-task-scheduler','systemd-user','launchagent']);
const absolute=(value)=>typeof value==='string'&&path.isAbsolute(value)&&!/[\\u0000\\r\\n]/u.test(value);
const validInstall=(value)=>value&&value.version===1&&/^[a-f0-9]{16}$/u.test(value.instanceId)&&typeof value.agentVersion==='string'&&value.protocolVersion===${NODE_PROTOCOL_VERSION}&&managers.has(value.manager)&&value.scope==='user-session'&&absolute(value.nodeExecutable)&&absolute(value.releasePath)&&absolute(value.launcherPath)&&absolute(value.credentialPath)&&absolute(value.agentHome)&&absolute(value.workingDirectory)&&/^[a-f0-9]{64}$/u.test(value.releaseHash)&&/^[a-f0-9]{64}$/u.test(value.launcherHash)&&/^[a-f0-9]{64}$/u.test(value.registrationFingerprint)&&typeof value.origin==='string';
const validStatus=(value)=>value&&value.version===1&&typeof value.enabled==='boolean'&&managers.has(value.manager)&&value.scope==='user-session'&&states.has(value.state)&&typeof value.agentVersion==='string'&&(value.lastStartAt===null||Number.isSafeInteger(value.lastStartAt))&&(value.lastExitAt===null||Number.isSafeInteger(value.lastExitAt))&&Number.isSafeInteger(value.restartCount)&&value.restartCount>=0&&value.restartCount<=LIMIT&&(value.registrationFingerprint===null||/^[a-f0-9]{64}$/u.test(value.registrationFingerprint))&&Array.isArray(value.crashFailures)&&value.crashFailures.length<=LIMIT&&value.crashFailures.every((entry)=>Number.isSafeInteger(entry)&&entry>=0);
const atomic=async(file,value)=>{const temporary=path.join(path.dirname(file),'.'+path.basename(file)+'.'+process.pid+'.tmp');const handle=await open(temporary,'wx',0o600);try{await handle.writeFile(JSON.stringify(value)+'\\n','utf8');await handle.sync();}finally{await handle.close();}await rename(temporary,file);};
const log=async(directory,value)=>{await mkdir(directory,{recursive:true,mode:0o700});const safe=bounded(redact(value)),current=path.join(directory,'agent.log');let size=0;try{size=(await stat(current)).size;}catch{}if(size+Buffer.byteLength(safe)>MAX){await rm(path.join(directory,'agent.'+(FILES-1)+'.log'),{force:true});for(let index=FILES-2;index>=1;index--)try{await rename(path.join(directory,'agent.'+index+'.log'),path.join(directory,'agent.'+(index+1)+'.log'));}catch{}try{await rename(current,path.join(directory,'agent.1.log'));}catch{}}await appendFile(current,safe,{encoding:'utf8',mode:0o600});};
let logQueue=Promise.resolve();const queueLog=(directory,value)=>{logQueue=logQueue.then(()=>log(directory,value)).catch(()=>{});return logQueue;};
const installPath=process.argv[process.argv.indexOf('--install')+1];
if(!installPath||!path.isAbsolute(installPath)) process.exit(${AGENT_EXIT.credentialInvalid});
const root=path.dirname(installPath), statusPath=path.join(root,'status.json'), logDirectory=path.join(root,'logs');
let install,status;
try{install=JSON.parse(await readFile(installPath,'utf8'));if(!validInstall(install))throw new Error('install_invalid');try{status=JSON.parse(await readFile(statusPath,'utf8'));}catch{}if(!validStatus(status))status={version:1,enabled:true,manager:install.manager,scope:'user-session',state:'starting',agentVersion:install.agentVersion,lastStartAt:null,lastExitAt:null,restartCount:0,registrationFingerprint:install.registrationFingerprint,crashFailures:[]};let nodeInfo;try{nodeInfo=await stat(install.nodeExecutable);}catch{throw new Error('node_runtime_missing');}if(!nodeInfo.isFile())throw new Error('node_runtime_missing');let release;try{release=await readFile(install.releasePath);}catch{throw new Error('agent_missing');}if(hash(release)!==install.releaseHash)throw new Error('hash_mismatch');}catch(error){await log(logDirectory,'launcher validation failed\\n');if(install&&managers.has(install.manager)){const reason=String(error?.message),state=reason==='node_runtime_missing'?'node_runtime_missing':reason==='agent_missing'?'agent_missing':'registration_invalid';await atomic(statusPath,{version:1,enabled:true,manager:install.manager,scope:'user-session',state,agentVersion:typeof install.agentVersion==='string'?install.agentVersion:'unknown',lastStartAt:null,lastExitAt:Date.now(),restartCount:0,registrationFingerprint:/^[a-f0-9]{64}$/u.test(install.registrationFingerprint)?install.registrationFingerprint:null,crashFailures:[]});}process.exit(0);}
const childEnv=Object.fromEntries(Object.entries(process.env).filter(([key])=>!['YSD_NODE_AGENT_KEY','YSD_NODE_PAIRING_CODE'].includes(key)));childEnv.YSD_NODE_AGENT_HOME=install.agentHome;
let controlled=false,child=null;for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{controlled=true;try{child?.kill(signal);}catch{}});
const sleep=(milliseconds)=>new Promise((resolve)=>setTimeout(resolve,milliseconds));
while(!controlled){const now=Date.now(),failures=(Array.isArray(status.crashFailures)?status.crashFailures:[]).filter((time)=>Number.isSafeInteger(time)&&time>=now-WINDOW&&time<=now);if(failures.length>=LIMIT){status={...status,enabled:true,state:'restart_limited',restartCount:failures.length,crashFailures:failures};await atomic(statusPath,status);break;}status={...status,enabled:true,state:'starting',lastStartAt:now,restartCount:failures.length,crashFailures:failures};await atomic(statusPath,status);const outcome=await new Promise((resolve)=>{child=spawn(install.nodeExecutable,[install.releasePath,'run','--url',install.origin,'--config',install.credentialPath],{cwd:install.workingDirectory,shell:false,windowsHide:true,env:childEnv,stdio:['ignore','pipe','pipe']});child.stdout.on('data',(chunk)=>void queueLog(logDirectory,String(chunk)));child.stderr.on('data',(chunk)=>void queueLog(logDirectory,String(chunk)));let finished=false;child.once('error',async()=>{if(finished)return;finished=true;await queueLog(logDirectory,'agent spawn failed\\n');resolve({code:null});});child.once('exit',async(code)=>{if(finished)return;finished=true;await logQueue;resolve({code});});});child=null;const ended=Date.now(),code=outcome.code;await queueLog(logDirectory,'agent exited code='+(Number.isInteger(code)?code:'spawn_error')+'\\n');if(code===${AGENT_EXIT.authorizationRejected}){status={...status,state:'authorization_rejected',lastExitAt:ended};await atomic(statusPath,status);break;}if(code===${AGENT_EXIT.alreadyRunning}){status={...status,state:'already_running',lastExitAt:ended};await atomic(statusPath,status);break;}if(code===0||controlled||terminal.has(code)){status={...status,state:'stopped',lastExitAt:ended};await atomic(statusPath,status);break;}const next=failures.concat(ended).slice(-LIMIT),retry=next.length<LIMIT;status={...status,state:retry?'stopped':'restart_limited',lastExitAt:ended,restartCount:next.length,crashFailures:next};await atomic(statusPath,status);if(!retry)break;await sleep(RETRY_DELAY);}
process.exit(0);
`;
}

async function verifyRegularFile(file: string, label: string): Promise<void> {
  const details = await lstat(file);
  if (!details.isFile() || details.isSymbolicLink()) throw new Error(`${label} must be a regular file.`);
}

async function validateWindowsAcl(directory: string): Promise<void> {
  if (process.platform !== 'win32') return;
  const result = await runFile('icacls.exe', [directory]);
  if (result.code !== 0) throw new Error('Could not validate the managed directory ACL.');
  for (const line of result.stdout.split(/\r?\n/u)) {
    if (/\\(?:Everyone|Users|Authenticated Users):.*\((?:F|M|W)\)/iu.test(line)) {
      throw new Error('The managed directory is writable by an untrusted broad principal.');
    }
  }
}

export async function copyManagedRelease(layout: ManagedLayout, source: string): Promise<{ hash: string; releasePath: string }> {
  await verifyRegularFile(source, 'Agent source');
  const hash = await hashFile(source);
  const directory = path.join(layout.releaseRoot, CURRENT_AGENT_VERSION);
  const releasePath = path.join(directory, `ysd-node-agent-${CURRENT_AGENT_VERSION}.mjs`);
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

export async function retainManagedReleases(
  layout: ManagedLayout,
  currentVersion: string,
  previousVersion: string | null,
): Promise<void> {
  await cleanupReleases(layout, new Set([currentVersion, previousVersion].filter(Boolean) as string[]));
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

export async function enableAutostart(input: {
  credentialPath: string;
  origin: string;
  sourcePath?: string;
}): Promise<ManagedStatus> {
  if (process.env.YSD_NODE_AGENT_KEY?.trim()) throw new Error('credential_key_unavailable');
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
  const install: ManagedInstall = {
    version: 1,
    instanceId: layout.instanceId,
    agentVersion: CURRENT_AGENT_VERSION,
    protocolVersion: NODE_PROTOCOL_VERSION,
    previousVersion: old && old.agentVersion !== CURRENT_AGENT_VERSION ? old.agentVersion : old?.previousVersion ?? null,
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
  await atomicWrite(layout.statusPath, `${JSON.stringify(initialStatus(manager, registrationFingerprint))}\n`);
  if (manager === 'windows-task-scheduler') {
    const rendered = renderWindowsTask(managerConfig);
    await registerWindows(rendered);
    const live = await windowsTaskXml(rendered.id);
    if (!live || fingerprintWindowsTaskXml(live, managerConfig) !== rendered.fingerprint) {
      throw new Error('registration_invalid');
    }
    const started = await runFile('schtasks.exe', ['/Run', '/TN', rendered.id]);
    if (started.code !== 0) throw new Error('Task Scheduler could not start the managed Agent.');
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

export async function statusAutostart(credentialPath: string): Promise<ManagedStatus> {
  if (process.env.YSD_NODE_AGENT_KEY?.trim()) {
    return { ...initialStatus(managerForPlatform() ?? 'systemd-user', ''.padStart(64, '0')), enabled: false, state: 'credential_key_unavailable', registrationFingerprint: null };
  }
  const { layout, install, status } = await loadContext(credentialPath);
  const manager = managerForPlatform();
  if (!manager) return { ...initialStatus('systemd-user', ''.padStart(64, '0')), enabled: false, state: 'manager_missing', registrationFingerprint: null };
  const base = status ?? { ...initialStatus(manager, ''.padStart(64, '0')), enabled: false, state: 'disabled', registrationFingerprint: null };
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
  const { layout, install, status } = await loadContext(credentialPath);
  const manager = install?.manager ?? managerForPlatform() ?? 'systemd-user';
  if (install?.manager === 'windows-task-scheduler') {
    if (stop) {
      await runFile('schtasks.exe', ['/Change', '/TN', install.registrationId, '/Disable']);
      await runFile('schtasks.exe', ['/End', '/TN', install.registrationId]);
    }
    await runFile('schtasks.exe', ['/Delete', '/TN', install.registrationId, '/F']);
  } else if (install?.manager === 'systemd-user') {
    await runFile('systemctl', ['--user', 'disable', '--now', install.registrationId]);
  } else if (install?.manager === 'launchagent') {
    const uid = process.getuid?.();
    if (uid !== undefined) await runFile('launchctl', ['bootout', `gui/${uid}/${install.registrationId}`]);
    const plist = path.join(os.homedir(), 'Library', 'LaunchAgents', `${install.registrationId}.plist`);
    await rm(plist, { force: true });
  }
  const next: ManagedStatus = {
    ...(status ?? initialStatus(manager, install?.registrationFingerprint ?? ''.padStart(64, '0'))),
    enabled: false,
    state: 'disabled',
    registrationFingerprint: install?.registrationFingerprint ?? null,
  };
  await atomicWrite(layout.statusPath, `${JSON.stringify(next)}\n`);
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

export async function readAutostartCapability(
  credentialPath: string,
  nodeId?: string,
): Promise<AutostartCapability> {
  const manager = managerForPlatform();
  if (!manager) return { version: 1, supported: false, enabled: false, manager: null, scope: 'none', state: 'unsupported' };
  try {
    const resolvedNodeId = nodeId ?? (await loadCredentials(credentialPath)).nodeId;
    const layout = await managedLayout(credentialPath, resolvedNodeId);
    let status: ManagedStatus | null = null;
    try { status = validateManagedStatus(JSON.parse(await readFile(layout.statusPath, 'utf8'))); } catch { /* Not enabled yet. */ }
    if (!status) return { version: 1, supported: true, enabled: false, manager, scope: 'user-session', state: 'disabled' };
    const publicState: AutostartCapability['state'] =
      status.state === 'starting' || status.state === 'stopped' || status.state === 'already_running'
        ? status.enabled ? 'enabled' : 'disabled'
        : status.state;
    return { version: 1, supported: true, enabled: status.enabled, manager, scope: 'user-session', state: publicState };
  } catch {
    return { version: 1, supported: true, enabled: false, manager, scope: 'user-session', state: 'disabled' };
  }
}
