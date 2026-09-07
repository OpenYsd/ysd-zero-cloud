import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  disableAutostart,
  enableAutostart,
  managedLayout,
  repairAutostart,
  statusAutostart,
  uninstallAutostart,
} from '../agent/autostart.ts';
import { saveCredentials } from '../agent/credentials.ts';

const execute = promisify(execFile);
const checks: string[] = [];
const failures: string[] = [];

function check(name: string, condition: unknown, detail = ''): void {
  (condition ? checks : failures).push(name);
  console.log(`  [${condition ? 'PASS' : 'FAIL'}] ${name}${detail ? ` — ${detail}` : ''}`);
}

async function taskXml(name: string): Promise<string | null> {
  try {
    return (await execute('schtasks.exe', ['/Query', '/TN', name, '/XML'], { windowsHide: true })).stdout;
  } catch { return null; }
}

async function waitFor(predicate: () => Promise<boolean>, milliseconds = 20_000): Promise<boolean> {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    if (await predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return false;
}

if (process.platform !== 'win32') {
  console.error('This acceptance harness is for the Windows live adapter only.');
  process.exit(2);
}

const artifact = path.resolve('public', 'agent', 'ysd-node-agent-0.6.0.mjs');
const home = await mkdtemp(path.join(os.tmpdir(), 'ysd-phase19-live-'));
const previousHome = process.env.YSD_NODE_AGENT_HOME;
const previousKey = process.env.YSD_NODE_AGENT_KEY;
process.env.YSD_NODE_AGENT_HOME = home;
delete process.env.YSD_NODE_AGENT_KEY;

let mode: 'online' | 'auth-fatal' = 'online';
let heartbeats = 0;
const server = createServer((request, response) => {
  let body = '';
  request.setEncoding('utf8');
  request.on('data', (chunk) => { body += chunk; });
  request.on('end', () => {
    if (request.url === '/api/nodes/agent/heartbeat') heartbeats += 1;
    response.setHeader('Content-Type', 'application/json');
    if (mode === 'auth-fatal') {
      response.statusCode = 401;
      response.end(JSON.stringify({ error: `server-body-must-not-appear node_${'s'.repeat(40)}` }));
      return;
    }
    response.statusCode = 200;
    response.end(request.url === '/api/nodes/agent/claim' ? JSON.stringify({ job: null }) : '{}');
  });
});
await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
const address = server.address();
if (!address || typeof address === 'string') throw new Error('Could not start the local fixture.');
const origin = `http://127.0.0.1:${address.port}`;

const firstConfig = path.join(home, 'node-one.json');
const secondConfig = path.join(home, 'node-two.json');
const fatalConfig = path.join(home, 'node-fatal.json');
const configs = [firstConfig, secondConfig, fatalConfig];
const nodes = ['node_phase19_first_00000001', 'node_phase19_second_0000002', 'node_phase19_fatal_00000003'];
const token = `node_${'t'.repeat(48)}`;
const taskNames: string[] = [];

try {
  for (let index = 0; index < configs.length; index += 1) {
    await saveCredentials(configs[index]!, {
      origin,
      nodeId: nodes[index]!,
      workspaceId: `ws_phase19_${index}`,
      token,
      createdAt: Date.now(),
    });
    const layout = await managedLayout(configs[index]!, nodes[index]!);
    taskNames.push(`\\YSD Zero Cloud Node Agent ${layout.instanceId}`);
  }

  console.log('\n=== current-user Task Scheduler ===');
  const enabled = await enableAutostart({ credentialPath: firstConfig, origin, sourcePath: artifact });
  check('enable reports one user-session Windows task', enabled.enabled && enabled.manager === 'windows-task-scheduler');
  check('headless managed Agent reaches the local control plane', await waitFor(async () => heartbeats > 0));
  const firstXml = await taskXml(taskNames[0]!);
  check('live task exists without Administrator or password', Boolean(firstXml));
  check('task uses logon, interactive token, least privilege, and IgnoreNew',
    Boolean(firstXml?.includes('<LogonTrigger>') && firstXml.includes('<LogonType>InteractiveToken</LogonType>')
      && (firstXml.includes('<RunLevel>LeastPrivilege</RunLevel>') || !firstXml.includes('<RunLevel>'))
      && firstXml.includes('<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>')));
  const managed = await managedLayout(firstConfig, nodes[0]!);
  const installText = await readFile(managed.installPath, 'utf8');
  const install = JSON.parse(installText);
  const managedBytes = await readFile(install.releasePath);
  const sourceBytes = await readFile(artifact);
  check('managed release is the exact built artifact', Buffer.compare(managedBytes, sourceBytes) === 0 && install.releaseHash.length === 64);
  check('registration contains zero credentials or environment secrets',
    Boolean(firstXml && !firstXml.includes(token) && !/YSD_NODE_AGENT_KEY|ysdp_|Authorization:|cookie=|session=/iu.test(firstXml)));
  const status = await statusAutostart(firstConfig);
  check('live fingerprint validates', status.enabled && status.state === 'enabled');

  console.log('\n=== duplicate, idempotency, and drift ===');
  await execute('schtasks.exe', ['/Run', '/TN', taskNames[0]!], { windowsHide: true });
  await execute('schtasks.exe', ['/Run', '/TN', taskNames[0]!], { windowsHide: true });
  await new Promise((resolve) => setTimeout(resolve, 750));
  check('starting the same task twice keeps the registration singular', Boolean(await taskXml(taskNames[0]!)));
  const duplicate = await execute(process.execPath, [artifact, 'run', '--url', origin, '--config', firstConfig], {
    env: { ...process.env, YSD_NODE_AGENT_HOME: home }, windowsHide: true,
  }).then(() => ({ code: 0, stderr: '' }), (error: { code?: number; stderr?: string }) => ({ code: error.code, stderr: error.stderr ?? '' }));
  check('manual duplicate exits with stable already_running code', duplicate.code === 20 && /already_running/u.test(duplicate.stderr));
  await enableAutostart({ credentialPath: firstConfig, origin, sourcePath: artifact });
  check('enable twice still leaves one deterministic registration', Boolean(await taskXml(taskNames[0]!)));
  await repairAutostart({ credentialPath: firstConfig, origin, sourcePath: artifact });
  await repairAutostart({ credentialPath: firstConfig, origin, sourcePath: artifact });
  check('repair twice is idempotent', (await statusAutostart(firstConfig)).state === 'enabled');

  await execute('schtasks.exe', ['/End', '/TN', taskNames[0]!], { windowsHide: true });
  const driftFile = path.join(home, 'drift-task.xml');
  const driftXml = firstXml!.replace(/<Command>[\s\S]*?<\/Command>/u, `<Command>${process.execPath}.missing</Command>`);
  await writeFile(driftFile, `\uFEFF${driftXml}`, { encoding: 'utf16le', mode: 0o600 });
  await execute('schtasks.exe', ['/Create', '/TN', taskNames[0]!, '/XML', driftFile, '/F'], { windowsHide: true });
  check('registration drift is detected', (await statusAutostart(firstConfig)).state === 'registration_invalid');
  await repairAutostart({ credentialPath: firstConfig, origin, sourcePath: artifact });
  check('repair restores the exact fingerprint', (await statusAutostart(firstConfig)).state === 'enabled');

  console.log('\n=== multiple node identities and disable ===');
  await enableAutostart({ credentialPath: secondConfig, origin, sourcePath: artifact });
  check('two configs produce two distinct tasks', taskNames[0] !== taskNames[1] && Boolean(await taskXml(taskNames[0]!)) && Boolean(await taskXml(taskNames[1]!)));
  await disableAutostart(firstConfig, true);
  check('disable --stop removes only its own task', !await taskXml(taskNames[0]!) && Boolean(await taskXml(taskNames[1]!)));
  await disableAutostart(firstConfig, true);
  check('disable twice succeeds', (await statusAutostart(firstConfig)).state === 'disabled');
  await enableAutostart({ credentialPath: firstConfig, origin, sourcePath: artifact });
  check('re-enable restores exactly one task', Boolean(await taskXml(taskNames[0]!)));

  console.log('\n=== terminal authorization failure ===');
  mode = 'auth-fatal';
  await enableAutostart({ credentialPath: fatalConfig, origin, sourcePath: artifact });
  const terminal = await waitFor(async () => (await statusAutostart(fatalConfig)).state === 'authorization_rejected');
  check('auth-fatal Agent records a terminal fixed state', terminal);
  const before = heartbeats;
  await new Promise((resolve) => setTimeout(resolve, 2_000));
  check('auth-fatal launcher does not create a restart storm', heartbeats === before);
  const fatalLayout = await managedLayout(fatalConfig, nodes[2]!);
  const logNames = await import('node:fs/promises').then(({ readdir }) => readdir(fatalLayout.logDirectory));
  const logText = (await Promise.all(logNames.map((name) => readFile(path.join(fatalLayout.logDirectory, name), 'utf8')))).join('\n');
  check('raw server body and credential never reach headless logs', !logText.includes('server-body-must-not-appear') && !logText.includes(token));
} finally {
  for (const config of configs) {
    try { await uninstallAutostart(config); } catch { /* Best-effort cleanup continues below. */ }
  }
  for (const taskName of taskNames) {
    try { await execute('schtasks.exe', ['/Delete', '/TN', taskName, '/F'], { windowsHide: true }); } catch { /* Already absent. */ }
  }
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  if (previousHome === undefined) delete process.env.YSD_NODE_AGENT_HOME;
  else process.env.YSD_NODE_AGENT_HOME = previousHome;
  if (previousKey === undefined) delete process.env.YSD_NODE_AGENT_KEY;
  else process.env.YSD_NODE_AGENT_KEY = previousKey;
}

console.log('\n=== cleanup ===');
for (const taskName of taskNames) check(`task removed: ${taskName.slice(-16)}`, !await taskXml(taskName));
check('temporary managed Agent home removed', !await import('node:fs').then(({ existsSync }) => existsSync(home)));
console.log(`\nPASSED ${checks.length}  FAILED ${failures.length}`);
process.exitCode = failures.length === 0 ? 0 : 1;
