#!/usr/bin/env node

import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import {
  CURRENT_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  NODE_TIMING,
  randomToken,
  stableJson,
  verifyTextSignature,
  type SignedJobClaim,
} from '../lib/nodes.ts';
import { defaultCredentialPath } from './agent-key.ts';
import { loadCredentials, saveCredentials } from './credentials.ts';
import {
  collectGameServerSnapshots,
  shutdownManagedGameServers,
} from './game-runtime.ts';
import {
  collectAppRuntimeSnapshots,
  shutdownManagedApps,
} from './app-runtime.ts';
import {
  AGENT_EXIT,
  acceptManagedUpgradeRequest,
  disableAutostart,
  enableAutostart,
  readAutostartCapability,
  repairAutostart,
  restorePreviousAutostart,
  statusAutostart,
  uninstallAutostart,
  upgradeAutostart,
  writeReadinessMarker,
} from './autostart.ts';
import { acquireAgentOwnership } from './instance-lock.ts';
import { ControlPlaneError, jsonRequest, signedPost } from './signed-request.ts';
import {
  createArtifactBackup,
  restoreArtifactBackup,
  verifyArtifactBackup,
  BackupError,
} from './artifact-backup.ts';
import { backupReasonMessage } from '../lib/artifact-backup.ts';
import {
  collectCapabilities,
  collectMetrics,
  executeSignedJob,
} from './runtime.ts';
import { verifyArtifact } from './app-runtime.ts';

type Command = 'pair' | 'run' | 'autostart' | 'artifact';
type AutostartAction =
  | 'enable'
  | 'status'
  | 'disable'
  | 'repair'
  | 'uninstall'
  | 'upgrade'
  | 'restore-previous';

/**
 * The backup verbs are spelled `artifact backup ...` in full. Phase 17 already
 * has a release rollback and Phase 20 an Agent `restore-previous`; a bare
 * `restore` here would read like either of them.
 */
type BackupAction = 'create' | 'verify' | 'restore';

const BACKUP_ACTIONS: BackupAction[] = ['create', 'verify', 'restore'];

const AUTOSTART_ACTIONS: AutostartAction[] = [
  'enable', 'status', 'disable', 'repair', 'uninstall', 'upgrade', 'restore-previous',
];

type Arguments = {
  command: Command;
  origin: string;
  configPath: string;
  autostartAction: AutostartAction | null;
  backupAction: BackupAction | null;
  bundlePath: string | null;
  artifactId: string | null;
  outputDirectory: string | null;
  stop: boolean;
  retry: boolean;
  sourcePath: string | null;
  /**
   * Set by the managed launcher when this process is a candidate on trial.
   * Both values are local, non-secret and bounded: a transaction id and its
   * generation. They exist so the readiness proof this Agent writes can only
   * satisfy the exact upgrade that asked for it.
   */
  managedTrial: string | null;
  managedGeneration: number;
};

function argument(name: string): string | null {
  const index = process.argv.indexOf(name);
  return index >= 0 ? (process.argv[index + 1] ?? null) : null;
}

function safeOrigin(value: string): string {
  const url = new URL(value);
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
    throw new Error(
      'The control plane must use HTTPS (HTTP is allowed only on localhost).',
    );
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(
      'The control-plane URL cannot include credentials, a query, or a fragment.',
    );
  }
  return url.origin;
}

const USAGE = [
  'YSD Node Agent',
  '',
  'Usage:',
  '  node ysd-node-agent-<version>.mjs pair --url <https://control-plane>',
  '  node ysd-node-agent-<version>.mjs run  --url <https://control-plane>',
  '  node ysd-node-agent-<version>.mjs autostart enable  --url <https://control-plane>',
  '  node ysd-node-agent-<version>.mjs autostart status  [--config <path>]',
  '  node ysd-node-agent-<version>.mjs autostart disable [--config <path>] [--stop]',
  '  node ysd-node-agent-<version>.mjs autostart repair  --url <https://control-plane>',
  '  node ysd-node-agent-<version>.mjs autostart uninstall [--config <path>]',
  '  node ysd-node-agent-<version>.mjs autostart upgrade [--config <path>] [--retry]',
  '  node ysd-node-agent-<version>.mjs autostart restore-previous [--config <path>]',
  '  node ysd-node-agent-<version>.mjs artifact backup create --artifact <id> --output <dir>',
  '  node ysd-node-agent-<version>.mjs artifact backup verify <bundle>',
  '  node ysd-node-agent-<version>.mjs artifact backup restore <bundle> [--config <path>]',
  '',
  'Options:',
  '  --url <origin>     Control plane origin. HTTPS, or HTTP on localhost.',
  '  --config <path>    Credential file. Defaults to a per-user location.',
  '  --artifact <id>    The artifact to back up.',
  '  --output <dir>     An existing absolute directory to write the backup into.',
  '  --retry            Re-attempt a candidate that already failed a trial.',
  '  --source <path>    Local Agent bundle to upgrade to. Defaults to this one.',
  '  --version          Print the agent and protocol version.',
  '  --help             Print this message.',
  '',
  'The upgrade runs on this machine, from a bundle already on this machine.',
  'Nothing is downloaded and nothing is started remotely. If the new Agent',
  'fails during its first managed start, the previous verified Agent is',
  'restored automatically.',
].join(String.fromCharCode(10));

function parseArguments(): Arguments {
  const candidate = process.argv[2] ?? 'run';
  if (candidate !== 'pair' && candidate !== 'run' && candidate !== 'autostart' && candidate !== 'artifact') {
    throw new Error(USAGE);
  }
  let backupAction: BackupAction | null = null;
  if (candidate === 'artifact') {
    if (process.argv[3] !== 'backup') throw new Error(USAGE);
    if (!BACKUP_ACTIONS.includes(process.argv[4] as BackupAction)) throw new Error(USAGE);
    backupAction = process.argv[4] as BackupAction;
  }
  const action = candidate === 'autostart' ? process.argv[3] : null;
  if (candidate === 'autostart' && !AUTOSTART_ACTIONS.includes(action as AutostartAction)) {
    throw new Error(USAGE);
  }
  const rawOrigin = argument('--url') ?? process.env.YSD_NODE_URL ?? '';
  // Upgrade and restore act on an install that already records its origin.
  // Asking for it again would be one more chance to point a working node at
  // the wrong control plane.
  const needsOrigin = candidate === 'pair' || candidate === 'run'
    || (candidate === 'autostart' && (action === 'enable' || action === 'repair'));
  const origin = rawOrigin ? safeOrigin(rawOrigin) : '';
  if (needsOrigin && !origin) throw new Error(USAGE);
  const trial = argument('--managed-trial');
  const generation = Number(argument('--managed-generation') ?? Number.NaN);
  return {
    command: candidate,
    origin,
    configPath:
      argument('--config') ??
      process.env.YSD_NODE_CONFIG ??
      defaultCredentialPath(),
    autostartAction: action as AutostartAction | null,
    backupAction,
    // The bundle is positional: `artifact backup verify <bundle>`.
    bundlePath: candidate === 'artifact' && backupAction !== 'create' ? (process.argv[5] ?? null) : null,
    artifactId: argument('--artifact'),
    outputDirectory: argument('--output'),
    stop: process.argv.includes('--stop'),
    retry: process.argv.includes('--retry'),
    sourcePath: argument('--source'),
    managedTrial:
      trial && /^[a-f0-9]{32}$/.test(trial) && Number.isSafeInteger(generation) && generation >= 0
        ? trial
        : null,
    managedGeneration: Number.isSafeInteger(generation) && generation >= 0 ? generation : 0,
  };
}

class AgentTerminalError extends Error {
  constructor(readonly reasonCode: string, readonly exitCode: number) {
    super(reasonCode);
  }
}

const PAIRING_CODE_PATTERN = /^ysdp_[A-Za-z0-9_-]{32}$/;

/**
 * Reads the one-time pairing code.
 *
 * An environment variable stays supported because automation and the
 * acceptance harness need it, but it is no longer the documented path. Typing
 * the code at a prompt keeps it out of shell history, out of the process list
 * where any other local user can read it, and out of the terminal scrollback
 * someone pastes into a screenshot. The code is never echoed back.
 */
async function readPairingCode(): Promise<string> {
  const supplied = process.env.YSD_NODE_PAIRING_CODE?.trim() ?? '';
  if (supplied) {
    if (!PAIRING_CODE_PATTERN.test(supplied)) {
      throw new Error('YSD_NODE_PAIRING_CODE is not a valid one-time pairing code.');
    }
    return supplied;
  }

  if (!process.stdin.isTTY) {
    throw new Error(
      'Run this in an interactive terminal so the pairing code can be typed, '
      + 'or set YSD_NODE_PAIRING_CODE for automation.',
    );
  }

  process.stdout.write('Paste the one-time pairing code from the Nodes page: ');
  const code = await new Promise<string>((resolve) => {
    let buffer = '';
    process.stdin.setEncoding('utf8');
    const onData = (chunk: string) => {
      buffer += chunk;
      const newline = buffer.indexOf('\n');
      if (newline < 0) return;
      process.stdin.off('data', onData);
      process.stdin.pause();
      resolve(buffer.slice(0, newline).trim());
    };
    process.stdin.on('data', onData);
    process.stdin.resume();
  });
  process.stdout.write('\n');

  if (!PAIRING_CODE_PATTERN.test(code)) {
    // The value is not echoed back: a mistyped code is still a secret.
    throw new Error('That is not a valid one-time pairing code.');
  }
  return code;
}

async function pair(arguments_: Arguments): Promise<void> {
  const code = await readPairingCode();
  const response = await jsonRequest<{
    nodeId: string;
    workspaceId: string;
    token: string;
  }>(`${arguments_.origin}/api/nodes/agent/pair`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code,
      agentVersion: CURRENT_AGENT_VERSION,
      protocolVersion: NODE_PROTOCOL_VERSION,
      platform: os.platform(),
      architecture: os.arch(),
      capabilities: await collectCapabilities(),
    }),
  });
  await saveCredentials(arguments_.configPath, {
    origin: arguments_.origin,
    nodeId: response.nodeId,
    workspaceId: response.workspaceId,
    token: response.token,
    createdAt: Date.now(),
  });
  console.log(
    `Paired node ${response.nodeId}. The credential is encrypted at ${arguments_.configPath}.`,
  );
  console.log(
    'Run the agent with the same YSD_NODE_AGENT_KEY and the run command.',
  );
}

async function heartbeat(
  origin: string,
  token: string,
  workspaceId: string,
  gameRootDirectory: string,
  appRootDirectory: string,
  runtimeGeneration: string,
  configPath: string,
  nodeId: string,
  signal?: AbortSignal,
  runningJobs = 0,
): Promise<void> {
  const autostart = await readAutostartCapability(configPath, nodeId);
  await signedPost({
    origin,
    token,
    pathname: '/api/nodes/agent/heartbeat',
    body: {
      agentVersion: CURRENT_AGENT_VERSION,
      capabilities: await collectCapabilities(fetch, autostart),
      metrics: collectMetrics(runningJobs),
      gameServers: await collectGameServerSnapshots(
        gameRootDirectory,
        workspaceId,
      ),
      appDeployments: collectAppRuntimeSnapshots(),
      runtimeGeneration,
    },
    signal,
  });
}

async function monitorClaim(input: {
  origin: string;
  token: string;
  claim: SignedJobClaim;
  execution: AbortController;
  signal: AbortSignal;
  workspaceId: string;
  gameRootDirectory: string;
  appRootDirectory: string;
  runtimeGeneration: string;
  configPath: string;
  nodeId: string;
}): Promise<void> {
  let lastHeartbeat = Date.now();
  while (!input.signal.aborted && !input.execution.signal.aborted) {
    try {
      const status = await signedPost<{
        state: string;
        cancelRequested: boolean;
      }>({
        origin: input.origin,
        token: input.token,
        pathname: `/api/nodes/agent/jobs/${input.claim.jobId}/status`,
        body: { leaseId: input.claim.leaseId },
        signal: input.signal,
      });
      if (status.cancelRequested || status.state !== 'leased') {
        input.execution.abort('control-plane-cancelled');
        return;
      }
      if (Date.now() - lastHeartbeat >= NODE_TIMING.heartbeatMs) {
        await heartbeat(
          input.origin,
          input.token,
          input.workspaceId,
          input.gameRootDirectory,
          input.appRootDirectory,
          input.runtimeGeneration,
          input.configPath,
          input.nodeId,
          input.signal,
          1,
        );
        lastHeartbeat = Date.now();
      }
      await delay(1_500, undefined, { signal: input.signal });
    } catch (error) {
      if (input.signal.aborted) return;
      // Losing authenticated lease visibility is a fail-closed condition.
      input.execution.abort(error);
      return;
    }
  }
}

async function poll(
  origin: string,
  token: string,
  workspaceId: string,
  gameRootDirectory: string,
  appRootDirectory: string,
  runtimeGeneration: string,
  configPath: string,
  nodeId: string,
  signal: AbortSignal,
): Promise<boolean> {
  const response = await signedPost<{
    job: { claim: SignedJobClaim; signature: string } | null;
  }>({
    origin,
    token,
    pathname: '/api/nodes/agent/claim',
    body: {},
    signal,
  });
  if (!response.job) return false;
  const capabilities = await collectCapabilities(
    fetch,
    await readAutostartCapability(configPath, nodeId),
  );
  const execution = new AbortController();
  const monitor = new AbortController();
  const monitorPromise = monitorClaim({
    origin,
    token,
    claim: response.job.claim,
    execution,
    signal: monitor.signal,
    workspaceId,
    gameRootDirectory,
    appRootDirectory,
    runtimeGeneration,
    configPath,
    nodeId,
  });
  let completed: Awaited<ReturnType<typeof executeSignedJob>>;
  try {
    completed = await executeSignedJob({
      token,
      origin,
      claim: response.job.claim,
      signature: response.job.signature,
      capabilities,
      signal: execution.signal,
      gameRootDirectory,
      appRootDirectory,
    });
  } finally {
    monitor.abort('job-complete');
    await monitorPromise;
  }
  await signedPost({
    origin,
    token,
    pathname: `/api/nodes/agent/jobs/${response.job.claim.jobId}/complete`,
    body: {
      leaseId: response.job.claim.leaseId,
      claim: response.job.claim,
      claimSignature: response.job.signature,
      ...completed,
    },
    signal,
  });
  console.log(
    `Completed ${response.job.claim.type} (${response.job.claim.jobId}).`,
  );
  return true;
}

async function run(arguments_: Arguments): Promise<void> {
  let credentials: Awaited<ReturnType<typeof loadCredentials>>;
  try {
    credentials = await loadCredentials(arguments_.configPath);
  } catch {
    throw new AgentTerminalError('credential_invalid', AGENT_EXIT.credentialInvalid);
  }
  if (credentials.origin !== arguments_.origin) {
    throw new AgentTerminalError('credential_origin_mismatch', AGENT_EXIT.credentialInvalid);
  }
  const shutdown = new AbortController();
  let controlledShutdown = false;
  let upgradeHandoff = false;
  const onSignal = () => {
    controlledShutdown = true;
    shutdown.abort('controlled-shutdown');
  };
  let ownership: Awaited<ReturnType<typeof acquireAgentOwnership>>;
  try {
    ownership = await acquireAgentOwnership(
      arguments_.configPath,
      credentials.nodeId,
      // The only thing another local process may ask this Agent to do: stand
      // down for the upgrade transaction its own managed install already
      // names. A stale or invented transaction id is refused, and the answer
      // is always a clean shutdown -- never "run this".
      async (transactionId) => {
        const expected = await acceptManagedUpgradeRequest(
          arguments_.configPath,
          credentials.nodeId,
          transactionId,
        );
        if (!expected) return false;
        upgradeHandoff = true;
        onSignal();
        return true;
      },
    );
  } catch (error) {
    if (error instanceof Error && error.message === 'already_running') {
      throw new AgentTerminalError('already_running', AGENT_EXIT.alreadyRunning);
    }
    throw new AgentTerminalError('ownership_lock_invalid', AGENT_EXIT.credentialInvalid);
  }
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  console.log(
    `YSD Node Agent ${CURRENT_AGENT_VERSION} started in outbound-only mode.`,
  );
  const gameRootDirectory = path.resolve(
    path.dirname(arguments_.configPath),
    '.ysd-game-servers',
  );
  const appRootDirectory = path.resolve(
    path.dirname(arguments_.configPath),
    '.ysd-app-runtime',
  );
  console.log(
    'Game Servers stay private on this machine unless you change local networking yourself.',
  );
  let lastHeartbeat = 0;
  let backoff = 2_000;
  let readinessWritten = false;
  const runtimeGeneration = randomToken(18);
  try {
    while (!shutdown.signal.aborted) {
      try {
      const now = Date.now();
      if (now - lastHeartbeat >= NODE_TIMING.heartbeatMs) {
        await heartbeat(
          credentials.origin,
          credentials.token,
          credentials.workspaceId,
          gameRootDirectory,
          appRootDirectory,
          runtimeGeneration,
          arguments_.configPath,
          credentials.nodeId,
          shutdown.signal,
        );
        lastHeartbeat = Date.now();
        // Readiness, and only here. Reaching this line means the control
        // plane answered a signed heartbeat with a success: the process
        // started, the credential decrypted, ownership was taken, the request
        // was signed, and the server accepted it. A banner on stdout or a few
        // seconds of uptime would have proved none of that.
        if (arguments_.managedTrial && !readinessWritten) {
          readinessWritten = true;
          try {
            await writeReadinessMarker({
              credentialPath: arguments_.configPath,
              nodeId: credentials.nodeId,
              transactionId: arguments_.managedTrial,
              generation: arguments_.managedGeneration,
              agentVersion: CURRENT_AGENT_VERSION,
            });
          } catch {
            // A managed trial that cannot record its own readiness will be
            // rolled back by the launcher. Nothing here should take the
            // running Agent down over it.
            readinessWritten = false;
          }
        }
      }
      const worked = await poll(
        credentials.origin,
        credentials.token,
        credentials.workspaceId,
        gameRootDirectory,
        appRootDirectory,
        runtimeGeneration,
        arguments_.configPath,
        credentials.nodeId,
        shutdown.signal,
      );
      backoff = 2_000;
      if (!worked) await delay(5_000, undefined, { signal: shutdown.signal });
      } catch (error) {
      if (shutdown.signal.aborted) break;
      const message =
        error instanceof Error ? error.message : 'Unknown agent error.';
      console.error(`Control-plane connection failed: ${message}`);
      if (
        error instanceof ControlPlaneError &&
        (error.status === 401 || error.status === 403)
      ) {
        await shutdownManagedGameServers();
        await shutdownManagedApps();
        throw new AgentTerminalError('authorization_rejected', AGENT_EXIT.authorizationRejected);
      }
      await delay(backoff, undefined, { signal: shutdown.signal });
      backoff = Math.min(30_000, backoff * 2);
      }
    }
    if (controlledShutdown) {
      await shutdownManagedGameServers();
      await shutdownManagedApps();
    }
    if (upgradeHandoff) {
      // A code the Phase 19 launcher already treats as terminal, so the old
      // launcher exits with this Agent instead of restarting it. That is what
      // lets the existing OS registration start launcher v2 next.
      process.exitCode = AGENT_EXIT.controlledShutdown;
    }
  } finally {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
    await ownership.release();
  }
}


// ---------------------------------------------------------------------------
// Artifact backup.
// ---------------------------------------------------------------------------

const APP_RUNTIME_DIRECTORY = '.ysd-app-runtime';

/** Where this node keeps deployment artifacts. */
function appRuntimeRoot(configPath: string): string {
  return path.resolve(path.dirname(configPath), APP_RUNTIME_DIRECTORY);
}

/**
 * Finds one artifact under this node's own storage.
 *
 * The layout is workspace/project/deployment/artifacts/<id>, and only the
 * workspace is known up front, so the two middle levels are enumerated. The
 * search is anchored at the node's own root and the id is pattern-checked
 * first, so nothing here can be steered outside it.
 */
async function locateArtifact(
  configPath: string,
  workspaceId: string,
  artifactId: string,
): Promise<{ artifactDirectory: string; deploymentDirectory: string } | null> {
  const { readdir } = await import('node:fs/promises');
  if (!/^art_[a-f0-9]{24}$/.test(artifactId)) return null;
  const root = appRuntimeRoot(configPath);
  const projects = path.join(root, 'workspaces', workspaceId, 'projects');
  const projectEntries = await readdir(projects, { withFileTypes: true }).catch(() => []);
  for (const project of projectEntries) {
    if (!project.isDirectory()) continue;
    const deployments = path.join(projects, project.name, 'deployments');
    const deploymentEntries = await readdir(deployments, { withFileTypes: true }).catch(() => []);
    for (const deployment of deploymentEntries) {
      if (!deployment.isDirectory()) continue;
      const deploymentDirectory = path.join(deployments, deployment.name);
      const artifactDirectory = path.join(deploymentDirectory, 'artifacts', artifactId);
      const found = await import('node:fs/promises').then(({ stat }) =>
        stat(artifactDirectory).then((info) => info.isDirectory()).catch(() => false));
      if (found) return { artifactDirectory, deploymentDirectory };
    }
  }
  return null;
}

/**
 * Reads and verifies the runtime manifest of an artifact this node owns.
 *
 * The signature is an HMAC over this node's own token, so this is the one place
 * that can establish an artifact is genuinely one of ours. Backing up an
 * artifact that fails here would faithfully preserve something already broken.
 */
async function readVerifiedRuntimeManifest(artifactDirectory: string, token: string): Promise<{
  deploymentId: string;
  projectId: string;
  artifactId: string;
  commit: string;
  checksum: string;
  sizeBytes: number;
  contract: Record<string, unknown>;
  createdAt: number;
  verifiedAt: number;
  entrypoint: string;
}> {
  const { readFile } = await import('node:fs/promises');
  const raw: unknown = JSON.parse(
    await readFile(path.join(artifactDirectory, '.ysd-artifact.json'), 'utf8'),
  );
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new BackupError('artifact_unverified');
  }
  const manifest = raw as Record<string, unknown>;
  const { signature, ...unsigned } = manifest;
  if (
    manifest.version !== 1 ||
    typeof signature !== 'string' ||
    !(await verifyTextSignature(token, `ysd-app-artifact-v1\n${stableJson(unsigned)}`, signature))
  ) {
    throw new BackupError('artifact_unverified');
  }
  const contract = manifest.contract as Record<string, unknown>;
  const entrypoint = typeof contract?.entrypoint === 'string' ? contract.entrypoint : '';
  if (!entrypoint) throw new BackupError('artifact_unverified');
  return {
    deploymentId: String(manifest.deploymentId),
    projectId: String(manifest.projectId),
    artifactId: String(manifest.artifactId),
    commit: String(manifest.commit),
    checksum: String(manifest.checksum),
    sizeBytes: Number(manifest.sizeBytes),
    contract,
    createdAt: Number(manifest.createdAt),
    verifiedAt: Number(manifest.verifiedAt),
    entrypoint,
  };
}

async function runBackupCreate(arguments_: Arguments): Promise<Record<string, unknown>> {
  const credentials = await loadCredentials(arguments_.configPath);
  const located = await locateArtifact(arguments_.configPath, credentials.workspaceId, arguments_.artifactId!);
  if (!located) throw new BackupError('artifact_not_found');
  const runtimeManifest = await readVerifiedRuntimeManifest(located.artifactDirectory, credentials.token);
  return await createArtifactBackup({
    artifactDirectory: located.artifactDirectory,
    destinationDirectory: arguments_.outputDirectory!,
    // A backup must land somewhere the Agent does not manage, so losing the
    // Agent home cannot take the backup with it.
    excludedRoots: [path.dirname(path.resolve(arguments_.configPath)), appRuntimeRoot(arguments_.configPath)],
    runtimeManifest,
    workspaceId: credentials.workspaceId,
    entrypoint: runtimeManifest.entrypoint,
  }) as unknown as Record<string, unknown>;
}

async function runBackupRestore(arguments_: Arguments): Promise<Record<string, unknown>> {
  const credentials = await loadCredentials(arguments_.configPath);
  const bundlePath = path.resolve(arguments_.bundlePath!);
  const { manifest } = await verifyArtifactBackup(bundlePath);
  // The bundle says which deployment it belongs to; the control plane says
  // whether that is true, and what this node is supposed to be running. The
  // bundle never authorises itself.
  let authoritative: {
    workspaceId: string; projectId: string; deploymentId: string;
    nodeId: string; currentArtifactId: string; checksum: string; desiredState: string;
  };
  try {
    authoritative = await signedPost({
      origin: credentials.origin,
      token: credentials.token,
      pathname: `/api/nodes/agent/deployments/${manifest.deploymentId}/restore-preflight`,
      body: {},
    });
  } catch {
    throw new BackupError('preflight_unavailable');
  }
  const deploymentDirectory = path.join(
    appRuntimeRoot(arguments_.configPath),
    'workspaces', authoritative.workspaceId,
    'projects', authoritative.projectId,
    'deployments', authoritative.deploymentId,
  );
  const restored = await restoreArtifactBackup({
    bundlePath,
    deploymentDirectory,
    authoritative,
    authenticatedNodeId: credentials.nodeId,
    token: credentials.token,
  });

  // Nothing is claimed to the control plane until the artifact on disk passes
  // the same check the App Runtime runs before it will activate one: the
  // rebuilt manifest verifies under this node's token, and the directory
  // hashes to what the manifest says. A restore that got as far as writing
  // bytes but cannot satisfy that is not a restore.
  const artifactDirectory = path.join(deploymentDirectory, 'artifacts', restored.artifactId);
  try {
    await verifyArtifact(artifactDirectory, credentials.token, restored.artifactId);
  } catch {
    throw new BackupError('artifact_unverified');
  }
  if (restored.outcome === 'restored') {
    try {
      await signedPost({
        origin: credentials.origin,
        token: credentials.token,
        pathname: `/api/nodes/agent/deployments/${authoritative.deploymentId}/restore-complete`,
        body: { artifactId: restored.artifactId, checksum: restored.artifactChecksum },
      });
    } catch {
      throw new BackupError('confirmation_unavailable');
    }
  }
  // Bytes and one availability fact. This command starts nothing: the
  // application comes back, or stays stopped, entirely through the existing
  // Phase 18 reconciliation and the deployment's own desired state.
  return { ...restored, desiredState: authoritative.desiredState };
}

const flags = new Set(process.argv.slice(2));
if (flags.has('--version') || flags.has('-v')) {
  // Deliberately just these two lines. Printing the platform, paths, or
  // runtime details here would leak machine facts into whatever someone
  // pastes into a support thread.
  console.log('YSD Node Agent ' + CURRENT_AGENT_VERSION);
  console.log('Protocol ' + String(NODE_PROTOCOL_VERSION));
  process.exit(0);
}
if (flags.has('--help') || flags.has('-h') || flags.has('help')) {
  console.log(USAGE);
  process.exit(0);
}

try {
  const arguments_ = parseArguments();
  if (arguments_.command === 'pair') {
    await pair(arguments_);
  } else if (arguments_.command === 'run') {
    await run(arguments_);
  } else if (arguments_.autostartAction === 'enable') {
    console.log(JSON.stringify(await enableAutostart({
      credentialPath: arguments_.configPath,
      origin: arguments_.origin,
    })));
  } else if (arguments_.autostartAction === 'status') {
    console.log(JSON.stringify(await statusAutostart(arguments_.configPath)));
  } else if (arguments_.autostartAction === 'disable') {
    console.log(JSON.stringify(await disableAutostart(arguments_.configPath, arguments_.stop)));
  } else if (arguments_.autostartAction === 'repair') {
    console.log(JSON.stringify(await repairAutostart({
      credentialPath: arguments_.configPath,
      origin: arguments_.origin,
    })));
  } else if (arguments_.autostartAction === 'uninstall') {
    await uninstallAutostart(arguments_.configPath);
    console.log(JSON.stringify({ state: 'uninstalled' }));
  } else if (arguments_.autostartAction === 'upgrade') {
    console.log(JSON.stringify(await upgradeAutostart({
      credentialPath: arguments_.configPath,
      retry: arguments_.retry,
      ...(arguments_.sourcePath ? { sourcePath: arguments_.sourcePath } : {}),
    })));
  } else if (arguments_.autostartAction === 'restore-previous') {
    console.log(JSON.stringify(await restorePreviousAutostart({
      credentialPath: arguments_.configPath,
    })));
  } else if (arguments_.backupAction === 'verify') {
    // Deliberately the only command that needs nothing but the file: no
    // credential, no control plane, no network. It proves the bundle is
    // internally consistent, which is not the same as proving who made it.
    if (!arguments_.bundlePath) throw new Error(USAGE);
    const verified = await verifyArtifactBackup(path.resolve(arguments_.bundlePath));
    console.log(JSON.stringify(verified.result));
  } else if (arguments_.backupAction === 'create') {
    if (!arguments_.artifactId || !arguments_.outputDirectory) throw new Error(USAGE);
    console.log(JSON.stringify(await runBackupCreate(arguments_)));
  } else if (arguments_.backupAction === 'restore') {
    if (!arguments_.bundlePath) throw new Error(USAGE);
    console.log(JSON.stringify(await runBackupRestore(arguments_)));
  }
} catch (error) {
  if (error instanceof BackupError) {
    // A fixed reason plus the sentence that explains it. No stack, no path.
    console.error(`${error.reason}: ${backupReasonMessage(error.reason)}`);
    process.exitCode = 1;
  } else if (error instanceof AgentTerminalError) {
    console.error(error.reasonCode);
    process.exitCode = error.exitCode;
  } else {
    const reason = error instanceof Error ? error.message : 'agent_failed';
    console.error(reason.replace(/[\r\n][\s\S]*/u, '').slice(0, 160));
    process.exitCode = AGENT_EXIT.credentialInvalid;
  }
}
