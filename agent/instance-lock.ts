/**
 * Local ownership for one managed node identity.
 *
 * Two locks, deliberately separate:
 *
 *   * the AGENT lock, held for as long as an Agent is running, so a second
 *     Agent for the same node exits instead of fighting over the same runtime
 *     directories and the same private ports;
 *   * the MAINTENANCE lock, held only for the duration of an enable, disable,
 *     repair, upgrade or restore, so two of those cannot interleave.
 *
 * They are distinct identities on purpose. Taking the maintenance lock must
 * never make a running Agent look absent, and a running Agent must never make
 * maintenance look busy.
 *
 * Both are sockets rather than PID files. A PID file survives the process that
 * wrote it and then lies -- the PID gets reused, or the file is left behind by
 * a hard kill -- so it needs a liveness heuristic on top. A listening socket
 * IS the liveness: the kernel drops it when the owner dies. On POSIX a stale
 * socket file can remain on disk, so an unconnectable one is treated as debris
 * and replaced; on Windows a named pipe leaves nothing behind at all.
 *
 * SECURITY BOUNDARY, STATED HONESTLY. These are same-user endpoints: a Windows
 * named pipe, or a unix socket at mode 0600. Another user cannot reach them.
 * The same user can, and that is not a boundary this can defend -- anyone
 * running as this user can already rewrite the managed install, the launcher
 * and the credential file directly. The command surface is therefore kept to
 * the single verb the upgrade handoff needs, and that verb only ever asks the
 * Agent to shut down cleanly.
 */
import net from 'node:net';
import { chmod, lstat, mkdir, unlink } from 'node:fs/promises';
import path from 'node:path';

import { deriveManagedIdentity } from './managed-upgrade.ts';

export type AgentOwnership = {
  endpoint: string;
  release(): Promise<void>;
};

/** Answered to a caller that sends nothing, and to any Agent with no handler. */
const OWNED = 'already_running\n';
const REFUSED = 'refused\n';
const ACCEPTED = 'shutting_down\n';

/** A command line is one short verb and one transaction id. Nothing else. */
const COMMAND_LIMIT = 256;
const COMMAND_WINDOW_MS = 2_000;
const REQUEST_TIMEOUT_MS = 5_000;
const UPGRADE_COMMAND = /^upgrade ([a-f0-9]{32})$/u;

type LockKind = 'agent' | 'maintenance';

function busyReason(kind: LockKind): string {
  return kind === 'agent' ? 'already_running' : 'maintenance_busy';
}

function windowsEndpoint(kind: LockKind, identity: string): string {
  return `\\\\.\\pipe\\ysd-zero-cloud-${kind}-${identity}`;
}

function socketName(kind: LockKind, identity: string): string {
  return `.ysd-${kind}-${identity}.sock`;
}

function connect(endpoint: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection(endpoint);
    socket.once('connect', () => {
      socket.end();
      resolve(true);
    });
    socket.once('error', () => resolve(false));
  });
}

async function posixEndpoint(configPath: string, kind: LockKind, identity: string): Promise<string> {
  const root = path.resolve(path.dirname(configPath));
  await mkdir(root, { recursive: true, mode: 0o700 });
  const endpoint = path.join(root, socketName(kind, identity));
  if (path.dirname(endpoint) !== root) throw new Error('lock_invalid');
  try {
    const details = await lstat(endpoint);
    if (details.isSymbolicLink() || !details.isSocket()) throw new Error('lock_invalid');
    if (await connect(endpoint)) throw new Error(busyReason(kind));
    const second = await lstat(endpoint);
    if (second.isSymbolicLink() || !second.isSocket()) throw new Error('lock_invalid');
    await unlink(endpoint);
  } catch (error) {
    if (error instanceof Error && (error.message === busyReason(kind) || error.message === 'lock_invalid')) throw error;
    if (!(error instanceof Error) || !('code' in error) || (error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  return endpoint;
}

async function acquire(
  kind: LockKind,
  configPath: string,
  nodeId: string,
  onUpgradeRequest?: (transactionId: string) => Promise<boolean>,
): Promise<AgentOwnership> {
  const identity = await deriveManagedIdentity(configPath, nodeId);
  const endpoint = process.platform === 'win32'
    ? windowsEndpoint(kind, identity)
    : await posixEndpoint(configPath, kind, identity);

  const server = net.createServer((socket) => {
    socket.setEncoding('utf8');
    let buffer = '';
    let answered = false;
    let timer: NodeJS.Timeout | null = null;
    const answer = (reply: string) => {
      if (answered) return;
      answered = true;
      if (timer) clearTimeout(timer);
      socket.end(reply);
    };
    timer = setTimeout(() => answer(OWNED), COMMAND_WINDOW_MS);
    // A peer that only wants to know whether the identity is held connects and
    // closes without saying anything. That is the Phase 19 probe, and it still
    // gets the Phase 19 answer.
    socket.once('end', () => answer(OWNED));
    socket.once('error', () => {
      answered = true;
      if (timer) clearTimeout(timer);
      socket.destroy();
    });
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      if (buffer.length > COMMAND_LIMIT) {
        answer(REFUSED);
        return;
      }
      const newline = buffer.indexOf('\n');
      if (newline < 0) return;
      const line = buffer.slice(0, newline).trim();
      if (!onUpgradeRequest) {
        // An Agent that predates the upgrade handoff answers exactly as it
        // always did, so the caller can tell it apart and fall back to the
        // native manager instead of assuming a graceful shutdown happened.
        answer(OWNED);
        return;
      }
      const match = UPGRADE_COMMAND.exec(line);
      if (!match) {
        answer(REFUSED);
        return;
      }
      void onUpgradeRequest(match[1]!).then(
        (accepted) => answer(accepted ? ACCEPTED : REFUSED),
        () => answer(REFUSED),
      );
    });
  });

  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(endpoint, resolve);
    });
  } catch (error) {
    server.close();
    if ((error as NodeJS.ErrnoException).code === 'EADDRINUSE') throw new Error(busyReason(kind));
    throw error;
  }
  if (process.platform !== 'win32') await chmod(endpoint, 0o600);
  let released = false;
  return {
    endpoint,
    async release() {
      if (released) return;
      released = true;
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (process.platform !== 'win32') {
        try {
          const details = await lstat(endpoint);
          if (details.isSocket() && !details.isSymbolicLink()) await unlink(endpoint);
        } catch { /* Already cleaned. */ }
      }
    },
  };
}

export async function acquireAgentOwnership(
  configPath: string,
  nodeId: string,
  onUpgradeRequest?: (transactionId: string) => Promise<boolean>,
): Promise<AgentOwnership> {
  return await acquire('agent', configPath, nodeId, onUpgradeRequest);
}

export async function acquireMaintenanceOwnership(
  configPath: string,
  nodeId: string,
): Promise<AgentOwnership> {
  return await acquire('maintenance', configPath, nodeId);
}

/** Whether some Agent currently holds this node identity. */
export async function agentOwnershipHeld(configPath: string, nodeId: string): Promise<boolean> {
  const identity = await deriveManagedIdentity(configPath, nodeId);
  const endpoint = process.platform === 'win32'
    ? windowsEndpoint('agent', identity)
    : path.join(path.resolve(path.dirname(configPath)), socketName('agent', identity));
  return await connect(endpoint);
}

export type UpgradeHandoff = 'shutting_down' | 'refused' | 'unsupported' | 'not_running';

/**
 * Asks a running Agent to stand down for an upgrade it can verify.
 *
 * `unsupported` is the interesting answer: it means an Agent holds the node
 * identity but does not implement the verb, which is exactly what a managed
 * 0.6.0 does. The caller must then use the native manager's own stop, because
 * assuming a handoff that never happened would start a second Agent.
 */
export async function requestManagedUpgradeShutdown(
  configPath: string,
  nodeId: string,
  transactionId: string,
): Promise<UpgradeHandoff> {
  if (!/^[a-f0-9]{32}$/u.test(transactionId)) return 'refused';
  const identity = await deriveManagedIdentity(configPath, nodeId);
  const endpoint = process.platform === 'win32'
    ? windowsEndpoint('agent', identity)
    : path.join(path.resolve(path.dirname(configPath)), socketName('agent', identity));
  return await new Promise<UpgradeHandoff>((resolve) => {
    const socket = net.createConnection(endpoint);
    let connected = false;
    let buffer = '';
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (!connected) {
        resolve('not_running');
        return;
      }
      const reply = buffer.split('\n')[0]?.trim() ?? '';
      if (reply === 'shutting_down') resolve('shutting_down');
      else if (reply === 'already_running') resolve('unsupported');
      else resolve('refused');
    };
    socket.setEncoding('utf8');
    socket.setTimeout(REQUEST_TIMEOUT_MS, finish);
    socket.once('connect', () => {
      connected = true;
      socket.write(`upgrade ${transactionId}\n`);
    });
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      if (buffer.includes('\n')) finish();
    });
    socket.once('error', finish);
    socket.once('close', finish);
  });
}
