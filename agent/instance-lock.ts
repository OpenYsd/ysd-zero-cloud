import net from 'node:net';
import { chmod, lstat, mkdir, unlink } from 'node:fs/promises';
import path from 'node:path';

import { deriveManagedIdentity } from './autostart.ts';

export type AgentOwnership = {
  endpoint: string;
  release(): Promise<void>;
};

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

async function posixEndpoint(configPath: string, identity: string): Promise<string> {
  const root = path.resolve(path.dirname(configPath));
  await mkdir(root, { recursive: true, mode: 0o700 });
  const endpoint = path.join(root, `.ysd-agent-${identity}.sock`);
  if (path.dirname(endpoint) !== root) throw new Error('lock_invalid');
  try {
    const details = await lstat(endpoint);
    if (details.isSymbolicLink() || !details.isSocket()) throw new Error('lock_invalid');
    if (await connect(endpoint)) throw new Error('already_running');
    const second = await lstat(endpoint);
    if (second.isSymbolicLink() || !second.isSocket()) throw new Error('lock_invalid');
    await unlink(endpoint);
  } catch (error) {
    if (error instanceof Error && (error.message === 'already_running' || error.message === 'lock_invalid')) throw error;
    if (!(error instanceof Error) || !('code' in error) || (error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  return endpoint;
}

export async function acquireAgentOwnership(
  configPath: string,
  nodeId: string,
): Promise<AgentOwnership> {
  const identity = await deriveManagedIdentity(configPath, nodeId);
  const endpoint = process.platform === 'win32'
    ? `\\\\.\\pipe\\ysd-zero-cloud-agent-${identity}`
    : await posixEndpoint(configPath, identity);
  const server = net.createServer((socket) => socket.end('already_running\n'));
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(endpoint, resolve);
    });
  } catch (error) {
    server.close();
    if ((error as NodeJS.ErrnoException).code === 'EADDRINUSE') throw new Error('already_running');
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
