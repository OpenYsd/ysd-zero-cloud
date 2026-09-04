import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'node:crypto';
import { Buffer } from 'node:buffer';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';

import { resolveAgentKey } from './agent-key.ts';

export type AgentCredentials = {
  origin: string;
  nodeId: string;
  workspaceId: string;
  token: string;
  createdAt: number;
};

type CredentialEnvelope = {
  version: 1;
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
};

/**
 * The key is resolved rather than demanded: an explicit YSD_NODE_AGENT_KEY
 * wins, otherwise the agent generates and stores a 256-bit one per user. The
 * KDF below is unchanged either way, so this improves the input without
 * touching the encryption.
 */
function key(secret: string, salt: Buffer): Buffer {
  return scryptSync(secret, salt, 32, {
    N: 16_384,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
}

export async function saveCredentials(
  path: string,
  credentials: AgentCredentials,
): Promise<void> {
  const secret = await resolveAgentKey();
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(secret, salt), iv);
  const plaintext = Buffer.from(JSON.stringify(credentials), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const envelope: CredentialEnvelope = {
    version: 1,
    salt: Buffer.from(salt).toString('base64url'),
    iv: Buffer.from(iv).toString('base64url'),
    tag: Buffer.from(cipher.getAuthTag()).toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
  };
  await mkdir(nodePath.dirname(nodePath.resolve(path)), { recursive: true, mode: 0o700 });
  // Re-pairing replaces the credential. 'wx' would refuse, which used to
  // strand anyone who paired a second time after revoking a node.
  await writeFile(path, JSON.stringify(envelope), { encoding: 'utf8', mode: 0o600 });
}

export async function loadCredentials(path: string): Promise<AgentCredentials> {
  const raw = await readFile(path, 'utf8');
  const envelope = JSON.parse(raw) as CredentialEnvelope;
  if (
    envelope.version !== 1 ||
    !envelope.salt ||
    !envelope.iv ||
    !envelope.tag ||
    !envelope.ciphertext
  ) {
    throw new Error('The credential file format is invalid.');
  }
  const secret = await resolveAgentKey();
  const salt = Buffer.from(envelope.salt, 'base64url');
  const decipher = createDecipheriv(
    'aes-256-gcm',
    key(secret, salt),
    Buffer.from(envelope.iv, 'base64url'),
  );
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64url'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64url')),
    decipher.final(),
  ]);
  const credentials = JSON.parse(
    plaintext.toString('utf8'),
  ) as AgentCredentials;
  if (
    !credentials.origin ||
    !credentials.nodeId ||
    !credentials.workspaceId ||
    !credentials.token
  ) {
    throw new Error('The decrypted credential file is incomplete.');
  }
  return credentials;
}
