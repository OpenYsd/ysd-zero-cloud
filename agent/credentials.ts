import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'node:crypto';
import { Buffer } from 'node:buffer';
import { readFile, writeFile } from 'node:fs/promises';

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

function passphrase(): string {
  const value = process.env.YSD_NODE_AGENT_KEY ?? '';
  if (value.length < 16) {
    throw new Error(
      'Set YSD_NODE_AGENT_KEY to a local passphrase of at least 16 characters.',
    );
  }
  return value;
}

function key(salt: Buffer): Buffer {
  return scryptSync(passphrase(), salt, 32, {
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
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(salt), iv);
  const plaintext = Buffer.from(JSON.stringify(credentials), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const envelope: CredentialEnvelope = {
    version: 1,
    salt: Buffer.from(salt).toString('base64url'),
    iv: Buffer.from(iv).toString('base64url'),
    tag: Buffer.from(cipher.getAuthTag()).toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
  };
  await writeFile(path, JSON.stringify(envelope), {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx',
  });
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
  const salt = Buffer.from(envelope.salt, 'base64url');
  const decipher = createDecipheriv(
    'aes-256-gcm',
    key(salt),
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
