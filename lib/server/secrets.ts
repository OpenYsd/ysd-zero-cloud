import { env } from 'cloudflare:workers';

import { createId, encryptSecret, fingerprint } from '@/lib/crypto';
import { isSecretEnvironment, type Secret } from '@/lib/domain';
import { authSecret } from './auth';
import { count, execute, query, queryOne } from './db';
import { writeLog } from './logs';

/**
 * Encrypted workspace configuration.
 *
 * Values are write-only by design. They are sealed with AES-GCM on the way in
 * and there is no endpoint that unseals them: a stored secret exists to be
 * handed to a workload, not to be read back through a browser. That removes
 * the entire class of bug where an over-broad session or a mis-scoped query
 * leaks credentials through the UI.
 */

export type { Secret };

export const MAX_SECRETS = 200;

/** Matches the shape platforms accept for an environment variable name. */
const NAME_PATTERN = /^[A-Z][A-Z0-9_]{1,63}$/;

function masterKey(): string {
  return env.YSD_SECRETS_KEY?.trim() || authSecret();
}

export function normalizeSecretName(input: string): string {
  return input.trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_');
}

const SELECT = `id, name, scope, environment, fingerprint, rotationDays, createdAt, updatedAt`;

export async function listSecrets(workspaceId: string): Promise<Secret[]> {
  return query<Secret>(
    `SELECT ${SELECT} FROM secret WHERE workspaceId = ? ORDER BY name ASC, environment ASC`,
    workspaceId,
  );
}

export async function countSecrets(workspaceId: string): Promise<number> {
  return count('SELECT COUNT(*) AS total FROM secret WHERE workspaceId = ?', workspaceId);
}

export type PutSecretInput = {
  workspaceId: string;
  actor: string;
  name: string;
  value: string;
  scope?: string;
  environment?: string;
  rotationDays?: number | null;
};

export type PutSecretResult =
  | { ok: true; secret: Secret; created: boolean }
  | { ok: false; error: string; status: number };

/** Creates or replaces a secret. The plaintext never leaves this function. */
export async function putSecret(input: PutSecretInput): Promise<PutSecretResult> {
  const name = normalizeSecretName(input.name);
  if (!NAME_PATTERN.test(name)) {
    return {
      ok: false,
      error: 'Use an uppercase name of 2-64 characters, for example DATABASE_URL.',
      status: 400,
    };
  }
  if (!input.value) {
    return { ok: false, error: 'A value is required.', status: 400 };
  }
  if (input.value.length > 8192) {
    return { ok: false, error: 'Values are limited to 8192 characters.', status: 400 };
  }

  const environment = input.environment && isSecretEnvironment(input.environment)
    ? input.environment
    : 'Production';
  const rotationDays =
    typeof input.rotationDays === 'number' && Number.isFinite(input.rotationDays)
      ? Math.max(1, Math.min(3650, Math.floor(input.rotationDays)))
      : null;

  const existing = await queryOne<{ id: string }>(
    'SELECT id FROM secret WHERE workspaceId = ? AND environment = ? AND name = ?',
    input.workspaceId,
    environment,
    name,
  );

  if (!existing && (await countSecrets(input.workspaceId)) >= MAX_SECRETS) {
    return {
      ok: false,
      error: `The free tier allows ${MAX_SECRETS} secrets. Delete one to add another.`,
      status: 409,
    };
  }

  const key = masterKey();
  const ciphertext = await encryptSecret(input.value, key);
  const print = await fingerprint(input.value);
  const now = Date.now();

  if (existing) {
    await execute(
      `UPDATE secret SET ciphertext = ?, fingerprint = ?, scope = ?, rotationDays = ?, updatedAt = ?
       WHERE workspaceId = ? AND id = ?`,
      ciphertext,
      print,
      input.scope?.trim() || 'Workspace',
      rotationDays,
      now,
      input.workspaceId,
      existing.id,
    );
  } else {
    await execute(
      `INSERT INTO secret (id, workspaceId, name, scope, environment, ciphertext, fingerprint, rotationDays, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      createId('sec'),
      input.workspaceId,
      name,
      input.scope?.trim() || 'Workspace',
      environment,
      ciphertext,
      print,
      rotationDays,
      now,
      now,
    );
  }

  await writeLog({
    workspaceId: input.workspaceId,
    source: 'secret',
    message: `${existing ? 'Rotated' : 'Created'} ${name} for ${environment}`,
    actor: input.actor,
    resource: name,
  });

  const secret = await queryOne<Secret>(
    `SELECT ${SELECT} FROM secret WHERE workspaceId = ? AND environment = ? AND name = ?`,
    input.workspaceId,
    environment,
    name,
  );
  if (!secret) return { ok: false, error: 'The secret could not be stored.', status: 500 };

  return { ok: true, secret, created: !existing };
}

export async function deleteSecret(
  workspaceId: string,
  id: string,
  actor: string,
): Promise<boolean> {
  const secret = await queryOne<{ name: string; environment: string }>(
    'SELECT name, environment FROM secret WHERE workspaceId = ? AND id = ?',
    workspaceId,
    id,
  );
  if (!secret) return false;

  await execute('DELETE FROM secret WHERE workspaceId = ? AND id = ?', workspaceId, id);
  await writeLog({
    workspaceId,
    level: 'WARN',
    source: 'secret',
    message: `Deleted ${secret.name} from ${secret.environment}`,
    actor,
    resource: secret.name,
  });
  return true;
}

/** The snapshot YSD Shield scores. Ciphertext is deliberately not included. */
export async function secretsForShield(workspaceId: string) {
  return query<{
    name: string;
    environment: string;
    rotationDays: number | null;
    updatedAt: number;
    fingerprint: string;
  }>(
    'SELECT name, environment, rotationDays, updatedAt, fingerprint FROM secret WHERE workspaceId = ?',
    workspaceId,
  );
}
