import { queryOne } from './db';
import { runtimeEnv } from './env';

/**
 * The instance owner.
 *
 * The SQL Editor runs statements this application cannot rewrite, so it cannot
 * be scoped to a workspace the way Database Studio is. Rather than expose every
 * tenant's rows through it, the editor is limited to a single trusted operator.
 *
 * Ownership is the earliest registered account, which on a self-hosted instance
 * is whoever set it up. `YSD_OWNER_EMAIL` overrides that when the first account
 * is not the right one.
 */
export async function isInstanceOwner(userId: string, email: string): Promise<boolean> {
  const configured = runtimeEnv.YSD_OWNER_EMAIL?.trim();
  if (configured) return configured.toLowerCase() === email.trim().toLowerCase();

  // Better Auth writes `createdAt` as an ISO 8601 string, which orders
  // correctly as text.
  const first = await queryOne<{ id: string }>(
    'SELECT id FROM "user" ORDER BY createdAt ASC, id ASC LIMIT 1',
  );
  return first?.id === userId;
}
