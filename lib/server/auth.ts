import { betterAuth } from 'better-auth';
import { env } from 'cloudflare:workers';

import { hasGithubOAuth } from '@/lib/integrations';
import { buildAuthOptions, resolveAuthSecret } from './auth-options';
import { ensureSchema, getDatabase } from './db';
import { runtimeEnv } from './env';

/**
 * The Better Auth instance, backed directly by the D1 binding.
 *
 * Better Auth 1.7 accepts a `D1Database` and picks its own SQLite dialect, so
 * no extra driver sits between the app and the binding. The instance is built
 * lazily: a Worker isolate must not do binding work while the module graph is
 * still evaluating.
 */

export type Auth = ReturnType<typeof betterAuth>;

let instance: Auth | undefined;

export function isDevelopment(): boolean {
  return process.env.NODE_ENV !== 'production';
}

/** Signing key for sessions, and the default master key for stored secrets. */
export function authSecret(): string {
  return resolveAuthSecret(env.BETTER_AUTH_SECRET, isDevelopment());
}

function createAuth(): Auth {
  const github = hasGithubOAuth(runtimeEnv)
    ? { clientId: env.GITHUB_CLIENT_ID!, clientSecret: env.GITHUB_CLIENT_SECRET! }
    : undefined;

  return betterAuth(
    buildAuthOptions({
      database: getDatabase(),
      secret: authSecret(),
      baseURL: env.BETTER_AUTH_URL?.trim() || undefined,
      github,
    }),
  );
}

/**
 * Returns the auth instance with the schema guaranteed to exist.
 *
 * Better Auth never creates its own tables at runtime, so the migration has to
 * have landed before the first sign-in query is issued.
 */
export async function getAuth(): Promise<Auth> {
  await ensureSchema();
  instance ??= createAuth();
  return instance;
}

export type SessionUser = {
  id: string;
  name: string;
  email: string;
  emailVerified: boolean;
  image?: string | null;
};

/** The signed-in user, or null. Never throws on an anonymous request. */
export async function getSessionUser(headers: Headers): Promise<SessionUser | null> {
  const auth = await getAuth();
  const session = await auth.api.getSession({ headers });
  if (!session?.user) return null;
  const { id, name, email, emailVerified, image } = session.user;
  return { id, name, email, emailVerified, image };
}
