import { betterAuth } from 'better-auth';
import { env, waitUntil } from 'cloudflare:workers';

import { hasGithubOAuth } from '@/lib/integrations';
import { buildAuthOptions, resolveAuthSecret } from './auth-options';
import { ensureSchema, getDatabase } from './db';
import { isEmailConfigured, sendEmail, verificationMessage } from './email';
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

/**
 * Whether a verified address is required to sign in.
 *
 * Tied to whether mail can actually be delivered.
 * `YSD_REQUIRE_EMAIL_VERIFICATION` can turn the requirement off even with a
 * provider configured, but it can never turn it on without one: requiring a
 * verified address with no way to send the link locks every operator out of
 * their own instance, which is worse than an unverified address.
 */
export function emailVerificationRequired(): boolean {
  if (!isEmailConfigured()) return false;
  const flag = runtimeEnv.YSD_REQUIRE_EMAIL_VERIFICATION?.trim().toLowerCase();
  return flag !== 'false' && flag !== '0';
}

/**
 * Origins permitted to drive the auth endpoints.
 *
 * Better Auth refuses a cross-site request whose Origin is not on this list,
 * which is what stops a hostile page from POSTing to sign-in with a victim's
 * cookies. The deployed origin is the only entry outside development.
 */
export function trustedOrigins(): string[] {
  const configured = runtimeEnv.BETTER_AUTH_URL?.trim();
  if (configured) return [configured.replace(/\/+$/, '')];
  return isDevelopment() ? ['http://localhost:3000'] : [];
}

function createAuth(): Auth {
  const github = hasGithubOAuth(runtimeEnv)
    ? {
        clientId: env.GITHUB_CLIENT_ID!,
        clientSecret: env.GITHUB_CLIENT_SECRET!,
      }
    : undefined;

  const mailConfigured = isEmailConfigured();

  return betterAuth(
    buildAuthOptions({
      database: getDatabase(),
      secret: authSecret(),
      // Only honoured outside development: `wrangler.jsonc` carries the
      // deployed origin, and the Vite plugin merges that file into the local
      // dev config too, which would otherwise point a dev session at
      // production for callbacks and redirects.
      baseURL: isDevelopment()
        ? undefined
        : env.BETTER_AUTH_URL?.trim() || undefined,
      github,
      requireEmailVerification: emailVerificationRequired(),
      // Local development runs over plain HTTP, where a Secure cookie is
      // dropped by the browser and nobody could sign in.
      secureCookies: !isDevelopment(),
      trustedOrigins: trustedOrigins(),
      ...(mailConfigured
        ? {
            sendVerificationEmail: async ({ user, url }) => {
              const message = verificationMessage(user.name, url);
              waitUntil(
                sendEmail({ to: user.email, ...message }).then((result) => {
                  if (!result.ok) {
                    // Provider details are deliberately generic and contain no
                    // recipient address or verification link.
                    console.warn(
                      '[ysd] verification email failed:',
                      result.error,
                    );
                  }
                }),
              );
            },
          }
        : {}),
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
export async function getSessionUser(
  headers: Headers,
): Promise<SessionUser | null> {
  const auth = await getAuth();
  const session = await auth.api.getSession({ headers });
  if (!session?.user) return null;
  const { id, name, email, emailVerified, image } = session.user;
  return { id, name, email, emailVerified, image };
}
