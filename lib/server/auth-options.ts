import type { BetterAuthOptions } from 'better-auth';

/**
 * Better Auth configuration, shared by the runtime instance and by the schema
 * generator in `scripts/`. Keeping it in one place means the committed
 * migration can never drift from the options the app actually boots with.
 *
 * This module must stay free of Cloudflare imports so the generator can run it
 * under plain Node.
 */

/**
 * Fallback signing key for `npm run dev`.
 *
 * This is a published constant, not a credential: it exists so a fresh
 * checkout boots without configuration. `resolveAuthSecret` refuses to use it
 * once the app is running anywhere other than development.
 */
export const DEVELOPMENT_AUTH_SECRET = 'ysd-zero-cloud-development-only-not-a-secret';

export type AuthConfig = {
  /** A D1 binding at runtime, or a `node:sqlite` handle in the generator. */
  database: NonNullable<BetterAuthOptions['database']>;
  secret: string;
  baseURL?: string;
  github?: { clientId: string; clientSecret: string };
};

export function buildAuthOptions(config: AuthConfig): BetterAuthOptions {
  return {
    appName: 'YSD Zero Cloud',
    database: config.database,
    secret: config.secret,
    ...(config.baseURL ? { baseURL: config.baseURL } : {}),

    emailAndPassword: {
      enabled: true,
      // No mail provider is configured, so requiring verification would lock
      // every new operator out of their own workspace. YSD Shield reports the
      // unverified accounts instead.
      requireEmailVerification: false,
      minPasswordLength: 12,
      maxPasswordLength: 256,
      autoSignIn: true,
    },

    ...(config.github
      ? {
          socialProviders: {
            github: {
              clientId: config.github.clientId,
              clientSecret: config.github.clientSecret,
            },
          },
        }
      : {}),

    session: {
      expiresIn: 60 * 60 * 24 * 7,
      updateAge: 60 * 60 * 24,
    },

    // Nothing in this project may call out to a third party uninvited.
    telemetry: { enabled: false },
  };
}

/**
 * Resolves the signing key, refusing the development fallback outside
 * development so a deployed workspace cannot run on a published constant.
 */
export function resolveAuthSecret(
  configured: string | undefined,
  isDevelopment: boolean,
): string {
  const trimmed = configured?.trim();
  if (trimmed) return trimmed;
  if (isDevelopment) return DEVELOPMENT_AUTH_SECRET;
  throw new Error(
    'BETTER_AUTH_SECRET is not set. Generate one with `openssl rand -base64 32` and add it as a Worker secret.',
  );
}
