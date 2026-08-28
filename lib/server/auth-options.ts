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
  /**
   * Whether a verified address is required before signing in.
   *
   * Only ever true when a mail provider is configured — requiring
   * verification with no way to deliver the mail would lock every operator out
   * of their own instance. `lib/server/email.ts` decides.
   */
  requireEmailVerification?: boolean;
  /**
   * Origins allowed to drive the auth endpoints. Anything else is refused by
   * the CSRF check, so this is the list that matters for cross-site requests.
   */
  trustedOrigins?: string[];
  /** False only for local HTTP development, where a Secure cookie never returns. */
  secureCookies?: boolean;
  /** Sends the verification mail. Absent when no provider is configured. */
  sendVerificationEmail?: (input: {
    user: { email: string; name: string };
    url: string;
    token: string;
  }) => Promise<void>;
};

export function buildAuthOptions(config: AuthConfig): BetterAuthOptions {
  return {
    appName: 'YSD Zero Cloud',
    database: config.database,
    secret: config.secret,
    ...(config.baseURL ? { baseURL: config.baseURL } : {}),

    emailAndPassword: {
      enabled: true,
      requireEmailVerification: config.requireEmailVerification ?? false,
      minPasswordLength: 12,
      maxPasswordLength: 256,
      autoSignIn: true,
    },

    emailVerification: {
      // The link is what an operator clicks; Better Auth marks the address
      // verified and we redirect them into the workspace.
      sendOnSignUp: Boolean(config.sendVerificationEmail),
      autoSignInAfterVerification: true,
      expiresIn: 60 * 60 * 24,
      ...(config.sendVerificationEmail
        ? { sendVerificationEmail: config.sendVerificationEmail }
        : {}),
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

    /**
     * Better Auth's own limiter, in front of every `/api/auth/*` route.
     *
     * Stored in the database rather than in memory: a Worker isolate is
     * discarded between requests, so an in-memory counter would reset
     * constantly and enforce nothing. This sits underneath the application
     * limiter in `lib/rate-limit.ts`, which applies tighter per-endpoint rules.
     */
    rateLimit: {
      enabled: true,
      storage: 'database',
      window: 60,
      max: 60,
    },

    ...(config.trustedOrigins?.length ? { trustedOrigins: config.trustedOrigins } : {}),

    advanced: {
      /**
       * Session cookies.
       *
       * `httpOnly` keeps the token away from any script on the page, so an XSS
       * bug cannot read a session out of `document.cookie`. `sameSite: lax`
       * stops the cookie riding along on a cross-site POST, which is the CSRF
       * case that matters here. `secure` is on everywhere except local HTTP,
       * where the browser would simply drop the cookie and nobody could sign in.
       */
      useSecureCookies: config.secureCookies ?? true,
      defaultCookieAttributes: {
        httpOnly: true,
        sameSite: 'lax',
        secure: config.secureCookies ?? true,
        path: '/',
      },

      /**
       * Which header carries the caller's address.
       *
       * Without this Better Auth cannot identify the client and drops every
       * request into one shared rate-limit bucket — so a single attacker would
       * consume the budget for every legitimate operator at once. On Cloudflare
       * the edge sets `CF-Connecting-IP` and a client cannot forge it, which is
       * why it is the only header trusted here.
       */
      ipAddress: {
        ipAddressHeaders: ['cf-connecting-ip'],
      },
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
