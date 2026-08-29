/**
 * Runtime environment contract.
 *
 * `Cloudflare.Env` is declaration-merged, so `import { env } from
 * "cloudflare:workers"` is typed everywhere without a generated file needing
 * to be committed. Only `DB` is required: every other entry unlocks an
 * optional integration and the app runs without it.
 */
declare namespace Cloudflare {
  interface Env {
    /** Workspace database. Provisioned by the `d1` entry in `.openai/hosting.json`. */
    DB: D1Database;
    /** Private object storage. Optional until R2 is enabled for the account. */
    STORAGE?: R2Bucket;

    /** Signing key for Better Auth sessions. Required outside development. */
    BETTER_AUTH_SECRET?: string;
    /** Absolute origin Better Auth issues callbacks against. */
    BETTER_AUTH_URL?: string;
    /** Master key for secret envelope encryption. Falls back to BETTER_AUTH_SECRET. */
    YSD_SECRETS_KEY?: string;
    /** Operator allowed to use the SQL Editor. Defaults to the first account. */
    YSD_OWNER_EMAIL?: string;

    /** Cloudflare Turnstile. Both are required for the challenge to be enforced. */
    TURNSTILE_SITE_KEY?: string;
    TURNSTILE_SECRET_KEY?: string;

    /** Transactional email (Resend free tier). Both values enable verification. */
    RESEND_API_KEY?: string;
    YSD_EMAIL_FROM?: string;
    /** Explicit production gate: `disabled-no-domain` until an owned domain exists. */
    YSD_EMAIL_VERIFICATION_MODE?: string;
    /** Set to "false" to keep verification optional even with mail configured. */
    YSD_REQUIRE_EMAIL_VERIFICATION?: string;

    /** GitHub OAuth sign-in. Both must be set for the provider to appear. */
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
    /** Read-only token used by Smart Deploy to inspect a repository. */
    GITHUB_TOKEN?: string;

    /** Read-only Cloudflare inventory calls. */
    CLOUDFLARE_API_TOKEN?: string;
    CLOUDFLARE_ACCOUNT_ID?: string;
    /** Set on deployed environments so the D1 metadata endpoint can be read. */
    CLOUDFLARE_D1_DATABASE_ID?: string;

    /** Public site origin used for metadata. */
    NEXT_PUBLIC_SITE_URL?: string;
    /** `workers-dev-only` while no custom domain or Tunnel exists. */
    YSD_NETWORK_MODE?: string;

    /** Set by Wrangler on deployed Workers. */
    WORKERS_CI?: string;
  }
}

declare module '*.sql?raw' {
  const content: string;
  export default content;
}
