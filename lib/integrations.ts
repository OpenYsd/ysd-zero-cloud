/**
 * The provider boundary.
 *
 * Nothing here talks to a network. Each descriptor states what an integration
 * would be responsible for and which configuration it needs, so every surface
 * can tell the operator exactly what is live and what is still simulated
 * without an adapter having to be written first.
 */

export type IntegrationProvider =
  | 'github'
  | 'github-oauth'
  | 'cloudflare'
  | 'cloudflare-d1'
  | 'better-auth'
  | 'turnstile'
  | 'email';

export type IntegrationStatus = 'mock' | 'configured' | 'bound';

export type IntegrationDescriptor = {
  id: IntegrationProvider;
  name: string;
  purpose: string;
  envKeys: string[];
  status: IntegrationStatus;
  /** True when the integration is fulfilled by a runtime binding, not env vars. */
  binding?: string;
  /** Whether the integration can only ever use no-cost provider features. */
  freeTierOnly: true;
};

type Definition = Omit<IntegrationDescriptor, 'status' | 'freeTierOnly'>;

const definitions: Definition[] = [
  {
    id: 'cloudflare-d1',
    name: 'Cloudflare D1',
    purpose: 'Workspace database, auth storage, and the Studio surfaces',
    envKeys: [],
    binding: 'DB',
  },
  {
    id: 'github-oauth',
    name: 'GitHub sign-in',
    purpose: 'OAuth sign-in for workspace members',
    envKeys: ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'],
  },
  {
    id: 'github',
    name: 'GitHub repositories',
    purpose: 'Repository discovery for Smart Deploy analysis',
    envKeys: ['GITHUB_TOKEN'],
  },
  {
    id: 'cloudflare',
    name: 'Cloudflare account',
    purpose: 'Workers, DNS, and R2 inventory',
    envKeys: ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'],
  },
  {
    id: 'better-auth',
    name: 'Better Auth',
    purpose: 'D1-backed identities, sessions, and verified email state',
    envKeys: ['BETTER_AUTH_SECRET'],
  },
  {
    id: 'turnstile',
    name: 'Cloudflare Turnstile',
    purpose: 'Bot protection for sign-in and sign-up',
    envKeys: ['TURNSTILE_SITE_KEY', 'TURNSTILE_SECRET_KEY'],
  },
  {
    id: 'email',
    name: 'Verification email',
    purpose: 'Transactional verification links through the Resend free tier',
    envKeys: ['RESEND_API_KEY', 'YSD_EMAIL_FROM'],
  },
];

export type IntegrationEnv = Record<string, unknown>;

function hasValue(env: IntegrationEnv, key: string): boolean {
  const value = env[key];
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * @param env Runtime environment. In workerd this is the Cloudflare `env`
 * object, so bindings and vars are both visible on it.
 */
export function getIntegrationCatalog(
  env: IntegrationEnv = {},
): IntegrationDescriptor[] {
  return definitions.map((definition) => {
    let status: IntegrationStatus = 'mock';
    if (definition.binding) {
      status = env[definition.binding] ? 'bound' : 'mock';
    } else if (
      definition.envKeys.length > 0 &&
      definition.envKeys.every((key) => hasValue(env, key))
    ) {
      status = 'configured';
    }
    return { ...definition, status, freeTierOnly: true };
  });
}

/** Whether GitHub OAuth sign-in can be offered on the sign-in page. */
export function hasGithubOAuth(env: IntegrationEnv): boolean {
  return (
    hasValue(env, 'GITHUB_CLIENT_ID') && hasValue(env, 'GITHUB_CLIENT_SECRET')
  );
}

/** Whether Smart Deploy may inspect a repository over the GitHub API. */
export function hasGithubToken(env: IntegrationEnv): boolean {
  return hasValue(env, 'GITHUB_TOKEN');
}

/** Whether the Cloudflare read-only inventory calls can be made. */
export function hasCloudflareApi(env: IntegrationEnv): boolean {
  return (
    hasValue(env, 'CLOUDFLARE_API_TOKEN') &&
    hasValue(env, 'CLOUDFLARE_ACCOUNT_ID')
  );
}
