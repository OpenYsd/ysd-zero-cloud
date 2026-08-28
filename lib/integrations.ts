export type IntegrationProvider = 'github' | 'cloudflare' | 'supabase';

export type IntegrationDescriptor = {
  id: IntegrationProvider;
  name: string;
  purpose: string;
  envKeys: string[];
  status: 'mock' | 'configured';
};

const definitions: Omit<IntegrationDescriptor, 'status'>[] = [
  { id: 'github', name: 'GitHub', purpose: 'Repository discovery and webhooks', envKeys: ['GITHUB_TOKEN'] },
  { id: 'cloudflare', name: 'Cloudflare', purpose: 'Workers, DNS, and R2 deployment', envKeys: ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'] },
  { id: 'supabase', name: 'Supabase', purpose: 'Database, auth, and storage provisioning', envKeys: ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY'] },
];

export function getIntegrationCatalog(env: Record<string, string | undefined> = process.env) {
  return definitions.map<IntegrationDescriptor>((definition) => ({
    ...definition,
    status: definition.envKeys.every((key) => Boolean(env[key])) ? 'configured' : 'mock',
  }));
}
