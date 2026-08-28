/** Deployment-time Zero Mode checks for the generated Wrangler configuration. */

type UnknownRecord = Record<string, unknown>;

export type DeploymentGuardInput = {
  freeTierVerified: boolean;
  estimatedMonthlyCost: number;
  expectedD1DatabaseId: string;
};

export type DeploymentGuardDecision = {
  allowed: boolean;
  reasons: string[];
};

const DISALLOWED_ARRAY_BINDINGS = [
  'ai_search',
  'ai_search_namespaces',
  'artifacts',
  'hyperdrive',
  'kv_namespaces',
  'pipelines',
  'r2_buckets',
  'secrets_store_secrets',
  'services',
  'vectorize',
  'workflows',
] as const;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasEntries(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  if (isRecord(value)) return Object.values(value).some(hasEntries);
  return (
    value !== undefined && value !== null && value !== false && value !== ''
  );
}

export function inspectDeploymentConfig(
  config: UnknownRecord,
  input: DeploymentGuardInput,
): DeploymentGuardDecision {
  const reasons: string[] = [];

  if (!input.freeTierVerified)
    reasons.push('The Cloudflare Free plan was not verified for this run.');
  if (
    !Number.isFinite(input.estimatedMonthlyCost) ||
    input.estimatedMonthlyCost !== 0
  ) {
    reasons.push('The estimated monthly cost must be exactly $0.00.');
  }

  for (const key of DISALLOWED_ARRAY_BINDINGS) {
    if (hasEntries(config[key]))
      reasons.push(`The generated config enables ${key}.`);
  }

  for (const key of [
    'ai',
    'browser',
    'cloudchamber',
    'containers',
    'durable_objects',
    'limits',
    'queues',
    'send_email',
  ]) {
    if (hasEntries(config[key]))
      reasons.push(`The generated config enables ${key}.`);
  }

  const databases = Array.isArray(config.d1_databases)
    ? config.d1_databases
    : [];
  if (databases.length !== 1) {
    reasons.push('Exactly one D1 database binding is required.');
  } else {
    const database = isRecord(databases[0]) ? databases[0] : {};
    if (database.binding !== 'DB')
      reasons.push('The D1 binding must be named DB.');
    if (database.database_id !== input.expectedD1DatabaseId) {
      reasons.push('The generated config points at an unexpected D1 database.');
    }
  }

  return { allowed: reasons.length === 0, reasons };
}
