/** Deployment-time Zero Mode checks for the generated Wrangler configuration. */

type UnknownRecord = Record<string, unknown>;

export type DeploymentGuardInput = {
  freeTierVerified: boolean;
  estimatedMonthlyCost: number;
  expectedD1DatabaseId: string;
  /** Empty until R2 is enabled; otherwise the one private bucket permitted. */
  expectedR2BucketName?: string;
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
  'secrets_store_secrets',
  'services',
  'vectorize',
  'workflows',
  'dispatch_namespaces',
  'mtls_certificates',
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
    'routes',
    'route',
  ]) {
    if (hasEntries(config[key]))
      reasons.push(`The generated config enables ${key}.`);
  }

  const triggers = isRecord(config.triggers) ? config.triggers : {};
  const crons = Array.isArray(triggers.crons) ? triggers.crons : [];
  if (
    Object.keys(triggers).some((key) => key !== 'crons') ||
    crons.length !== 1 ||
    crons[0] !== '* * * * *'
  ) {
    reasons.push(
      'Phase 9 requires exactly one reviewed one-minute Cron Trigger on the existing Worker.',
    );
  }

  const vars = isRecord(config.vars) ? config.vars : {};
  const attestation = {
    transport: vars.YSD_PUBLIC_TRANSPORT_MODE,
    plan: vars.YSD_CLOUDFLARE_PLAN,
    billing: vars.YSD_BILLING_STATE,
    zones: vars.YSD_OWNED_ZONE_COUNT,
    tunnels: vars.YSD_TUNNEL_COUNT,
  };
  if (
    attestation.transport !== 'unavailable-zero-mode' ||
    attestation.plan !== 'workers-free' ||
    attestation.billing !== 'no-payment-method' ||
    attestation.zones !== '0' ||
    attestation.tunnels !== '0'
  ) {
    reasons.push(
      'Public transport must remain unavailable under the verified Workers Free, no-zone, no-tunnel account state.',
    );
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

  const buckets = Array.isArray(config.r2_buckets) ? config.r2_buckets : [];
  const expectedBucket = input.expectedR2BucketName?.trim() ?? '';
  if (!expectedBucket && buckets.length > 0) {
    reasons.push(
      'The generated config enables an R2 bucket without a Zero Mode attestation.',
    );
  } else if (expectedBucket) {
    if (buckets.length !== 1) {
      reasons.push('Exactly one private R2 bucket binding is required.');
    } else {
      const bucket = isRecord(buckets[0]) ? buckets[0] : {};
      if (bucket.binding !== 'STORAGE')
        reasons.push('The R2 binding must be named STORAGE.');
      if (bucket.bucket_name !== expectedBucket) {
        reasons.push('The generated config points at an unexpected R2 bucket.');
      }
    }
  }

  return { allowed: reasons.length === 0, reasons };
}
