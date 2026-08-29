/**
 * Zero Mode: the cost guard every deployment plan passes through.
 *
 * The rule is deliberately blunt. A plan is only allowed when every resource
 * in it is both free-tier eligible and projected at exactly zero. There is no
 * budget, no threshold, and no override that lets a charge through: an
 * operator who wants a paid resource has to turn the guard off first, and that
 * decision is recorded rather than assumed.
 */

export type ResourceKind =
  | 'compute'
  | 'database'
  | 'storage'
  | 'network'
  | 'ai';

export type PlannedResource = {
  name: string;
  provider: string;
  kind: ResourceKind;
  estimatedMonthlyCost: number;
  freeTierEligible: boolean;
  /** Why this resource stays inside a free allowance. */
  note?: string;
};

export type ZeroModeDecision = {
  allowed: boolean;
  estimatedMonthlyCost: number;
  blockedResources: PlannedResource[];
  reason: string;
};

export function enforceZeroMode(
  resources: PlannedResource[],
  enabled = true,
): ZeroModeDecision {
  const estimatedMonthlyCost = resources.reduce(
    (total, resource) => total + resource.estimatedMonthlyCost,
    0,
  );

  if (!enabled) {
    return {
      allowed: true,
      estimatedMonthlyCost,
      blockedResources: [],
      reason: 'Zero Mode is disabled; the cost estimate is informational.',
    };
  }

  const blockedResources = resources.filter(
    (resource) =>
      resource.estimatedMonthlyCost > 0 || !resource.freeTierEligible,
  );
  const allowed = blockedResources.length === 0 && estimatedMonthlyCost === 0;

  return {
    allowed,
    estimatedMonthlyCost,
    blockedResources,
    reason: allowed
      ? 'Plan verified: every resource is free-tier eligible.'
      : `Blocked ${blockedResources.length} billable resource${blockedResources.length === 1 ? '' : 's'}.`,
  };
}

/**
 * The same guard applied to a single resource, for callers that build a plan
 * incrementally and want to reject a bad addition at the point it is made.
 */
export function isZeroCost(resource: PlannedResource): boolean {
  return resource.estimatedMonthlyCost === 0 && resource.freeTierEligible;
}

/**
 * Free-tier resources the planner is allowed to reach for.
 *
 * Keeping the catalog here rather than inline in the planner means a resource
 * cannot enter a plan without a reviewer seeing its cost claim.
 */
export const ZERO_COST_RESOURCES = {
  cloudflareWorker: {
    name: 'Cloudflare Worker',
    provider: 'Cloudflare',
    kind: 'compute',
    estimatedMonthlyCost: 0,
    freeTierEligible: true,
    note: '100,000 requests per day on the free plan',
  },
  cloudflareD1: {
    name: 'Cloudflare D1 database',
    provider: 'Cloudflare',
    kind: 'database',
    estimatedMonthlyCost: 0,
    freeTierEligible: true,
    note: '5 GB storage and 5 million reads per day on the free plan',
  },
  cloudflareR2: {
    name: 'Cloudflare R2 bucket',
    provider: 'Cloudflare',
    kind: 'storage',
    estimatedMonthlyCost: 0,
    freeTierEligible: true,
    note: 'Private Standard bucket; app guard stops at 1 GB and 5% of monthly operations',
  },
  cloudflarePages: {
    name: 'Cloudflare static assets',
    provider: 'Cloudflare',
    kind: 'network',
    estimatedMonthlyCost: 0,
    freeTierEligible: true,
    note: 'Unlimited static requests',
  },
  userOwnedAiCompute: {
    name: 'User-owned AI compute node',
    provider: 'Local machine',
    kind: 'ai',
    estimatedMonthlyCost: 0,
    freeTierEligible: true,
    note: 'Inference runs on hardware the workspace operator already owns; Cloudflare is only the D1-backed control plane',
  },
} as const satisfies Record<string, PlannedResource>;
