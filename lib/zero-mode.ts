export type PlannedResource = {
  name: string;
  provider: string;
  kind: 'compute' | 'database' | 'storage' | 'network' | 'ai';
  estimatedMonthlyCost: number;
  freeTierEligible: boolean;
};

export type ZeroModeDecision = {
  allowed: boolean;
  estimatedMonthlyCost: number;
  blockedResources: PlannedResource[];
  reason: string;
};

export function enforceZeroMode(resources: PlannedResource[], enabled = true): ZeroModeDecision {
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
    (resource) => resource.estimatedMonthlyCost > 0 || !resource.freeTierEligible,
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
