import { enforceZeroMode, type PlannedResource, type ZeroModeDecision } from './zero-mode.ts';

export type DeployTarget = 'auto' | 'cloudflare' | 'supabase' | 'gpu';

export type SmartDeployPlan = {
  id: string;
  repository: string;
  framework: 'Next.js' | 'Vite' | 'Node.js';
  target: DeployTarget;
  steps: string[];
  resources: PlannedResource[];
  protection: ZeroModeDecision;
};

function detectFramework(repository: string): SmartDeployPlan['framework'] {
  if (repository.toLowerCase().includes('api')) return 'Node.js';
  if (repository.toLowerCase().includes('playground')) return 'Vite';
  return 'Next.js';
}

export function createSmartDeployPlan(
  repository: string,
  target: DeployTarget,
  zeroModeEnabled: boolean,
): SmartDeployPlan {
  const normalizedTarget = target === 'auto' ? 'cloudflare' : target;
  const resources: PlannedResource[] =
    normalizedTarget === 'gpu'
      ? [
          {
            name: 'GPU inference worker',
            provider: 'External GPU',
            kind: 'ai',
            estimatedMonthlyCost: 18,
            freeTierEligible: false,
          },
        ]
      : normalizedTarget === 'supabase'
        ? [
            {
              name: 'Supabase project',
              provider: 'Supabase',
              kind: 'database',
              estimatedMonthlyCost: 0,
              freeTierEligible: true,
            },
          ]
        : [
            {
              name: 'Cloudflare Worker',
              provider: 'Cloudflare',
              kind: 'compute',
              estimatedMonthlyCost: 0,
              freeTierEligible: true,
            },
          ];

  return {
    id: `plan_${repository.replace(/[^a-z0-9]/gi, '_').toLowerCase()}`,
    repository,
    framework: detectFramework(repository),
    target,
    steps: ['Inspect repository', 'Resolve zero-cost resources', 'Build artifact', 'Run health checks'],
    resources,
    protection: enforceZeroMode(resources, zeroModeEnabled),
  };
}
