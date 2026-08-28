import {
  enforceZeroMode,
  ZERO_COST_RESOURCES,
  type PlannedResource,
  type ZeroModeDecision,
} from './zero-mode.ts';

export type DeployTarget = 'auto' | 'cloudflare' | 'supabase' | 'gpu';

export type Framework = 'Next.js' | 'Vite' | 'Node.js' | 'Static';

/**
 * What the analyser learned about a repository.
 *
 * When a GitHub token is configured these come from the repository itself;
 * without one the planner falls back to the repository name alone and says so
 * in `confidence`.
 */
export type RepositorySignals = {
  /** Dependency names from a discovered manifest. */
  dependencies?: string[];
  /** Paths seen at the repository root. */
  files?: string[];
};

export type SmartDeployPlan = {
  id: string;
  repository: string;
  framework: Framework;
  confidence: 'inspected' | 'inferred';
  target: DeployTarget;
  steps: string[];
  resources: PlannedResource[];
  protection: ZeroModeDecision;
};

/**
 * Picks a framework from real repository signals when they exist, and from the
 * repository name when they do not. Name matching is a guess, so the plan
 * reports it as `inferred` rather than presenting it as fact.
 */
export function detectFramework(repository: string, signals?: RepositorySignals): Framework {
  const dependencies = new Set(signals?.dependencies ?? []);
  const files = new Set(signals?.files ?? []);

  if (dependencies.has('next') || dependencies.has('vinext')) return 'Next.js';
  if (dependencies.has('vite') || files.has('vite.config.ts') || files.has('vite.config.js')) {
    return 'Vite';
  }
  if (files.has('index.html') && dependencies.size === 0) return 'Static';
  if (dependencies.has('express') || dependencies.has('hono') || dependencies.has('fastify')) {
    return 'Node.js';
  }

  const name = repository.toLowerCase();
  if (name.includes('api')) return 'Node.js';
  if (name.includes('playground')) return 'Vite';
  if (name.includes('docs') || name.includes('site')) return 'Static';
  return 'Next.js';
}

function resourcesFor(target: Exclude<DeployTarget, 'auto'>, framework: Framework): PlannedResource[] {
  if (target === 'gpu') {
    // Kept in the catalog on purpose: the planner must be able to describe a
    // paid option so Zero Mode has something real to reject.
    return [
      {
        name: 'GPU inference worker',
        provider: 'External GPU',
        kind: 'ai',
        estimatedMonthlyCost: 18,
        freeTierEligible: false,
      },
    ];
  }

  if (target === 'supabase') {
    return [{ ...ZERO_COST_RESOURCES.supabaseProject }];
  }

  const resources: PlannedResource[] = [{ ...ZERO_COST_RESOURCES.cloudflareWorker }];
  if (framework === 'Next.js' || framework === 'Node.js') {
    resources.push({ ...ZERO_COST_RESOURCES.cloudflareD1 });
  }
  if (framework === 'Static' || framework === 'Vite') {
    resources.push({ ...ZERO_COST_RESOURCES.cloudflarePages });
  }
  return resources;
}

function stepsFor(framework: Framework, target: Exclude<DeployTarget, 'auto'>): string[] {
  const build = framework === 'Static' ? 'Collect static assets' : 'Build artifact';
  return [
    'Inspect repository',
    'Resolve zero-cost resources',
    build,
    target === 'cloudflare' ? 'Upload to Cloudflare' : `Provision on ${target}`,
    'Run health checks',
  ];
}

export function createSmartDeployPlan(
  repository: string,
  target: DeployTarget,
  zeroModeEnabled: boolean,
  signals?: RepositorySignals,
): SmartDeployPlan {
  const normalizedTarget = target === 'auto' ? 'cloudflare' : target;
  const framework = detectFramework(repository, signals);
  const resources = resourcesFor(normalizedTarget, framework);

  return {
    id: `plan_${repository.replace(/[^a-z0-9]/gi, '_').toLowerCase()}`,
    repository,
    framework,
    confidence: signals?.dependencies || signals?.files ? 'inspected' : 'inferred',
    target,
    steps: stepsFor(framework, normalizedTarget),
    resources,
    protection: enforceZeroMode(resources, zeroModeEnabled),
  };
}
