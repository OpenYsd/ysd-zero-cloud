import type {
  AppEnvironment,
  AppFramework,
  RepositoryAnalysis,
  SafeBuildContract,
} from './app-runtime.ts';
import {
  enforceZeroMode,
  ZERO_COST_RESOURCES,
  type PlannedResource,
  type ZeroModeDecision,
} from './zero-mode.ts';

export type DeployTarget = 'user-node';
export type Framework = AppFramework;

export type RepositorySource = {
  owner: string;
  repository: string;
  branch: string;
  commit: string;
  visibility: 'public';
};

export type SmartDeployPlan = {
  id: string;
  repository: string;
  source: RepositorySource;
  framework: Framework;
  confidence: 'inspected';
  target: DeployTarget;
  nodeId: string;
  nodeName: string;
  environment: AppEnvironment;
  exposure: 'private';
  localAddress: string;
  healthPath: string;
  steps: string[];
  resources: PlannedResource[];
  protection: ZeroModeDecision;
  analysis: RepositoryAnalysis;
  contract: SafeBuildContract | null;
  blockedReasons: string[];
};

export function detectFramework(
  _repository: string,
  signals?: { dependencies?: string[] },
): Framework {
  const dependencies = new Set(signals?.dependencies ?? []);
  if (dependencies.has('next') || dependencies.has('vinext')) return 'Next.js';
  if (dependencies.has('vite')) return 'Vite';
  if (dependencies.has('@nestjs/core')) return 'NestJS';
  if (dependencies.has('express')) return 'Express';
  if (dependencies.has('fastify')) return 'Fastify';
  return 'Node.js';
}

export function createSmartDeployPlan(input: {
  repository: string;
  source: RepositorySource;
  nodeId: string;
  nodeName: string;
  environment: AppEnvironment;
  port: number;
  healthPath: string;
  analysis: RepositoryAnalysis;
  zeroModeEnabled?: boolean;
}): SmartDeployPlan {
  const resources: PlannedResource[] = [
    {
      ...ZERO_COST_RESOURCES.cloudflareWorker,
      note: 'Existing control plane only; no application build or runtime executes here',
    },
    {
      ...ZERO_COST_RESOURCES.cloudflareD1,
      note: 'Existing bounded deployment metadata only; no source or artifact bytes are stored',
    },
    { ...ZERO_COST_RESOURCES.userOwnedAppCompute },
  ];
  const protection = enforceZeroMode(resources, true);
  const blockedReasons = [...input.analysis.blockedReasons];
  if (input.zeroModeEnabled === false) {
    blockedReasons.push(
      'App Runtime requires Zero Mode; the attempted override was ignored.',
    );
  }
  return {
    id: `plan_${input.source.commit.slice(0, 24)}`,
    repository: input.repository,
    source: input.source,
    framework: input.analysis.framework,
    confidence: 'inspected',
    target: 'user-node',
    nodeId: input.nodeId,
    nodeName: input.nodeName,
    environment: input.environment,
    exposure: 'private',
    localAddress: `http://127.0.0.1:${input.port}`,
    healthPath: input.healthPath,
    steps: [
      'Pin GitHub source commit',
      'Verify manifest, lockfile, scripts, and registry policy',
      'Lease the existing signed Compute Node queue',
      'Download and checksum a bounded GitHub archive',
      'Install from the frozen lockfile with lifecycle hooks disabled',
      'Start a fixed Node.js entrypoint in the private sandbox',
      'Verify a localhost-only health check',
      'Record the verified local artifact and deployment state',
    ],
    resources,
    protection: {
      ...protection,
      allowed: protection.allowed && blockedReasons.length === 0,
      reason:
        blockedReasons.length === 0
          ? 'Zero Mode verified: control plane metadata is free and compute stays on the selected user-owned node.'
          : blockedReasons.join(' '),
    },
    analysis: input.analysis,
    contract: input.analysis.contract,
    blockedReasons,
  };
}
