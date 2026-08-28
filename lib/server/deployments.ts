import { env } from 'cloudflare:workers';

import { createId } from '@/lib/crypto';
import type { Deployment, DeploymentState } from '@/lib/domain';
import { hasGithubToken } from '@/lib/integrations';
import { runtimeEnv } from './env';
import { createSmartDeployPlan, type DeployTarget, type SmartDeployPlan } from '@/lib/smart-deploy';
import { count, execute, query, queryOne } from './db';
import { inspectRepository, latestCommit } from './github';
import { writeLog } from './logs';
import { createProject, findProjectByName, projectNameFromRepository, setProjectStatus } from './projects';

/**
 * Deployment records.
 *
 * A recorded deployment describes a plan that passed the cost guard; it does
 * not claim the code was shipped. Pushing an artifact needs the Wrangler
 * toolchain, which a Worker cannot run, so the state machine stops at
 * `planned` and says so rather than reporting a success that never happened.
 */

export type { Deployment, DeploymentState };

export type DeploymentWithPlan = Deployment & { plan: SmartDeployPlan };

type DeploymentRow = Omit<Deployment, 'zeroModeEnabled'> & {
  zeroModeEnabled: number;
  plan?: string;
};

function toDeployment(row: DeploymentRow): Deployment {
  const { plan: _plan, zeroModeEnabled, ...rest } = row;
  return { ...rest, zeroModeEnabled: zeroModeEnabled === 1 };
}

const COLUMNS = `id, projectId, repository, target, framework, commitSha, state, durationMs,
  estimatedMonthlyCost, zeroModeEnabled, createdAt, finishedAt`;

export async function listDeployments(workspaceId: string, limit = 50): Promise<Deployment[]> {
  const rows = await query<DeploymentRow>(
    `SELECT ${COLUMNS} FROM deployment WHERE workspaceId = ? ORDER BY createdAt DESC LIMIT ?`,
    workspaceId,
    Math.min(200, Math.max(1, limit)),
  );
  return rows.map(toDeployment);
}

export async function getDeployment(
  workspaceId: string,
  id: string,
): Promise<DeploymentWithPlan | null> {
  const row = await queryOne<DeploymentRow>(
    `SELECT ${COLUMNS}, plan FROM deployment WHERE workspaceId = ? AND id = ?`,
    workspaceId,
    id,
  );
  if (!row) return null;
  return { ...toDeployment(row), plan: JSON.parse(row.plan ?? '{}') as SmartDeployPlan };
}

export async function countDeployments(workspaceId: string): Promise<number> {
  return count('SELECT COUNT(*) AS total FROM deployment WHERE workspaceId = ?', workspaceId);
}

/** Planned resources that carried a projected charge. Feeds YSD Shield. */
export async function countBillableResources(workspaceId: string): Promise<number> {
  return count(
    'SELECT COUNT(*) AS total FROM deployment WHERE workspaceId = ? AND estimatedMonthlyCost > 0',
    workspaceId,
  );
}

export type PlanRequest = {
  workspaceId: string;
  actor: string;
  repository: string;
  target: DeployTarget;
  /** Read from the workspace row, never from the request body. */
  zeroModeEnabled: boolean;
};

export type PlanOutcome = {
  plan: SmartDeployPlan;
  deployment: Deployment;
};

/**
 * Analyses a repository, applies the cost guard, and records the result.
 *
 * A blocked plan is stored too. Refusals are the interesting half of an audit
 * trail, and hiding them would make the log look like nothing was attempted.
 */
export async function planDeployment(request: PlanRequest): Promise<PlanOutcome> {
  const startedAt = Date.now();
  const token = hasGithubToken(runtimeEnv) ? env.GITHUB_TOKEN : undefined;

  const signals = await inspectRepository(request.repository, token);
  const plan = createSmartDeployPlan(
    request.repository,
    request.target,
    request.zeroModeEnabled,
    signals ?? undefined,
  );

  const commitSha = (await latestCommit(request.repository, token)) ?? 'unknown';
  const allowed = plan.protection.allowed;

  // Only a plan that cleared the guard earns a project. A blocked plan should
  // not leave scaffolding behind in the workspace.
  let projectId: string | null = null;
  if (allowed) {
    const name = projectNameFromRepository(request.repository);
    const existing = await findProjectByName(request.workspaceId, name);
    if (existing) {
      projectId = existing.id;
    } else {
      const created = await createProject({
        workspaceId: request.workspaceId,
        actor: request.actor,
        name,
        repository: request.repository,
        framework: plan.framework,
      });
      if (created.ok) projectId = created.project.id;
    }
    if (projectId) await setProjectStatus(request.workspaceId, projectId, 'live');
  }

  const finishedAt = Date.now();
  const deployment: Deployment = {
    id: createId('dpl'),
    projectId,
    repository: request.repository,
    target: request.target,
    framework: plan.framework,
    commitSha,
    state: allowed ? 'planned' : 'blocked',
    durationMs: finishedAt - startedAt,
    estimatedMonthlyCost: plan.protection.estimatedMonthlyCost,
    zeroModeEnabled: request.zeroModeEnabled,
    createdAt: startedAt,
    finishedAt,
  };

  await execute(
    `INSERT INTO deployment (id, workspaceId, projectId, repository, target, framework, commitSha,
       state, durationMs, estimatedMonthlyCost, zeroModeEnabled, plan, createdAt, finishedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    deployment.id,
    request.workspaceId,
    deployment.projectId,
    deployment.repository,
    deployment.target,
    deployment.framework,
    deployment.commitSha,
    deployment.state,
    deployment.durationMs,
    deployment.estimatedMonthlyCost,
    deployment.zeroModeEnabled ? 1 : 0,
    JSON.stringify(plan),
    deployment.createdAt,
    deployment.finishedAt,
  );

  await writeLog({
    workspaceId: request.workspaceId,
    level: allowed ? 'INFO' : 'WARN',
    source: 'deployment',
    message: allowed
      ? `Plan accepted for ${request.repository} · ${plan.framework} on ${plan.resources[0]?.provider ?? 'Cloudflare'}`
      : `Plan blocked for ${request.repository} · ${plan.protection.reason}`,
    actor: request.actor,
    resource: deployment.id,
  });

  return { plan, deployment };
}
