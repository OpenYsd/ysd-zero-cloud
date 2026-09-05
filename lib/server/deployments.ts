import { env } from 'cloudflare:workers';

import {
  APP_RUNTIME_JOB_TYPE,
  APP_RUNTIME_LIMITS,
  type AppEnvironment,
  type AppRuntimeOperation,
} from '@/lib/app-runtime';
import { createId, decryptSecret, sha256Hex } from '@/lib/crypto';
import type {
  AppArtifact,
  AppDeploymentAction,
  AppDeploymentLog,
  Deployment,
  DeploymentState,
} from '@/lib/domain';
import { hasGithubToken } from '@/lib/integrations';
import {
  deriveNodeStatus,
  parseCapabilities,
  sealNodeEnvironment,
  stableJson,
} from '@/lib/nodes';
import { deploymentBlockers } from '@/lib/node-preflight';
import {
  evaluateRollbackEligibility,
  rollbackReasonMessage,
  type RollbackReasonCode,
} from '@/lib/releases';
import { createSmartDeployPlan, type SmartDeployPlan } from '@/lib/smart-deploy';
import { authSecret } from './auth';
import { count, db, execute, query, queryOne } from './db';
import { runtimeEnv } from './env';
import { inspectRepositoryForDeploy } from './github';
import { writeLog } from './logs';
import { enqueueJob, type WorkflowJobContext } from './nodes';
import { recordAppRuntimeSecurityEvent } from './app-runtime-control';
import { assertResourceCapacity } from './organization-limits';
import {
  createProject,
  findProjectByName,
  getProject,
  projectNameFromRepository,
  setProjectStatus,
} from './projects';
import { emitWorkflowEvent } from './workflow-events';

export type { Deployment, DeploymentState };

export type DeploymentDetail = Deployment & {
  plan: SmartDeployPlan;
  actions: AppDeploymentAction[];
  artifacts: AppArtifact[];
  logs: AppDeploymentLog[];
};

type DeploymentRow = Omit<Deployment, 'zeroModeEnabled' | 'crashLoop' | 'nodeName'> & {
  zeroModeEnabled: number;
  crashLoop: number;
  nodeName: string | null;
  plan?: string;
};

type DeployNodeRow = {
  id: string;
  name: string;
  capabilities: string;
  tokenCiphertext: string;
  lastHeartbeatAt: number | null;
  revokedAt: number | null;
  agentVersion: string | null;
  protocolVersion: number | null;
};

const SELECT = `d.id, d.projectId, d.repository, d.target, d.framework, d.commitSha,
  d.branch, d.environment, d.nodeId, n.name AS nodeName, d.jobId,
  d.currentArtifactId, d.localPort, d.localAddress, d.exposure, d.observedBind,
  d.healthPath, d.state, d.durationMs, d.buildDurationMs, d.estimatedMonthlyCost,
  d.zeroModeEnabled, d.restartCount, d.crashLoop, d.lastError, d.createdAt,
  d.startedAt, COALESCE(d.updatedAt, d.createdAt) AS updatedAt, d.finishedAt,
  d.deletedAt`;

function toDeployment(row: DeploymentRow): Deployment {
  return {
    ...row,
    target: row.target,
    environment:
      row.environment === 'Preview' || row.environment === 'Development'
        ? row.environment
        : 'Production',
    exposure: 'private',
    observedBind:
      row.observedBind === '127.0.0.1' || row.observedBind === '0.0.0.0'
        ? row.observedBind
        : 'unknown',
    zeroModeEnabled: row.zeroModeEnabled === 1,
    crashLoop: row.crashLoop === 1,
  };
}

function credentialKey(): string {
  return env.YSD_SECRETS_KEY?.trim() || authSecret();
}

function parseNodeCapabilities(value: string) {
  try {
    return parseCapabilities(JSON.parse(value) as unknown);
  } catch {
    return null;
  }
}

async function deploymentNode(workspaceId: string, nodeId: string): Promise<
  | { ok: true; row: DeployNodeRow; token: string }
  | { ok: false; status: number; error: string }
> {
  const row = await queryOne<DeployNodeRow>(
    `SELECT id, name, capabilities, tokenCiphertext, lastHeartbeatAt, revokedAt,
            agentVersion, protocolVersion
     FROM compute_node WHERE workspaceId = ? AND id = ?`,
    workspaceId,
    nodeId,
  );
  if (!row) return { ok: false, status: 404, error: 'The selected Compute Node was not found.' };
  const status = deriveNodeStatus({ revokedAt: row.revokedAt, lastHeartbeatAt: row.lastHeartbeatAt, now: Date.now() });
  if (status !== 'online') return { ok: false, status: 409, error: `The selected Compute Node is ${status}.` };
  const capabilities = parseNodeCapabilities(row.capabilities);
  if (!capabilities?.contracts.appRuntime || !capabilities.appRuntime?.available) {
    return { ok: false, status: 409, error: 'The selected node does not advertise the secure App Runtime contract.' };
  }

  // The same evaluator the preflight UI uses, re-run where it is
  // authoritative. A browser cannot skip this by claiming preflight passed.
  //
  // It also closes something the heartbeat could not. An agent below the
  // minimum version is refused at heartbeat and drifts offline on its own, so
  // the version gate is enforced indirectly. `protocolVersion` is different:
  // it is checked only when the node PAIRS, and the stored value never changes
  // afterwards. Once the control plane moves to protocol 2, a node admitted
  // under protocol 1 would still heartbeat happily and could be handed a job
  // written against a contract it does not speak.
  const blockers = deploymentBlockers({
    belongsToWorkspace: true,
    status,
    agentVersion: row.agentVersion,
    protocolVersion: row.protocolVersion,
    capabilities,
  });
  if (blockers.length > 0) {
    return {
      ok: false,
      status: 409,
      // Check codes from the fixed enum, never node-supplied text.
      error: `The selected Compute Node is not ready to deploy (${blockers.join(', ')}).`,
    };
  }

  try {
    return { ok: true, row, token: await decryptSecret(row.tokenCiphertext, credentialKey()) };
  } catch {
    return { ok: false, status: 503, error: 'The node credential could not be opened.' };
  }
}

async function scopedEnvironment(input: {
  workspaceId: string;
  projectId: string;
  deploymentId: string;
  environment: AppEnvironment;
  names: string[];
}): Promise<Record<string, string>> {
  if (input.names.length === 0) return {};
  const rows = await query<{ name: string; scope: string; ciphertext: string }>(
    `SELECT name, scope, ciphertext FROM secret
     WHERE workspaceId = ? AND environment IN (?, 'All')`,
    input.workspaceId,
    input.environment,
  );
  const allowed = new Set(input.names);
  const scopes = new Set(['Workspace', `Project:${input.projectId}`, `Deployment:${input.deploymentId}`]);
  const values: Record<string, string> = {};
  for (const row of rows) {
    if (!allowed.has(row.name) || !scopes.has(row.scope)) continue;
    values[row.name] = await decryptSecret(row.ciphertext, credentialKey());
  }
  return values;
}

async function nextPort(nodeId: string): Promise<number | null> {
  const rows = await query<{ localPort: number }>(
    `SELECT localPort FROM deployment
     WHERE nodeId = ? AND localPort IS NOT NULL AND deletedAt IS NULL AND state <> 'blocked'`,
    nodeId,
  );
  const used = new Set(rows.map((row) => row.localPort));
  for (let port = APP_RUNTIME_LIMITS.portMinimum; port <= APP_RUNTIME_LIMITS.portMaximum; port += 1) {
    if (!used.has(port)) return port;
  }
  return null;
}

/**
 * How a new release of an existing service is recorded.
 *
 * The wire operation stays `redeploy`, which is exactly what the agent does
 * here: fetch the commit named in the payload, build it, activate it. Agent
 * 0.4.0 validates the operation against a fixed allowlist and the payload
 * against a fixed key allowlist, so inventing a `release` verb or a new field
 * would make every existing node reject the job. What Phase 17 changes is
 * which commit the control plane puts in that payload -- and the action row
 * records the product-level word so history does not have to guess whether a
 * `redeploy` re-ran the same commit or shipped a new one.
 */
export const RELEASE_ACTION_KIND = 'release' as const;

/**
 * The one lookup allowed to resolve a rollback target.
 *
 * Every scope is bound: workspace, project, deployment, node, artifact id. A
 * probe for another tenant's artifact returns nothing here, which the
 * evaluator reports as `artifact_missing` -- the same answer a made-up id
 * gets, so the response cannot be used to discover that a row exists.
 */
async function rollbackTarget(input: {
  workspaceId: string;
  projectId: string;
  deploymentId: string;
  nodeId: string;
  artifactId: string | null;
}): Promise<AppArtifact | null> {
  if (!input.artifactId || !/^art_[a-f0-9]{24}$/.test(input.artifactId)) return null;
  return queryOne<AppArtifact>(
    `SELECT id, deploymentId, projectId, nodeId, version, state, checksum,
            commitSha, sizeBytes, createdAt, verifiedAt, activatedAt
       FROM app_artifact
      WHERE workspaceId = ? AND projectId = ? AND deploymentId = ? AND nodeId = ?
        AND id = ? AND deletedAt IS NULL`,
    input.workspaceId,
    input.projectId,
    input.deploymentId,
    input.nodeId,
    input.artifactId,
  );
}

export async function listDeployments(
  workspaceId: string,
  limit = 50,
  projectIds?: readonly string[] | null,
): Promise<Deployment[]> {
  if (projectIds !== null && projectIds !== undefined && projectIds.length === 0) return [];
  const restricted = projectIds !== null && projectIds !== undefined;
  const rows = await query<DeploymentRow>(
    `SELECT ${SELECT} FROM deployment d LEFT JOIN compute_node n ON n.id = d.nodeId
     WHERE d.workspaceId = ?${restricted ? ` AND d.projectId IN (${(projectIds ?? []).map(() => '?').join(', ')})` : ''}
     ORDER BY d.createdAt DESC LIMIT ?`,
    workspaceId,
    ...(projectIds ?? []),
    Math.min(200, Math.max(1, limit)),
  );
  return rows.map(toDeployment);
}

export async function getDeployment(
  workspaceId: string,
  id: string,
  projectIds?: readonly string[] | null,
): Promise<DeploymentDetail | null> {
  if (projectIds !== null && projectIds !== undefined && projectIds.length === 0) return null;
  const restricted = projectIds !== null && projectIds !== undefined;
  const row = await queryOne<DeploymentRow>(
    `SELECT ${SELECT}, d.plan FROM deployment d LEFT JOIN compute_node n ON n.id = d.nodeId
     WHERE d.workspaceId = ? AND d.id = ?${restricted ? ` AND d.projectId IN (${(projectIds ?? []).map(() => '?').join(', ')})` : ''}`,
    workspaceId,
    id,
    ...(projectIds ?? []),
  );
  if (!row) return null;
  let plan: SmartDeployPlan;
  try {
    plan = JSON.parse(row.plan ?? '{}') as SmartDeployPlan;
  } catch {
    return null;
  }
  const [actions, artifacts, logs] = await Promise.all([
    query<AppDeploymentAction>(
      `SELECT id, deploymentId, projectId, nodeId, jobId, kind, state, error,
              createdAt, updatedAt, completedAt
       FROM app_deployment_action WHERE workspaceId = ? AND deploymentId = ?
       ORDER BY createdAt DESC LIMIT 50`,
      workspaceId,
      id,
    ),
    query<AppArtifact>(
      `SELECT id, deploymentId, projectId, nodeId, commitSha, version, state,
              checksum, sizeBytes, createdAt, verifiedAt, activatedAt
       FROM app_artifact WHERE workspaceId = ? AND deploymentId = ? AND deletedAt IS NULL
       ORDER BY version DESC LIMIT 10`,
      workspaceId,
      id,
    ),
    query<AppDeploymentLog>(
      `SELECT id, deploymentId, nodeId, level, phase, message, createdAt
       FROM app_deployment_log WHERE workspaceId = ? AND deploymentId = ?
       ORDER BY createdAt DESC LIMIT 200`,
      workspaceId,
      id,
    ),
  ]);
  return { ...toDeployment(row), plan, actions, artifacts, logs };
}

export async function countDeployments(
  workspaceId: string,
  projectIds?: readonly string[] | null,
): Promise<number> {
  if (projectIds !== null && projectIds !== undefined) {
    if (projectIds.length === 0) return 0;
    return count(
      `SELECT COUNT(*) AS total FROM deployment
        WHERE workspaceId = ? AND projectId IN (${projectIds.map(() => '?').join(', ')})`,
      workspaceId,
      ...projectIds,
    );
  }
  return count('SELECT COUNT(*) AS total FROM deployment WHERE workspaceId = ?', workspaceId);
}

export async function countBillableResources(workspaceId: string): Promise<number> {
  return count('SELECT COUNT(*) AS total FROM deployment WHERE workspaceId = ? AND estimatedMonthlyCost > 0', workspaceId);
}

export type PlanRequest = {
  workspaceId: string;
  actor: string;
  repository: string;
  branch?: string | null;
  commit?: string | null;
  nodeId: string;
  environment: AppEnvironment;
  healthPath: string;
  memoryMb: number;
  diskQuotaBytes: number;
  idempotencyKey: string | null;
  allowedProjectIds?: readonly string[] | null;
};

export type PlanOutcome =
  | { ok: true; plan: SmartDeployPlan; deployment: Deployment; duplicate: boolean }
  | { ok: false; status: number; error: string; plan?: SmartDeployPlan; deployment?: Deployment };

export async function planDeployment(request: PlanRequest): Promise<PlanOutcome> {
  const workspaceTenant = await queryOne<{ organizationId: string | null }>(
    'SELECT organizationId FROM workspace WHERE id = ? AND archivedAt IS NULL',
    request.workspaceId,
  );
  if (!workspaceTenant?.organizationId) {
    return { ok: false, status: 404, error: 'Organization workspace not found.' };
  }
  let scopedProjectId: string | null = null;
  if (request.allowedProjectIds !== null && request.allowedProjectIds !== undefined) {
    const project = await findProjectByName(
      request.workspaceId,
      projectNameFromRepository(request.repository),
    );
    if (!project || !request.allowedProjectIds.includes(project.id)) {
      return { ok: false, status: 404, error: 'Project not found in this token or member scope.' };
    }
    scopedProjectId = project.id;
  }
  const idempotencyKey = request.idempotencyKey?.trim().slice(0, 128) || null;
  if (idempotencyKey) {
    const duplicate = await queryOne<{ deploymentId: string }>(
      `SELECT deploymentId FROM app_deployment_action WHERE workspaceId = ? AND idempotencyKey = ?`,
      request.workspaceId,
      idempotencyKey,
    );
    if (duplicate) {
      const deployment = await getDeployment(
        request.workspaceId,
        duplicate.deploymentId,
        request.allowedProjectIds,
      );
      if (deployment) return { ok: true, plan: deployment.plan, deployment, duplicate: true };
    }
  }

  const capacity = await assertResourceCapacity(request.workspaceId, 'deployments');
  if (!capacity.ok) return { ok: false, status: 409, error: capacity.error };

  const node = await deploymentNode(request.workspaceId, request.nodeId);
  if (!node.ok) return node;
  const capabilities = parseNodeCapabilities(node.row.capabilities)!;
  if (
    capabilities.memory.freeBytes < request.memoryMb * 1024 ** 2 + APP_RUNTIME_LIMITS.memoryReserveBytes ||
    capabilities.disk.freeBytes < request.diskQuotaBytes + APP_RUNTIME_LIMITS.diskReserveBytes
  ) {
    return { ok: false, status: 409, error: 'The selected node does not have the required free RAM and disk reserve.' };
  }
  if ((capabilities.appRuntime?.activeDeployments ?? 0) >= (capabilities.appRuntime?.maxDeployments ?? 1)) {
    return { ok: false, status: 409, error: 'The selected node reached its App Runtime deployment ceiling.' };
  }
  const recent = await count(
    `SELECT COUNT(*) AS total FROM deployment WHERE workspaceId = ? AND createdAt >= ?`,
    request.workspaceId,
    Date.now() - 60 * 60_000,
  );
  if (recent >= 20) return { ok: false, status: 429, error: 'Suspicious deployment volume was blocked by YSD Shield.' };

  const token = hasGithubToken(runtimeEnv) ? env.GITHUB_TOKEN : undefined;
  const inspection = await inspectRepositoryForDeploy({
    repository: request.repository,
    branch: request.branch,
    commit: request.commit,
    token,
  });
  if (!inspection.ok) return inspection;
  const port = await nextPort(node.row.id);
  if (!port) return { ok: false, status: 409, error: 'The node has no free App Runtime port in the private range.' };
  const startedAt = Date.now();
  const plan = createSmartDeployPlan({
    repository: `${inspection.value.source.owner}/${inspection.value.source.repository}`,
    source: inspection.value.source,
    nodeId: node.row.id,
    nodeName: node.row.name,
    environment: request.environment,
    port,
    healthPath: request.healthPath,
    analysis: inspection.value.analysis,
    zeroModeEnabled: true,
  });
  const deploymentId = createId('dpl');
  if (!plan.protection.allowed || !plan.contract) {
    const now = Date.now();
    for (const reason of plan.blockedReasons.slice(0, 8)) {
      const type = /lifecycle hook/i.test(reason)
        ? 'app-lifecycle-hook'
        : /package-manager configuration|registry|dependency .*approved/i.test(reason)
          ? 'app-unsafe-registry'
          : /submodule|LFS|path|link/i.test(reason)
            ? 'app-path-abuse'
            : /script|start|entrypoint|command/i.test(reason)
              ? 'app-unsafe-script'
              : 'app-source-policy';
      await recordAppRuntimeSecurityEvent({
        workspaceId: request.workspaceId,
        nodeId: node.row.id,
        type,
        severity: type === 'app-source-policy' ? 'high' : 'critical',
        detail: reason,
      });
    }
    await execute(
      `INSERT INTO deployment
       (id, workspaceId, projectId, repository, target, framework, commitSha,
        state, durationMs, estimatedMonthlyCost, zeroModeEnabled, plan, createdAt,
        finishedAt, branch, environment, nodeId, localPort, localAddress,
        exposure, observedBind, healthPath, buildDurationMs, startedAt, updatedAt,
        lastError, restartCount, crashLoop, deletedAt)
       VALUES (?, ?, ?, ?, 'user-node', ?, ?, 'blocked', ?, 0, 1, ?, ?, ?,
               ?, ?, ?, ?, ?, 'private', 'unknown', ?, NULL, NULL, ?, ?, 0, 0, NULL)`,
      deploymentId,
      request.workspaceId,
      scopedProjectId,
      plan.repository,
      plan.framework,
      plan.source.commit,
      now - startedAt,
      JSON.stringify(plan),
      startedAt,
      now,
      plan.source.branch,
      request.environment,
      node.row.id,
      port,
      plan.localAddress,
      request.healthPath,
      now,
      plan.protection.reason,
    );
    await writeLog({
      workspaceId: request.workspaceId,
      source: 'deployment',
      level: 'WARN',
      message: `Smart Deploy blocked · ${plan.protection.reason}`,
      actor: request.actor,
      resource: deploymentId,
    });
    const deployment = (await getDeployment(
      request.workspaceId,
      deploymentId,
      request.allowedProjectIds,
    ))!;
    return { ok: false, status: 409, error: plan.protection.reason, plan, deployment };
  }

  const name = projectNameFromRepository(plan.repository);
  const existing = scopedProjectId
    ? await getProject(request.workspaceId, scopedProjectId)
    : await findProjectByName(request.workspaceId, name);
  let projectId = existing?.id ?? null;
  if (!projectId && (request.allowedProjectIds === null || request.allowedProjectIds === undefined)) {
    const created = await createProject({
      workspaceId: request.workspaceId,
      actor: request.actor,
      name,
      repository: plan.repository,
      framework: plan.framework,
    });
    if (created.ok) projectId = created.project.id;
  }
  if (!projectId) return { ok: false, status: 500, error: 'The deployment project could not be created.' };
  await setProjectStatus(request.workspaceId, projectId, 'building');

  const artifactId = createId('art');
  const actionId = createId('dact');
  const previewExposure = request.environment === 'Preview';
  const exposureRouteId = previewExposure
    ? `pvw_${(await sha256Hex(`preview|${workspaceTenant.organizationId}|${request.workspaceId}|${projectId}|${deploymentId}`)).slice(0, 24)}`
    : createId('route');
  const exposureId = createId('exp');
  const version = (await queryOne<{ version: number }>(
    `SELECT COALESCE(MAX(version), 0) + 1 AS version FROM app_artifact WHERE workspaceId = ? AND projectId = ? AND nodeId = ?`,
    request.workspaceId,
    projectId,
    node.row.id,
  ))?.version ?? 1;
  const environment = await scopedEnvironment({
    workspaceId: request.workspaceId,
    projectId,
    deploymentId,
    environment: request.environment,
    names: plan.contract.envNames,
  });
  const environmentCiphertext = await sealNodeEnvironment(node.token, environment);
  await execute(
    `INSERT INTO deployment
     (id, workspaceId, projectId, repository, target, framework, commitSha,
      state, durationMs, estimatedMonthlyCost, zeroModeEnabled, plan, createdAt,
      finishedAt, branch, environment, nodeId, jobId, currentArtifactId,
      localPort, localAddress, exposure, observedBind, healthPath,
      buildDurationMs, startedAt, updatedAt, lastError, restartCount, crashLoop, deletedAt)
     VALUES (?, ?, ?, ?, 'user-node', ?, ?, 'queued', NULL, 0, 1, ?, ?, NULL,
             ?, ?, ?, NULL, NULL, ?, ?, 'private', 'unknown', ?, NULL, NULL, ?, NULL, 0, 0, NULL)`,
    deploymentId,
    request.workspaceId,
    projectId,
    plan.repository,
    plan.framework,
    plan.source.commit,
    JSON.stringify(plan),
    startedAt,
    plan.source.branch,
    request.environment,
    node.row.id,
    port,
    plan.localAddress,
    request.healthPath,
    Date.now(),
  );
  const queued = await enqueueJob({
    workspaceId: request.workspaceId,
    actor: request.actor,
    type: APP_RUNTIME_JOB_TYPE,
    payload: {
      operation: 'deploy',
      deploymentId,
      projectId,
      actionId,
      artifactId,
      targetArtifactId: null,
      source: {
        owner: plan.source.owner,
        repository: plan.source.repository,
        commit: plan.source.commit,
      },
      contract: plan.contract,
      environment: request.environment,
      environmentCiphertext,
      port,
      healthPath: request.healthPath,
      memoryMb: request.memoryMb,
      diskQuotaBytes: request.diskQuotaBytes,
      retainArtifacts: APP_RUNTIME_LIMITS.maximumArtifactsPerProject,
    },
    targetNodeId: node.row.id,
    idempotencyKey: idempotencyKey ? `app:${idempotencyKey}` : `app:deploy:${deploymentId}`,
  });
  if (!queued.ok) {
    await execute(`UPDATE deployment SET state = 'failed', lastError = ?, finishedAt = ?, updatedAt = ? WHERE workspaceId = ? AND id = ?`, queued.error, Date.now(), Date.now(), request.workspaceId, deploymentId);
    return { ok: false, status: queued.status, error: queued.error };
  }
  if (!queued.created) {
    await execute(`DELETE FROM deployment WHERE workspaceId = ? AND id = ?`, request.workspaceId, deploymentId);
    const duplicateAction = idempotencyKey
      ? await queryOne<{ deploymentId: string }>(
          `SELECT deploymentId FROM app_deployment_action WHERE workspaceId = ? AND idempotencyKey = ?`,
          request.workspaceId,
          idempotencyKey,
        )
      : null;
    const duplicate = duplicateAction
      ? await getDeployment(
        request.workspaceId,
        duplicateAction.deploymentId,
        request.allowedProjectIds,
      )
      : null;
    return duplicate
      ? { ok: true, plan: duplicate.plan, deployment: duplicate, duplicate: true }
      : { ok: false, status: 409, error: 'The original idempotent deployment request is still being finalized.' };
  }
  const database = await db();
  await database.batch([
    database.prepare(`UPDATE deployment SET jobId = ?, updatedAt = ? WHERE workspaceId = ? AND id = ?`).bind(queued.job.id, Date.now(), request.workspaceId, deploymentId),
    database.prepare(
      `INSERT INTO app_deployment_action
       (id, workspaceId, deploymentId, projectId, nodeId, jobId, kind, state,
        idempotencyKey, requestedBy, error, createdAt, updatedAt, completedAt)
       VALUES (?, ?, ?, ?, ?, ?, 'deploy', 'queued', ?, ?, NULL, ?, ?, NULL)`,
    ).bind(actionId, request.workspaceId, deploymentId, projectId, node.row.id, queued.job.id, idempotencyKey, request.actor, startedAt, startedAt),
    database.prepare(
      `INSERT INTO app_artifact
       (id, workspaceId, deploymentId, projectId, nodeId, commitSha, version,
        state, manifest, checksum, sizeBytes, createdAt, verifiedAt, activatedAt, deletedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'building', ?, NULL, 0, ?, NULL, NULL, NULL)`,
    ).bind(artifactId, request.workspaceId, deploymentId, projectId, node.row.id, plan.source.commit, version, stableJson({ contract: plan.contract, source: plan.source }), startedAt),
    database.prepare(
      `INSERT INTO public_exposure
       (id, organizationId, workspaceId, projectId, deploymentId, routeId,
        routePath, mode, status, accessPolicy, transport, transportState,
        assignedHostname, targetNodeId, targetArtifactId, healthState,
        tlsState, verificationState, fallbackPolicy, rateLimitEnabled,
        rateLimitPerMinute, ipAllowlist, isPreview, expiresAt, lastRequestAt,
        lastError, createdBy, createdAt, updatedAt, deletedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'private', 'disabled', 'authenticated',
               'none', 'unavailable_zero_mode', NULL, ?, NULL, 'unknown',
               'unavailable', 'not_required', 'none', 1, 60, '[]', ?, ?, NULL,
               NULL, ?, ?, ?, NULL)`,
    ).bind(
      exposureId,
      workspaceTenant.organizationId,
      request.workspaceId,
      projectId,
      deploymentId,
      exposureRouteId,
      `/apps/${exposureRouteId}`,
      node.row.id,
      previewExposure ? 1 : 0,
      previewExposure ? startedAt + 24 * 60 * 60_000 : null,
      request.actor,
      startedAt,
      startedAt,
    ),
  ]);
  await writeLog({
    workspaceId: request.workspaceId,
    source: 'deployment',
    message: `Queued safe Node.js deploy on ${node.row.name} · private localhost only`,
    actor: request.actor,
    resource: deploymentId,
  });
  await emitWorkflowEvent({
    workspaceId: request.workspaceId,
    type: 'deployment.created',
    resourceType: 'deployment',
    resourceId: deploymentId,
    projectId,
    payload: {
      status: 'queued',
      projectId,
      deploymentId,
      nodeId: node.row.id,
      environment: request.environment,
    },
    dedupeKey: `deployment.created:${deploymentId}`,
  }).catch(() => undefined);
  return {
    ok: true,
    plan,
    deployment: (await getDeployment(request.workspaceId, deploymentId, request.allowedProjectIds))!,
    duplicate: false,
  };
}

export async function cancelDeployment(input: {
  workspaceId: string;
  deploymentId: string;
  actor: string;
  allowedProjectIds?: readonly string[] | null;
}): Promise<{ ok: true; state: DeploymentState } | { ok: false; status: number; error: string }> {
  if (input.allowedProjectIds !== null && input.allowedProjectIds !== undefined &&
      input.allowedProjectIds.length === 0) {
    return { ok: false, status: 404, error: 'Deployment not found.' };
  }
  const restricted = input.allowedProjectIds !== null && input.allowedProjectIds !== undefined;
  const row = await queryOne<{ jobId: string | null; state: string; jobState: string | null }>(
    `SELECT d.jobId, d.state, j.state AS jobState FROM deployment d
     LEFT JOIN node_job j ON j.id = d.jobId AND j.workspaceId = d.workspaceId
     WHERE d.workspaceId = ? AND d.id = ?${restricted
       ? ` AND d.projectId IN (${(input.allowedProjectIds ?? []).map(() => '?').join(', ')})`
       : ''}`,
    input.workspaceId,
    input.deploymentId,
    ...(input.allowedProjectIds ?? []),
  );
  if (!row) return { ok: false, status: 404, error: 'Deployment not found.' };
  if (!row.jobId || !['queued', 'building', 'starting', 'restarting', 'rolling_back'].includes(row.state)) {
    return { ok: false, status: 409, error: 'The deployment has no cancellable action.' };
  }
  const now = Date.now();
  const update = await execute(
    `UPDATE node_job SET state = CASE WHEN state = 'queued' THEN 'cancelled' ELSE 'cancelling' END,
       lastError = 'Cancellation requested by the workspace operator.',
       completedAt = CASE WHEN state = 'queued' THEN ? ELSE completedAt END, updatedAt = ?
     WHERE workspaceId = ? AND id = ? AND state IN ('queued','leased')`,
    now,
    now,
    input.workspaceId,
    row.jobId,
  );
  if ((update.meta.changes ?? 0) === 0) return { ok: false, status: 409, error: 'The action is no longer cancellable.' };
  const state: DeploymentState = row.jobState === 'queued' ? 'cancelled' : 'cancelling';
  await execute(`UPDATE deployment SET state = ?, lastError = ?, updatedAt = ?, finishedAt = CASE WHEN ? = 'cancelled' THEN ? ELSE finishedAt END WHERE workspaceId = ? AND id = ?`, state, 'Cancellation requested.', now, state, now, input.workspaceId, input.deploymentId);
  await execute(
    `UPDATE public_exposure SET healthState = 'stale',
            status = CASE WHEN mode = 'private' THEN 'disabled' ELSE 'unavailable_zero_mode' END,
            lastError = 'Deployment cancellation changed lifecycle health; routing is failed closed.', updatedAt = ?
      WHERE workspaceId = ? AND deploymentId = ? AND deletedAt IS NULL`,
    now,
    input.workspaceId,
    input.deploymentId,
  );
  await execute(
    `UPDATE app_deployment_action SET state = ?, error = 'Cancellation requested.', updatedAt = ?,
       completedAt = CASE WHEN ? = 'cancelled' THEN ? ELSE completedAt END
     WHERE workspaceId = ? AND deploymentId = ? AND jobId = ?`,
    state,
    now,
    state,
    now,
    input.workspaceId,
    input.deploymentId,
    row.jobId,
  );
  await writeLog({ workspaceId: input.workspaceId, source: 'deployment', level: 'WARN', message: 'Cancelled App Runtime action', actor: input.actor, resource: input.deploymentId });
  return { ok: true, state };
}

export async function createDeploymentAction(input: {
  workspaceId: string;
  deploymentId: string;
  actor: string;
  operation: Exclude<AppRuntimeOperation, 'deploy'>;
  targetArtifactId?: string | null;
  /**
   * What the caller believed was running. Supplied by the rollback
   * confirmation so a decision made against stale history cannot execute.
   * `undefined` means the caller did not claim to know.
   */
  expectedCurrentArtifactId?: string | null;
  idempotencyKey: string | null;
  allowedProjectIds?: readonly string[] | null;
  workflowContext?: WorkflowJobContext;
}): Promise<
  | { ok: true; action: AppDeploymentAction; deployment: Deployment; duplicate: boolean }
  | { ok: false; status: number; error: string; reasons?: RollbackReasonCode[] }
> {
  const detail = await getDeployment(input.workspaceId, input.deploymentId, input.allowedProjectIds);
  if (!detail || !detail.projectId || !detail.nodeId) return { ok: false, status: 404, error: 'Deployment not found.' };
  if (detail.deletedAt !== null || detail.state === 'blocked') return { ok: false, status: 409, error: 'This deployment cannot accept actions.' };
  // Idempotency is answered before the in-progress guard. A retry carrying the
  // same key is the same request and must resolve to the action already
  // queued; answering "already in progress" would make a retried request
  // indistinguishable from a genuine conflict. A different key during a
  // running action still gets the busy refusal below.
  const key = input.idempotencyKey?.trim().slice(0, 128) || null;
  if (key) {
    const existing = await queryOne<AppDeploymentAction>(
      `SELECT id, deploymentId, projectId, nodeId, jobId, kind, state, error, createdAt, updatedAt, completedAt
       FROM app_deployment_action WHERE workspaceId = ? AND idempotencyKey = ?`,
      input.workspaceId,
      key,
    );
    if (existing) return { ok: true, action: existing, deployment: detail, duplicate: true };
  }
  if (['queued', 'building', 'starting', 'stopping', 'restarting', 'rolling_back', 'deleting', 'cancelling'].includes(detail.state)) {
    return { ok: false, status: 409, error: 'A deployment action is already in progress.' };
  }
  const node = await deploymentNode(input.workspaceId, detail.nodeId);
  if (!node.ok) return node;
  const targetArtifactId = input.operation === 'rollback' ? input.targetArtifactId ?? null : null;
  if (input.operation === 'rollback') {
    // The target must agree with this deployment on every axis -- deployment
    // included. This used to be scoped to workspace, project and node only,
    // which let a sibling service's artifact through the API. The node would
    // then look for those bytes under *this* deployment's directory, where
    // they have never existed, and fail late with an integrity error. The
    // refusal belongs here, before anything is queued.
    const artifact = await rollbackTarget({
      workspaceId: input.workspaceId,
      projectId: detail.projectId,
      deploymentId: detail.id,
      nodeId: detail.nodeId,
      artifactId: targetArtifactId,
    });
    // Node readiness was already proven by `deploymentNode` above, so this
    // call re-checks the artifact and deployment axes only.
    const eligibility = evaluateRollbackEligibility({
      artifact,
      deployment: {
        id: detail.id,
        projectId: detail.projectId,
        nodeId: detail.nodeId,
        state: detail.state,
        currentArtifactId: detail.currentArtifactId,
        deletedAt: detail.deletedAt,
      },
      node: null,
    });
    if (!eligibility.eligible) {
      const [first] = eligibility.reasons;
      return {
        ok: false,
        status: 409,
        error: rollbackReasonMessage(first ?? 'artifact_missing'),
        reasons: eligibility.reasons,
      };
    }
    // Optimistic concurrency. The confirmation told us which release the
    // person was looking at; if something else became current in between,
    // the decision they made no longer describes this deployment.
    if (
      input.expectedCurrentArtifactId !== undefined &&
      input.expectedCurrentArtifactId !== detail.currentArtifactId
    ) {
      return {
        ok: false,
        status: 409,
        error: rollbackReasonMessage('stale_current_release'),
        reasons: ['stale_current_release'],
      };
    }
  }
  let artifactId = detail.currentArtifactId;
  // A redeploy rebuilds the release that is running, which is not always the
  // one the deployment was created from: once a newer release has shipped onto
  // this service, `plan` still describes the original commit. The artifact
  // records the commit and build contract of its own release, so read them
  // from there and fall back to the plan for deployments that never moved.
  let redeploySource = detail.plan.source;
  let redeployContract = detail.plan.contract;
  if (input.operation === 'redeploy') {
    const running = detail.currentArtifactId
      ? await queryOne<{ manifest: string }>(
          `SELECT manifest FROM app_artifact
            WHERE workspaceId = ? AND deploymentId = ? AND id = ? AND deletedAt IS NULL`,
          input.workspaceId,
          detail.id,
          detail.currentArtifactId,
        )
      : null;
    if (running) {
      try {
        const recorded = JSON.parse(running.manifest) as {
          source?: typeof detail.plan.source;
          contract?: typeof detail.plan.contract;
        };
        if (recorded.source) redeploySource = recorded.source;
        if (recorded.contract) redeployContract = recorded.contract;
      } catch {
        // A manifest that will not parse is not a reason to refuse the
        // action; the stored plan is a truthful, if older, description.
      }
    }
    artifactId = createId('art');
  }
  if (['start', 'restart', 'rollback', 'status'].includes(input.operation) && !artifactId && !targetArtifactId) {
    return { ok: false, status: 409, error: 'No verified local artifact is available.' };
  }
  const actionId = createId('dact');
  const environmentValues = await scopedEnvironment({
    workspaceId: input.workspaceId,
    projectId: detail.projectId,
    deploymentId: detail.id,
    environment: detail.environment,
    names: detail.plan.contract?.envNames ?? [],
  });
  const payload = {
    operation: input.operation,
    deploymentId: detail.id,
    projectId: detail.projectId,
    actionId,
    artifactId,
    targetArtifactId,
    source: input.operation === 'redeploy'
      ? { owner: redeploySource.owner, repository: redeploySource.repository, commit: redeploySource.commit }
      : null,
    contract: input.operation === 'redeploy' ? redeployContract : detail.plan.contract,
    environment: detail.environment,
    environmentCiphertext: await sealNodeEnvironment(node.token, environmentValues),
    port: detail.localPort,
    healthPath: detail.healthPath,
    memoryMb: APP_RUNTIME_LIMITS.memoryMinimumMb,
    diskQuotaBytes: APP_RUNTIME_LIMITS.diskMinimumBytes,
    retainArtifacts: APP_RUNTIME_LIMITS.maximumArtifactsPerProject,
  };
  const queued = await enqueueJob({
    workspaceId: input.workspaceId,
    actor: input.actor,
    type: APP_RUNTIME_JOB_TYPE,
    payload,
    targetNodeId: detail.nodeId,
    idempotencyKey: key ? `app:${key}` : `app:${input.operation}:${actionId}`,
    workflowContext: input.workflowContext,
  });
  if (!queued.ok) return queued;
  if (!queued.created && key) {
    const existing = await queryOne<AppDeploymentAction>(
      `SELECT id, deploymentId, projectId, nodeId, jobId, kind, state, error, createdAt, updatedAt, completedAt
       FROM app_deployment_action WHERE workspaceId = ? AND idempotencyKey = ?`,
      input.workspaceId,
      key,
    );
    return existing
      ? { ok: true, action: existing, deployment: detail, duplicate: true }
      : { ok: false, status: 409, error: 'The original idempotent action is still being finalized.' };
  }
  const now = Date.now();
  const desiredState: DeploymentState =
    input.operation === 'stop' ? 'stopping'
      : input.operation === 'restart' ? 'restarting'
        : input.operation === 'rollback' ? 'rolling_back'
          : input.operation === 'delete' ? 'deleting'
            : input.operation === 'redeploy' ? 'building'
              : input.operation === 'start' ? 'starting'
                : detail.state;
  const database = await db();
  const statements: D1PreparedStatement[] = [
    database.prepare(
      `INSERT INTO app_deployment_action
       (id, workspaceId, deploymentId, projectId, nodeId, jobId, kind, state,
        idempotencyKey, requestedBy, error, createdAt, updatedAt, completedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, NULL, ?, ?, NULL)`,
    ).bind(actionId, input.workspaceId, detail.id, detail.projectId, detail.nodeId, queued.job.id, input.operation, key, input.actor, now, now),
    database.prepare(`UPDATE deployment SET state = ?, jobId = ?, lastError = NULL, updatedAt = ? WHERE workspaceId = ? AND id = ?`).bind(desiredState, queued.job.id, now, input.workspaceId, detail.id),
    database.prepare(
      `UPDATE public_exposure SET healthState = 'stale',
              status = CASE WHEN mode = 'private' THEN 'disabled' ELSE 'unavailable_zero_mode' END,
              lastError = 'Deployment lifecycle action is in progress; routing is failed closed.', updatedAt = ?
        WHERE workspaceId = ? AND deploymentId = ? AND deletedAt IS NULL`,
    ).bind(now, input.workspaceId, detail.id),
  ];
  if (input.operation === 'redeploy' && artifactId) {
    const version = (await queryOne<{ version: number }>(
      `SELECT COALESCE(MAX(version), 0) + 1 AS version FROM app_artifact WHERE workspaceId = ? AND projectId = ? AND nodeId = ?`,
      input.workspaceId, detail.projectId, detail.nodeId,
    ))?.version ?? 1;
    statements.push(database.prepare(
      `INSERT INTO app_artifact
       (id, workspaceId, deploymentId, projectId, nodeId, commitSha, version,
        state, manifest, checksum, sizeBytes, createdAt, verifiedAt, activatedAt, deletedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'building', ?, NULL, 0, ?, NULL, NULL, NULL)`,
    ).bind(artifactId, input.workspaceId, detail.id, detail.projectId, detail.nodeId, redeploySource.commit, version, stableJson({ contract: redeployContract, source: redeploySource }), now));
  }
  await database.batch(statements);
  const action = (await queryOne<AppDeploymentAction>(
    `SELECT id, deploymentId, projectId, nodeId, jobId, kind, state, error, createdAt, updatedAt, completedAt
     FROM app_deployment_action WHERE workspaceId = ? AND id = ?`,
    input.workspaceId, actionId,
  ))!;
  await writeLog({ workspaceId: input.workspaceId, source: 'deployment', message: `Queued App Runtime ${input.operation}`, actor: input.actor, resource: detail.id });
  return {
    ok: true,
    action,
    deployment: (await getDeployment(input.workspaceId, detail.id, input.allowedProjectIds))!,
    duplicate: false,
  };
}

/**
 * Ship a new release of an existing service.
 *
 * Smart Deploy still means "stand up a new service", and that stays true --
 * changing it would silently repoint an established product behaviour. This
 * is the other half: keep the deployment, the node, and the private port, and
 * put a newer commit of the same repository on them. That is what turns a
 * deployment into a release line, and it is the only way two artifacts ever
 * come to share a directory on the node, which is what rollback needs.
 *
 * The repository is read from the stored deployment, never from the caller.
 * A caller chooses a branch or commit *within* that repository and it goes
 * through the same inspection Smart Deploy uses, so the Phase 14 source
 * boundary is unchanged: no arbitrary URL, no caller-supplied build command.
 */
export async function createRelease(input: {
  workspaceId: string;
  deploymentId: string;
  actor: string;
  branch?: string | null;
  commit?: string | null;
  idempotencyKey: string | null;
  allowedProjectIds?: readonly string[] | null;
}): Promise<
  | { ok: true; action: AppDeploymentAction; deployment: Deployment; artifactId: string; duplicate: boolean }
  | { ok: false; status: number; error: string }
> {
  const detail = await getDeployment(input.workspaceId, input.deploymentId, input.allowedProjectIds);
  if (!detail || !detail.projectId || !detail.nodeId || !detail.localPort) {
    return { ok: false, status: 404, error: 'Deployment not found.' };
  }
  if (detail.deletedAt !== null || detail.state === 'blocked') {
    return { ok: false, status: 409, error: 'This deployment cannot accept actions.' };
  }
  // Same ordering as the lifecycle actions: a retry with the same key resolves
  // to the release already queued rather than a busy refusal.
  const key = input.idempotencyKey?.trim().slice(0, 128) || null;
  if (key) {
    const existing = await queryOne<AppDeploymentAction>(
      `SELECT id, deploymentId, projectId, nodeId, jobId, kind, state, error, createdAt, updatedAt, completedAt
       FROM app_deployment_action WHERE workspaceId = ? AND idempotencyKey = ?`,
      input.workspaceId,
      key,
    );
    if (existing) {
      return { ok: true, action: existing, deployment: detail, artifactId: '', duplicate: true };
    }
  }
  if (['queued', 'building', 'starting', 'stopping', 'restarting', 'rolling_back', 'deleting', 'cancelling'].includes(detail.state)) {
    return { ok: false, status: 409, error: 'A deployment action is already in progress.' };
  }
  const node = await deploymentNode(input.workspaceId, detail.nodeId);
  if (!node.ok) return node;

  const token = hasGithubToken(runtimeEnv) ? env.GITHUB_TOKEN : undefined;
  const inspection = await inspectRepositoryForDeploy({
    repository: detail.repository,
    branch: input.branch ?? detail.branch,
    commit: input.commit ?? null,
    token,
  });
  if (!inspection.ok) return inspection;

  // The contract is rebuilt from the *new* commit. Reusing the stored one
  // would hand the node a build recipe describing different source.
  const plan = createSmartDeployPlan({
    repository: `${inspection.value.source.owner}/${inspection.value.source.repository}`,
    source: inspection.value.source,
    nodeId: node.row.id,
    nodeName: node.row.name,
    environment: detail.environment,
    port: detail.localPort,
    healthPath: detail.healthPath,
    analysis: inspection.value.analysis,
    zeroModeEnabled: true,
  });
  if (!plan.protection.allowed || !plan.contract) {
    for (const reason of plan.blockedReasons.slice(0, 8)) {
      await recordAppRuntimeSecurityEvent({
        workspaceId: input.workspaceId,
        nodeId: node.row.id,
        type: 'app-source-policy',
        severity: 'high',
        detail: reason,
      });
    }
    return {
      ok: false,
      status: 409,
      error: plan.blockedReasons[0] ?? 'This commit does not satisfy the safe build contract.',
    };
  }
  if (inspection.value.source.commit === detail.commitSha) {
    return {
      ok: false,
      status: 409,
      error: 'That commit is already the current release. Use redeploy to rebuild it.',
    };
  }

  const actionId = createId('dact');
  const artifactId = createId('art');
  const version = (await queryOne<{ version: number }>(
    `SELECT COALESCE(MAX(version), 0) + 1 AS version FROM app_artifact WHERE workspaceId = ? AND projectId = ? AND nodeId = ?`,
    input.workspaceId,
    detail.projectId,
    node.row.id,
  ))?.version ?? 1;
  const environmentValues = await scopedEnvironment({
    workspaceId: input.workspaceId,
    projectId: detail.projectId,
    deploymentId: detail.id,
    environment: detail.environment,
    names: plan.contract.envNames,
  });
  const queued = await enqueueJob({
    workspaceId: input.workspaceId,
    actor: input.actor,
    type: APP_RUNTIME_JOB_TYPE,
    payload: {
      // The verb agent 0.4.0 already speaks: build the commit named in
      // `source` and activate it. Only the commit differs from a redeploy.
      operation: 'redeploy',
      deploymentId: detail.id,
      projectId: detail.projectId,
      actionId,
      artifactId,
      targetArtifactId: null,
      source: {
        owner: plan.source.owner,
        repository: plan.source.repository,
        commit: plan.source.commit,
      },
      contract: plan.contract,
      environment: detail.environment,
      environmentCiphertext: await sealNodeEnvironment(node.token, environmentValues),
      port: detail.localPort,
      healthPath: detail.healthPath,
      memoryMb: APP_RUNTIME_LIMITS.memoryMinimumMb,
      diskQuotaBytes: APP_RUNTIME_LIMITS.diskMinimumBytes,
      retainArtifacts: APP_RUNTIME_LIMITS.maximumArtifactsPerProject,
    },
    targetNodeId: node.row.id,
    idempotencyKey: key ? `app:${key}` : `app:release:${actionId}`,
  });
  if (!queued.ok) return queued;
  if (!queued.created && key) {
    const existing = await queryOne<AppDeploymentAction>(
      `SELECT id, deploymentId, projectId, nodeId, jobId, kind, state, error, createdAt, updatedAt, completedAt
       FROM app_deployment_action WHERE workspaceId = ? AND idempotencyKey = ?`,
      input.workspaceId,
      key,
    );
    return existing
      ? { ok: true, action: existing, deployment: detail, artifactId: '', duplicate: true }
      : { ok: false, status: 409, error: 'The original idempotent action is still being finalized.' };
  }

  const now = Date.now();
  const database = await db();
  await database.batch([
    database.prepare(
      `INSERT INTO app_deployment_action
       (id, workspaceId, deploymentId, projectId, nodeId, jobId, kind, state,
        idempotencyKey, requestedBy, error, createdAt, updatedAt, completedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, NULL, ?, ?, NULL)`,
    ).bind(actionId, input.workspaceId, detail.id, detail.projectId, node.row.id, queued.job.id, RELEASE_ACTION_KIND, key, input.actor, now, now),
    // The artifact carries its own commit and contract from the moment it is
    // created. That record is immutable per release, so history keeps telling
    // the truth about what each release was built from even after the
    // deployment moves on.
    database.prepare(
      `INSERT INTO app_artifact
       (id, workspaceId, deploymentId, projectId, nodeId, commitSha, version,
        state, manifest, checksum, sizeBytes, createdAt, verifiedAt, activatedAt, deletedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'building', ?, NULL, 0, ?, NULL, NULL, NULL)`,
    ).bind(artifactId, input.workspaceId, detail.id, detail.projectId, node.row.id, plan.source.commit, version, stableJson({ contract: plan.contract, source: plan.source }), now),
    // `currentArtifactId` is deliberately untouched here. It moves only when
    // the node reports the new release verified, started and healthy, so a
    // failed release leaves the running one exactly where it was.
    database.prepare(
      `UPDATE deployment SET state = 'building', jobId = ?, lastError = NULL, updatedAt = ?
        WHERE workspaceId = ? AND id = ?`,
    ).bind(queued.job.id, now, input.workspaceId, detail.id),
    database.prepare(
      `UPDATE public_exposure SET healthState = 'stale',
              status = CASE WHEN mode = 'private' THEN 'disabled' ELSE 'unavailable_zero_mode' END,
              lastError = 'Deployment lifecycle action is in progress; routing is failed closed.', updatedAt = ?
        WHERE workspaceId = ? AND deploymentId = ? AND deletedAt IS NULL`,
    ).bind(now, input.workspaceId, detail.id),
  ]);
  const action = (await queryOne<AppDeploymentAction>(
    `SELECT id, deploymentId, projectId, nodeId, jobId, kind, state, error, createdAt, updatedAt, completedAt
     FROM app_deployment_action WHERE workspaceId = ? AND id = ?`,
    input.workspaceId,
    actionId,
  ))!;
  await writeLog({
    workspaceId: input.workspaceId,
    source: 'deployment',
    message: 'Queued a new release',
    actor: input.actor,
    resource: detail.id,
  });
  return {
    ok: true,
    action,
    artifactId,
    deployment: (await getDeployment(input.workspaceId, detail.id, input.allowedProjectIds))!,
    duplicate: false,
  };
}
