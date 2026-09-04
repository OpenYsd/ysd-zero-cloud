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
  idempotencyKey: string | null;
  allowedProjectIds?: readonly string[] | null;
  workflowContext?: WorkflowJobContext;
}): Promise<{ ok: true; action: AppDeploymentAction; deployment: Deployment; duplicate: boolean } | { ok: false; status: number; error: string }> {
  const detail = await getDeployment(input.workspaceId, input.deploymentId, input.allowedProjectIds);
  if (!detail || !detail.projectId || !detail.nodeId) return { ok: false, status: 404, error: 'Deployment not found.' };
  if (detail.deletedAt !== null || detail.state === 'blocked') return { ok: false, status: 409, error: 'This deployment cannot accept actions.' };
  if (['queued', 'building', 'starting', 'stopping', 'restarting', 'rolling_back', 'deleting', 'cancelling'].includes(detail.state)) {
    return { ok: false, status: 409, error: 'A deployment action is already in progress.' };
  }
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
  const node = await deploymentNode(input.workspaceId, detail.nodeId);
  if (!node.ok) return node;
  const targetArtifactId = input.operation === 'rollback' ? input.targetArtifactId ?? null : null;
  if (input.operation === 'rollback') {
    const artifact = await queryOne<{ id: string }>(
      `SELECT id FROM app_artifact WHERE workspaceId = ? AND projectId = ? AND nodeId = ?
       AND id = ? AND state = 'verified' AND deletedAt IS NULL`,
      input.workspaceId,
      detail.projectId,
      detail.nodeId,
      targetArtifactId,
    );
    if (!artifact) return { ok: false, status: 409, error: 'Rollback requires a previously verified artifact on the same node.' };
  }
  let artifactId = detail.currentArtifactId;
  if (input.operation === 'redeploy') artifactId = createId('art');
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
      ? { owner: detail.plan.source.owner, repository: detail.plan.source.repository, commit: detail.plan.source.commit }
      : null,
    contract: detail.plan.contract,
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
    ).bind(artifactId, input.workspaceId, detail.id, detail.projectId, detail.nodeId, detail.commitSha, version, stableJson({ contract: detail.plan.contract, source: detail.plan.source }), now));
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
