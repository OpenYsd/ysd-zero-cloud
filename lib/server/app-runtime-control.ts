import {
  APP_RUNTIME_LIMITS,
  parseAppRuntimeSnapshots,
  redactAppRuntimeCredentials,
  validateAppRuntimeJobPayload,
} from '@/lib/app-runtime';
import { createId } from '@/lib/crypto';
import { type NodeJobState } from '@/lib/nodes';
import { db, execute, queryOne } from './db';
import { writeLog } from './logs';
import { emitWorkflowEvent } from './workflow-events';

type AppJob = {
  id: string;
  workspaceId: string;
  payload: string;
  assignedNodeId: string | null;
  workflowId: string | null;
  workflowExecutionId: string | null;
  workflowCorrelationId: string | null;
  workflowChainDepth: number | null;
};

function integer(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= maximum
    ? value
    : null;
}

function cleanLog(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  let sanitized = '';
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code !== 127)) sanitized += character;
    if (sanitized.length >= 2_000) break;
  }
  const safe = redactAppRuntimeCredentials(sanitized).slice(0, 2_000).trim();
  return safe || null;
}

export async function recordAppRuntimeSecurityEvent(input: {
  workspaceId: string;
  nodeId: string | null;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detail: string;
}): Promise<void> {
  await execute(
    `INSERT INTO node_security_event
     (id, workspaceId, nodeId, type, severity, detail, networkFingerprint, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`,
    createId('nsec'),
    input.workspaceId,
    input.nodeId,
    input.type,
    input.severity,
    input.detail.slice(0, 500),
    Date.now(),
  );
}

export async function recordAppRuntimeJobOutcome(input: {
  job: AppJob;
  state: NodeJobState;
  result: Record<string, unknown> | null;
  error: string | null;
  now: number;
}): Promise<void> {
  let rawPayload: unknown;
  try {
    rawPayload = JSON.parse(input.job.payload);
  } catch {
    return;
  }
  const validated = validateAppRuntimeJobPayload(rawPayload);
  if (!validated.ok) return;
  const payload = validated.payload;
  const successful = input.state === 'succeeded';
  const reportedState = typeof input.result?.state === 'string' ? input.result.state : null;
  const checksum =
    typeof input.result?.checksum === 'string' && /^sha256:[a-f0-9]{64}$/.test(input.result.checksum)
      ? input.result.checksum
      : null;
  const integrityRequired = ['deploy', 'redeploy', 'rollback'].includes(payload.operation);
  const effectiveSuccess = successful && (!integrityRequired || checksum !== null);
  const outcomeState: NodeJobState = successful && !effectiveSuccess ? 'failed' : input.state;
  const outcomeError = successful && !effectiveSuccess
    ? 'The App Runtime artifact completion was unsigned.'
    : input.error;
  const deploymentState = !effectiveSuccess
    ? outcomeState === 'cancelled'
      ? 'cancelled'
      : outcomeState === 'timed_out'
        ? 'timed_out'
        : 'failed'
    : payload.operation === 'stop'
      ? 'stopped'
      : payload.operation === 'delete'
        ? 'deleted'
        : reportedState === 'crash_loop'
          ? 'crash_loop'
          : reportedState === 'stopped'
            ? 'stopped'
            : 'healthy';
  const artifactId =
    payload.operation === 'rollback' ? payload.targetArtifactId : payload.artifactId;
  const observedBind =
    input.result?.bind === '127.0.0.1' || input.result?.bind === '0.0.0.0'
      ? input.result.bind
      : 'unknown';
  const buildDurationMs = integer(input.result?.buildDurationMs, APP_RUNTIME_LIMITS.buildTimeoutMs + 60_000);
  const durationMs = integer(input.result?.deployDurationMs, APP_RUNTIME_LIMITS.buildTimeoutMs + 2 * 60_000);
  const restartCount = integer(input.result?.restartCount, 1_000) ?? 0;
  const crashLoop = input.result?.crashLoop === true;
  const localAddress =
    typeof input.result?.localAddress === 'string' &&
    input.result.localAddress === `http://127.0.0.1:${payload.port}`
      ? input.result.localAddress
      : null;

  const database = await db();
  const statements: D1PreparedStatement[] = [
    database
      .prepare(
        `UPDATE app_deployment_action
         SET state = ?, error = ?, updatedAt = ?, completedAt = ?
         WHERE workspaceId = ? AND id = ? AND jobId = ?`,
      )
      .bind(outcomeState, outcomeError, input.now, input.now, input.job.workspaceId, payload.actionId, input.job.id),
    database
      .prepare(
        `UPDATE deployment
         SET state = ?, currentArtifactId = CASE WHEN ? = 1 THEN COALESCE(?, currentArtifactId) ELSE currentArtifactId END,
             localAddress = CASE WHEN ? = 1 THEN COALESCE(?, localAddress) ELSE localAddress END,
             observedBind = ?, buildDurationMs = COALESCE(?, buildDurationMs),
             durationMs = COALESCE(?, durationMs), restartCount = ?, crashLoop = ?,
             lastError = ?, startedAt = CASE WHEN ? = 'healthy' THEN COALESCE(startedAt, ?) ELSE startedAt END,
             finishedAt = CASE WHEN ? IN ('failed','cancelled','timed_out','deleted') THEN ? ELSE finishedAt END,
             deletedAt = CASE WHEN ? = 'deleted' THEN ? ELSE deletedAt END, updatedAt = ?
         WHERE workspaceId = ? AND id = ? AND jobId = ?`,
      )
      .bind(
        deploymentState,
        effectiveSuccess ? 1 : 0,
        artifactId,
        effectiveSuccess ? 1 : 0,
        localAddress,
        observedBind,
        buildDurationMs,
        durationMs,
        restartCount,
        crashLoop ? 1 : 0,
        outcomeError,
        deploymentState,
        input.now,
        deploymentState,
        input.now,
        deploymentState,
        input.now,
        input.now,
        input.job.workspaceId,
        payload.deploymentId,
        input.job.id,
      ),
    database
      .prepare(`UPDATE project SET status = ?, updatedAt = ? WHERE workspaceId = ? AND id = ?`)
      .bind(deploymentState === 'healthy' ? 'live' : deploymentState === 'failed' || deploymentState === 'crash_loop' ? 'blocked' : 'idle', input.now, input.job.workspaceId, payload.projectId),
    database
      .prepare(
        `UPDATE public_exposure
            SET targetArtifactId = CASE WHEN ? = 1 AND ? IS NOT NULL THEN ? ELSE targetArtifactId END,
                healthState = ?,
                status = CASE WHEN mode = 'private' THEN 'disabled' ELSE 'unavailable_zero_mode' END,
                transport = 'none', transportState = 'unavailable_zero_mode',
                tlsState = 'unavailable', lastError = ?, updatedAt = ?
          WHERE workspaceId = ? AND deploymentId = ? AND deletedAt IS NULL`,
      )
      .bind(
        effectiveSuccess ? 1 : 0,
        artifactId,
        artifactId,
        deploymentState === 'healthy'
          ? 'healthy'
          : deploymentState === 'stopped'
            ? 'offline'
            : 'failed',
        deploymentState === 'healthy'
          ? 'Public transport remains unavailable under Zero Mode.'
          : `Deployment lifecycle changed to ${deploymentState}; routing is failed closed.`,
        input.now,
        input.job.workspaceId,
        payload.deploymentId,
      ),
  ];
  if (artifactId && (payload.operation === 'deploy' || payload.operation === 'redeploy' || payload.operation === 'rollback')) {
    statements.push(
      database
        .prepare(
          `UPDATE app_artifact
           SET state = ?, checksum = COALESCE(?, checksum), sizeBytes = COALESCE(?, sizeBytes),
               verifiedAt = CASE WHEN ? = 1 THEN COALESCE(verifiedAt, ?) ELSE verifiedAt END,
               activatedAt = CASE WHEN ? = 1 THEN ? ELSE activatedAt END
           WHERE workspaceId = ? AND projectId = ? AND nodeId = ? AND id = ? AND deletedAt IS NULL`,
        )
        .bind(
          effectiveSuccess && checksum ? 'verified' : successful ? 'corrupted' : 'failed',
          checksum,
          integer(input.result?.sizeBytes, APP_RUNTIME_LIMITS.diskMaximumBytes),
          effectiveSuccess && checksum ? 1 : 0,
          input.now,
          effectiveSuccess && checksum ? 1 : 0,
          input.now,
          input.job.workspaceId,
          payload.projectId,
          input.job.assignedNodeId,
          artifactId,
        ),
    );
  }
  if (payload.operation === 'delete' && effectiveSuccess) {
    statements.push(
      database
        .prepare(
          `UPDATE app_artifact SET state = 'deleted', deletedAt = ?
           WHERE workspaceId = ? AND deploymentId = ? AND deletedAt IS NULL`,
        )
        .bind(input.now, input.job.workspaceId, payload.deploymentId),
      database
        .prepare(
          `UPDATE exposure_domain
              SET exposureId = NULL, attachState = 'detached', tlsState = 'unavailable',
                  detachedAt = ?, updatedAt = ?
            WHERE workspaceId = ? AND exposureId IN (
              SELECT id FROM public_exposure WHERE workspaceId = ? AND deploymentId = ?
            ) AND deletedAt IS NULL`,
        )
        .bind(input.now, input.now, input.job.workspaceId, input.job.workspaceId, payload.deploymentId),
      database
        .prepare(
          `UPDATE public_exposure
              SET mode = 'private', status = 'deleted', assignedHostname = NULL,
                  healthState = 'failed', tlsState = 'unavailable', deletedAt = ?, updatedAt = ?
            WHERE workspaceId = ? AND deploymentId = ? AND deletedAt IS NULL`,
        )
        .bind(input.now, input.now, input.job.workspaceId, payload.deploymentId),
    );
  }
  const logs = Array.isArray(input.result?.logs)
    ? input.result.logs.map(cleanLog).filter((line): line is string => Boolean(line)).slice(-APP_RUNTIME_LIMITS.maximumResultLogLines)
    : [];
  for (const message of logs) {
    statements.push(
      database
        .prepare(
          `INSERT INTO app_deployment_log
           (id, workspaceId, deploymentId, nodeId, level, phase, message, createdAt)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          createId('alog'), input.job.workspaceId, payload.deploymentId,
          input.job.assignedNodeId, /error|failed|denied|crash/i.test(message) ? 'WARN' : 'INFO',
          message.startsWith('[build]') ? 'build' : 'runtime', message, input.now,
        ),
    );
  }
  await database.batch(statements);
  await execute(
    `DELETE FROM app_deployment_log
     WHERE workspaceId = ? AND deploymentId = ? AND id NOT IN (
       SELECT id FROM app_deployment_log WHERE workspaceId = ? AND deploymentId = ?
       ORDER BY createdAt DESC LIMIT 500
     )`,
    input.job.workspaceId,
    payload.deploymentId,
    input.job.workspaceId,
    payload.deploymentId,
  );
  if (successful && !checksum && integrityRequired) {
    await recordAppRuntimeSecurityEvent({
      workspaceId: input.job.workspaceId,
      nodeId: input.job.assignedNodeId,
      type: 'app-artifact-checksum-missing',
      severity: 'critical',
      detail: `App Runtime completion ${input.job.id} did not carry a verified artifact checksum.`,
    });
  }
  if (observedBind === '0.0.0.0') {
    await recordAppRuntimeSecurityEvent({
      workspaceId: input.job.workspaceId,
      nodeId: input.job.assignedNodeId,
      type: 'app-exposed-bind',
      severity: 'high',
      detail: `Deployment ${payload.deploymentId} reported a wildcard bind. No public route was created.`,
    });
  }
  if (crashLoop) {
    await recordAppRuntimeSecurityEvent({
      workspaceId: input.job.workspaceId,
      nodeId: input.job.assignedNodeId,
      type: 'app-crash-loop',
      severity: 'high',
      detail: `Deployment ${payload.deploymentId} reached crash-loop protection.`,
    });
  }
  if (input.result?.networkGuard === false) {
    await recordAppRuntimeSecurityEvent({
      workspaceId: input.job.workspaceId,
      nodeId: input.job.assignedNodeId,
      type: 'app-unexpected-outbound',
      severity: 'critical',
      detail: `Deployment ${payload.deploymentId} did not enforce the signed localhost-only network contract.`,
    });
  }
  if (input.result?.unexpectedOutbound === true) {
    await recordAppRuntimeSecurityEvent({
      workspaceId: input.job.workspaceId,
      nodeId: input.job.assignedNodeId,
      type: 'app-unexpected-outbound',
      severity: 'critical',
      detail: `Deployment ${payload.deploymentId} attempted outbound network access and the local permission guard blocked it.`,
    });
  }
  if (logs.some((message) => message.includes('Environment leak indicator'))) {
    await recordAppRuntimeSecurityEvent({
      workspaceId: input.job.workspaceId,
      nodeId: input.job.assignedNodeId,
      type: 'app-env-leak',
      severity: 'critical',
      detail: `Deployment ${payload.deploymentId} emitted a scoped environment value; the value was redacted.`,
    });
  }
  const failure = outcomeError ?? '';
  if (/outbound network attempt|ERR_ACCESS_DENIED.*network|allow-net/i.test(failure)) {
    await recordAppRuntimeSecurityEvent({
      workspaceId: input.job.workspaceId,
      nodeId: input.job.assignedNodeId,
      type: 'app-unexpected-outbound',
      severity: 'critical',
      detail: `Deployment ${payload.deploymentId} attempted network access outside its localhost-only contract.`,
    });
  }
  if (/path traversal|symbolic link|sandbox path|archive paths|special archive/i.test(failure)) {
    await recordAppRuntimeSecurityEvent({
      workspaceId: input.job.workspaceId,
      nodeId: input.job.assignedNodeId,
      type: 'app-path-abuse',
      severity: 'critical',
      detail: `Deployment ${payload.deploymentId} triggered a local path or archive boundary check.`,
    });
  }
  if (/disk quota|insufficient disk|heap|out of memory|resource/i.test(failure)) {
    await recordAppRuntimeSecurityEvent({
      workspaceId: input.job.workspaceId,
      nodeId: input.job.assignedNodeId,
      type: 'app-resource-exhaustion',
      severity: 'high',
      detail: `Deployment ${payload.deploymentId} exceeded or could not reserve its local resource budget.`,
    });
  }
  await writeLog({
    workspaceId: input.job.workspaceId,
    source: 'deployment',
    level: deploymentState === 'healthy' || deploymentState === 'stopped' || deploymentState === 'deleted' ? 'INFO' : 'WARN',
    message: `App Runtime ${payload.operation} ${deploymentState} on user-owned compute`,
    actor: input.job.assignedNodeId ? `agent:${input.job.assignedNodeId}` : 'node-agent',
    resource: payload.deploymentId,
  });
  const workflowEvent = deploymentState === 'failed' || deploymentState === 'timed_out' ||
      deploymentState === 'crash_loop'
    ? 'deployment.failed'
    : effectiveSuccess && payload.operation === 'rollback'
      ? 'deployment.rolled_back'
      : effectiveSuccess && deploymentState === 'healthy'
        ? 'deployment.deployed'
        : null;
  if (workflowEvent) {
    await emitWorkflowEvent({
      workspaceId: input.job.workspaceId,
      type: workflowEvent,
      resourceType: 'deployment',
      resourceId: payload.deploymentId,
      projectId: payload.projectId,
      payload: {
        status: deploymentState,
        projectId: payload.projectId,
        deploymentId: payload.deploymentId,
        nodeId: input.job.assignedNodeId,
        environment: payload.environment,
      },
      dedupeKey: `${workflowEvent}:${payload.deploymentId}:${input.job.id}`,
      correlationId: input.job.workflowCorrelationId ?? undefined,
      causationId: input.job.workflowExecutionId,
      sourceWorkflowId: input.job.workflowId,
      chainDepth: input.job.workflowChainDepth ?? 0,
      createdAt: input.now,
    }).catch(() => undefined);
  }
}

export async function syncAppRuntimeSnapshots(input: {
  workspaceId: string;
  nodeId: string;
  snapshots: unknown;
  cpuLoadPercent?: number;
  memoryUsedBytes?: number;
  now: number;
}): Promise<boolean> {
  const snapshots = parseAppRuntimeSnapshots(input.snapshots);
  if (!snapshots) return false;
  const database = await db();
  const statements: D1PreparedStatement[] = [];
  for (const snapshot of snapshots) {
    if (Math.abs(snapshot.observedAt - input.now) > 60_000) continue;
    const known = await queryOne<{ ok: number }>(
      `SELECT 1 AS ok FROM deployment WHERE workspaceId = ? AND id = ? AND projectId = ? AND nodeId = ?`,
      input.workspaceId, snapshot.deploymentId, snapshot.projectId, input.nodeId,
    );
    if (!known) {
      statements.push(
        database.prepare(
          `INSERT INTO node_security_event
           (id, workspaceId, nodeId, type, severity, detail, networkFingerprint, createdAt)
           VALUES (?, ?, ?, 'app-unknown-snapshot', 'high', ?, NULL, ?)`,
        ).bind(createId('nsec'), input.workspaceId, input.nodeId, `Unknown App Runtime deployment ${snapshot.deploymentId} was reported.`, input.now),
      );
      continue;
    }
    statements.push(
      database.prepare(
        `UPDATE deployment SET state = ?, currentArtifactId = COALESCE(?, currentArtifactId),
             observedBind = ?, restartCount = ?, crashLoop = ?, startedAt = CASE WHEN ? = 'healthy' THEN COALESCE(startedAt, ?) ELSE startedAt END,
             updatedAt = ? WHERE workspaceId = ? AND id = ? AND nodeId = ? AND deletedAt IS NULL`,
      ).bind(
        snapshot.crashLoop ? 'crash_loop' : snapshot.state === 'running' ? 'healthy' : 'stopped',
        snapshot.artifactId, snapshot.bind, snapshot.restartCount, snapshot.crashLoop ? 1 : 0,
        snapshot.state === 'running' ? 'healthy' : 'stopped', input.now, input.now,
        input.workspaceId, snapshot.deploymentId, input.nodeId,
      ),
      database.prepare(
        `INSERT INTO app_deployment_metric
         (id, workspaceId, deploymentId, nodeId, cpuLoadPercent, memoryUsedBytes, uptimeSeconds, restartCount, recordedAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        createId('amet'), input.workspaceId, snapshot.deploymentId, input.nodeId,
        input.cpuLoadPercent ?? null,
        snapshot.memoryUsedBytes ?? input.memoryUsedBytes ?? null,
        snapshot.uptimeSeconds, snapshot.restartCount, input.now,
      ),
      database.prepare(
        `UPDATE public_exposure
            SET healthState = ?,
                status = CASE WHEN mode = 'private' THEN 'disabled' ELSE 'unavailable_zero_mode' END,
                transport = 'none', transportState = 'unavailable_zero_mode',
                tlsState = 'unavailable', updatedAt = ?
          WHERE workspaceId = ? AND deploymentId = ? AND targetNodeId = ? AND deletedAt IS NULL`,
      ).bind(
        snapshot.crashLoop ? 'failed' : snapshot.state === 'running' ? 'healthy' : 'offline',
        input.now,
        input.workspaceId,
        snapshot.deploymentId,
        input.nodeId,
      ),
    );
  }
  if (statements.length > 0) await database.batch(statements);
  await execute(
    `DELETE FROM app_deployment_metric WHERE workspaceId = ? AND nodeId = ? AND recordedAt < ?`,
    input.workspaceId, input.nodeId, input.now - 7 * 24 * 60 * 60_000,
  );
  return true;
}

export type AppRuntimeShieldState = {
  unsafeScripts: number;
  lifecycleHooks: number;
  unsafeRegistry: number;
  pathAbuse: number;
  unsignedArtifacts: number;
  checksumMismatch: number;
  exposedBind: number;
  crashLoops: number;
  staleNodes: number;
  revokedActivity: number;
  resourceExhaustion: number;
  envLeak: number;
  unexpectedOutbound: number;
  forbiddenProvider: number;
  suspiciousVolume: number;
};

export async function appRuntimeForShield(workspaceId: string, now = Date.now()): Promise<AppRuntimeShieldState> {
  const eventCount = async (types: string[]) => {
    if (types.length === 0) return 0;
    const placeholders = types.map(() => '?').join(',');
    const row = await queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM node_security_event WHERE workspaceId = ? AND type IN (${placeholders}) AND createdAt >= ?`,
      workspaceId, ...types, now - 24 * 60 * 60_000,
    );
    return row?.total ?? 0;
  };
  const [unsigned, corrupt, crash, stale, volume] = await Promise.all([
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM app_artifact
       WHERE workspaceId = ? AND deletedAt IS NULL
         AND (state = 'corrupted' OR (state = 'verified' AND (checksum IS NULL OR verifiedAt IS NULL)))`,
      workspaceId,
    ),
    queryOne<{ total: number }>(`SELECT COUNT(*) AS total FROM app_artifact WHERE workspaceId = ? AND state = 'corrupted' AND deletedAt IS NULL`, workspaceId),
    queryOne<{ total: number }>(`SELECT COUNT(*) AS total FROM deployment WHERE workspaceId = ? AND crashLoop = 1 AND deletedAt IS NULL`, workspaceId),
    queryOne<{ total: number }>(`SELECT COUNT(*) AS total FROM deployment d JOIN compute_node n ON n.id = d.nodeId WHERE d.workspaceId = ? AND d.deletedAt IS NULL AND (n.revokedAt IS NOT NULL OR n.lastHeartbeatAt IS NULL OR n.lastHeartbeatAt < ?)`, workspaceId, now - 3 * 60_000),
    queryOne<{ total: number }>(`SELECT COUNT(*) AS total FROM app_deployment_action WHERE workspaceId = ? AND createdAt >= ?`, workspaceId, now - 60 * 60_000),
  ]);
  return {
    unsafeScripts: await eventCount(['app-unsafe-script']),
    lifecycleHooks: await eventCount(['app-lifecycle-hook']),
    unsafeRegistry: await eventCount(['app-unsafe-registry']),
    pathAbuse: await eventCount(['app-path-abuse', 'app-symlink-escape']),
    unsignedArtifacts: unsigned?.total ?? 0,
    checksumMismatch: (corrupt?.total ?? 0) + await eventCount(['app-artifact-checksum-missing']),
    exposedBind: await eventCount(['app-exposed-bind']),
    crashLoops: crash?.total ?? 0,
    staleNodes: stale?.total ?? 0,
    revokedActivity: await eventCount(['revoked-node-app-activity']),
    resourceExhaustion: await eventCount(['app-resource-exhaustion']),
    envLeak: await eventCount(['app-env-leak']),
    unexpectedOutbound: await eventCount(['app-unexpected-outbound']),
    forbiddenProvider: await eventCount(['app-forbidden-provider', 'app-forbidden-tunnel']),
    suspiciousVolume: (volume?.total ?? 0) > 20 ? volume!.total : 0,
  };
}
