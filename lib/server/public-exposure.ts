import { createId, createOpaqueToken, fingerprint, sha256Hex } from '@/lib/crypto';
import {
  domainVerificationQueryUrl,
  gatewayDecision,
  gatewayResponseHeaders,
  ipAllowed,
  normalizeCustomHostname,
  parseExposureMutation,
  type ExposureDomain,
  type ExposureHealth,
  type ExposureMutation,
  type PublicExposure,
  type PublicExposureAvailability,
} from '@/lib/public-exposure';
import { can, canAccessProject, type Actor } from '@/lib/roles';
import { consume, rateLimitHeaders } from '@/lib/rate-limit';
import { deriveNodeStatus } from '@/lib/nodes';
import { getSessionUser } from './auth';
import { db, execute, query, queryOne } from './db';
import { runtimeEnv } from './env';
import { clientAddress } from './rate-limit';

const UNAVAILABLE_REASON =
  'Unavailable under Zero Mode: this Workers Free account has no payment method, owned zone, or reviewed Cloudflare Tunnel route.';

function gatewayOrigin(): URL {
  const source =
    runtimeEnv.BETTER_AUTH_URL?.trim() ||
    runtimeEnv.NEXT_PUBLIC_SITE_URL?.trim() ||
    'http://localhost:3000';
  try {
    return new URL(source);
  } catch {
    return new URL('http://localhost:3000');
  }
}

export function publicExposureAvailability(): PublicExposureAvailability {
  const origin = gatewayOrigin();
  // These exact values were verified before deployment and are pinned by the
  // Zero Mode deploy guard. Merely changing a client flag or request body can
  // never make transport available.
  const attested =
    runtimeEnv.YSD_PUBLIC_TRANSPORT_MODE === 'unavailable-zero-mode' &&
    runtimeEnv.YSD_CLOUDFLARE_PLAN === 'workers-free' &&
    runtimeEnv.YSD_BILLING_STATE === 'no-payment-method' &&
    runtimeEnv.YSD_OWNED_ZONE_COUNT === '0' &&
    runtimeEnv.YSD_TUNNEL_COUNT === '0';
  return {
    available: false,
    state: 'unavailable-zero-mode',
    reason: attested ? UNAVAILABLE_REASON : `${UNAVAILABLE_REASON} Account attestation is also incomplete.`,
    accountPlan: 'workers-free',
    billingState: 'no-payment-method',
    ownedZones: 0,
    tunnels: 0,
    workersDevHostname: origin.hostname,
    gatewayStyle: 'path',
    projectedMonthlyCost: 0,
  };
}

type ExposureRow = {
  id: string;
  deploymentId: string;
  projectId: string;
  repository: string;
  environment: string;
  nodeName: string;
  routeId: string;
  mode: PublicExposure['mode'];
  status: PublicExposure['status'];
  accessPolicy: PublicExposure['accessPolicy'];
  transportState: string;
  assignedHostname: string | null;
  healthState: PublicExposure['health'];
  tlsState: PublicExposure['tls'];
  verificationState: PublicExposure['verification'];
  fallbackPolicy: PublicExposure['fallbackPolicy'];
  rateLimitEnabled: number;
  rateLimitPerMinute: number;
  ipAllowlist: string;
  isPreview: number;
  expiresAt: number | null;
  lastRequestAt: number | null;
  lastError: string | null;
  updatedAt: number;
};

const EXPOSURE_SELECT = `e.id, e.deploymentId, e.projectId, d.repository, d.environment,
  n.name AS nodeName, e.routeId, e.mode, e.status, e.accessPolicy,
  e.transportState, e.assignedHostname, e.healthState, e.tlsState,
  e.verificationState, e.fallbackPolicy, e.rateLimitEnabled,
  e.rateLimitPerMinute, e.ipAllowlist, e.isPreview, e.expiresAt,
  e.lastRequestAt, e.lastError, e.updatedAt`;

function parseAllowlist(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) && parsed.every((item) => typeof item === 'string')
      ? parsed.slice(0, 32)
      : [];
  } catch {
    return [];
  }
}

function toPublicExposure(row: ExposureRow, actor: Actor): PublicExposure {
  const origin = gatewayOrigin();
  const gatewayRoute = new URL(`/apps/${row.routeId}/`, origin).href;
  const active =
    row.status === 'active' && row.transportState === 'ready' &&
    row.healthState === 'healthy' && row.tlsState === 'cloudflare';
  const publicUrl = active
    ? row.assignedHostname
      ? `https://${row.assignedHostname}/`
      : gatewayRoute
    : null;
  const preview = row.isPreview === 1;
  return {
    id: row.id,
    deploymentId: row.deploymentId,
    projectId: row.projectId,
    repository: row.repository,
    environment: row.environment === 'Preview' || row.environment === 'Development'
      ? row.environment
      : 'Production',
    nodeName: row.nodeName,
    routeId: row.routeId,
    gatewayRoute,
    publicUrl,
    assignedHostname: row.assignedHostname,
    mode: row.mode,
    status: row.status,
    accessPolicy: row.accessPolicy,
    health: row.healthState,
    tls: row.tlsState,
    verification: row.verificationState,
    fallbackPolicy: row.fallbackPolicy,
    rateLimitEnabled: row.rateLimitEnabled === 1,
    rateLimitPerMinute: row.rateLimitPerMinute,
    ipAllowlist: parseAllowlist(row.ipAllowlist),
    preview,
    expiresAt: row.expiresAt,
    lastRequestAt: row.lastRequestAt,
    lastError: row.lastError,
    updatedAt: row.updatedAt,
    canManage: can(actor, 'exposure.manage') || (preview && can(actor, 'exposure.preview')),
  };
}

export async function listPublicExposures(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
}): Promise<PublicExposure[]> {
  if (input.actor.projectIds !== null && input.actor.projectIds !== undefined && input.actor.projectIds.length === 0) return [];
  const restricted = input.actor.projectIds !== null && input.actor.projectIds !== undefined;
  const rows = await query<ExposureRow>(
    `SELECT ${EXPOSURE_SELECT}
       FROM public_exposure e
       JOIN deployment d ON d.id = e.deploymentId AND d.workspaceId = e.workspaceId
       JOIN compute_node n ON n.id = e.targetNodeId AND n.workspaceId = e.workspaceId
      WHERE e.organizationId = ? AND e.workspaceId = ? AND e.deletedAt IS NULL
        ${restricted ? `AND e.projectId IN (${(input.actor.projectIds ?? []).map(() => '?').join(', ')})` : ''}
      ORDER BY e.updatedAt DESC LIMIT 200`,
    input.organizationId,
    input.workspaceId,
    ...(input.actor.projectIds ?? []),
  );
  return rows.map((row) => toPublicExposure(row, input.actor));
}

async function findExposure(input: {
  organizationId: string;
  workspaceId: string;
  exposureId: string;
  actor: Actor;
}): Promise<PublicExposure | null> {
  const row = await queryOne<ExposureRow>(
    `SELECT ${EXPOSURE_SELECT}
       FROM public_exposure e
       JOIN deployment d ON d.id = e.deploymentId AND d.workspaceId = e.workspaceId
       JOIN compute_node n ON n.id = e.targetNodeId AND n.workspaceId = e.workspaceId
      WHERE e.organizationId = ? AND e.workspaceId = ? AND e.id = ? AND e.deletedAt IS NULL`,
    input.organizationId,
    input.workspaceId,
    input.exposureId,
  );
  if (!row || !canAccessProject(input.actor, row.projectId)) return null;
  return toPublicExposure(row, input.actor);
}

type DeploymentTarget = {
  id: string;
  projectId: string;
  repository: string;
  environment: string;
  state: string;
  nodeId: string;
  currentArtifactId: string | null;
  nodeName: string;
  lastHeartbeatAt: number | null;
  revokedAt: number | null;
  previewDeployments: number;
  artifactState: string | null;
};

function targetHealth(row: DeploymentTarget, now: number): ExposureHealth {
  const node = deriveNodeStatus({
    revokedAt: row.revokedAt,
    lastHeartbeatAt: row.lastHeartbeatAt,
    now,
  });
  if (node === 'revoked') return 'revoked';
  if (node === 'offline') return 'offline';
  if (node === 'stale') return 'stale';
  if (row.state !== 'healthy' || row.artifactState !== 'verified') return 'failed';
  return 'healthy';
}

function mayManageExposure(actor: Actor, target: DeploymentTarget, mutation: ExposureMutation): boolean {
  if (can(actor, 'exposure.manage')) return true;
  return mutation.preview && target.environment === 'Preview' && target.previewDeployments === 1 &&
    mutation.mode !== 'custom-domain' && can(actor, 'exposure.preview');
}

export type ExposureWriteResult =
  | { ok: true; exposure: PublicExposure; created: boolean }
  | { ok: false; status: number; error: string; securityEvent?: string };

export async function upsertPublicExposure(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
  body: unknown;
  now?: number;
}): Promise<ExposureWriteResult> {
  const now = input.now ?? Date.now();
  const parsed = parseExposureMutation(input.body, now);
  if (!parsed.ok) return parsed;
  const mutation = parsed.value;
  const target = await queryOne<DeploymentTarget>(
    `SELECT d.id, d.projectId, d.repository, d.environment, d.state, d.nodeId,
            d.currentArtifactId, n.name AS nodeName, n.lastHeartbeatAt,
            n.revokedAt, w.previewDeployments, a.state AS artifactState
       FROM deployment d
       JOIN workspace w ON w.id = d.workspaceId AND w.organizationId = ?
       JOIN compute_node n ON n.id = d.nodeId AND n.workspaceId = d.workspaceId
       LEFT JOIN app_artifact a ON a.id = d.currentArtifactId
      WHERE d.workspaceId = ? AND d.id = ? AND d.projectId IS NOT NULL
        AND d.nodeId IS NOT NULL AND d.deletedAt IS NULL`,
    input.organizationId,
    input.workspaceId,
    mutation.deploymentId,
  );
  if (!target || !canAccessProject(input.actor, target.projectId)) {
    return { ok: false, status: 404, error: 'Deployment not found.' };
  }
  if (!mayManageExposure(input.actor, target, mutation)) {
    return { ok: false, status: 403, error: 'This role may manage only enabled Preview exposure.' };
  }
  if (mutation.preview !== (target.environment === 'Preview')) {
    return { ok: false, status: 409, error: 'Preview routes may target only Preview deployments.' };
  }
  const health = targetHealth(target, now);
  const existing = await queryOne<{ id: string; routeId: string }>(
    `SELECT id, routeId FROM public_exposure
      WHERE organizationId = ? AND workspaceId = ? AND deploymentId = ?
        AND isPreview = ? AND deletedAt IS NULL`,
    input.organizationId,
    input.workspaceId,
    target.id,
    mutation.preview ? 1 : 0,
  );
  const routeId = existing?.routeId ?? (mutation.preview
    ? `pvw_${(await sha256Hex(`preview|${input.organizationId}|${input.workspaceId}|${target.projectId}|${target.id}`)).slice(0, 24)}`
    : createId('route'));
  const routePath = `/apps/${routeId}`;
  const status = mutation.mode === 'private' ? 'disabled' : 'unavailable_zero_mode';
  const error = mutation.mode === 'private' ? null : UNAVAILABLE_REASON;
  const exposureId = existing?.id ?? createId('exp');
  if (existing) {
    await execute(
      `UPDATE public_exposure
          SET mode = ?, status = ?, accessPolicy = ?, transport = 'none',
              transportState = 'unavailable_zero_mode', assignedHostname = NULL,
              targetNodeId = ?, targetArtifactId = ?, healthState = ?,
              tlsState = 'unavailable', verificationState = ?, fallbackPolicy = ?,
              rateLimitEnabled = 1, rateLimitPerMinute = ?, ipAllowlist = ?,
              expiresAt = ?, lastError = ?, updatedAt = ?
        WHERE organizationId = ? AND workspaceId = ? AND id = ? AND deletedAt IS NULL`,
      mutation.mode,
      status,
      mutation.accessPolicy,
      target.nodeId,
      target.artifactState === 'verified' ? target.currentArtifactId : null,
      health,
      mutation.mode === 'custom-domain' ? 'pending' : 'not_required',
      mutation.fallbackPolicy,
      mutation.rateLimitPerMinute,
      JSON.stringify(mutation.ipAllowlist),
      mutation.expiresAt,
      error,
      now,
      input.organizationId,
      input.workspaceId,
      exposureId,
    );
  } else {
    await execute(
      `INSERT INTO public_exposure
       (id, organizationId, workspaceId, projectId, deploymentId, routeId,
        routePath, mode, status, accessPolicy, transport, transportState,
        assignedHostname, targetNodeId, targetArtifactId, healthState,
        tlsState, verificationState, fallbackPolicy, rateLimitEnabled,
        rateLimitPerMinute, ipAllowlist, isPreview, expiresAt, lastRequestAt,
        lastError, createdBy, createdAt, updatedAt, deletedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 'unavailable_zero_mode',
               NULL, ?, ?, ?, 'unavailable', ?, ?, 1, ?, ?, ?, ?, NULL, ?, ?, ?, ?, NULL)`,
      exposureId,
      input.organizationId,
      input.workspaceId,
      target.projectId,
      target.id,
      routeId,
      routePath,
      mutation.mode,
      status,
      mutation.accessPolicy,
      target.nodeId,
      target.artifactState === 'verified' ? target.currentArtifactId : null,
      health,
      mutation.mode === 'custom-domain' ? 'pending' : 'not_required',
      mutation.fallbackPolicy,
      mutation.rateLimitPerMinute,
      JSON.stringify(mutation.ipAllowlist),
      mutation.preview ? 1 : 0,
      mutation.expiresAt,
      error,
      input.actor.userId,
      now,
      now,
    );
  }
  if (mutation.preview) {
    await execute(
      `UPDATE public_exposure SET status = 'expired', mode = 'private', deletedAt = ?, updatedAt = ?
        WHERE organizationId = ? AND workspaceId = ? AND isPreview = 1
          AND expiresAt IS NOT NULL AND expiresAt <= ? AND deletedAt IS NULL`,
      now,
      now,
      input.organizationId,
      input.workspaceId,
      now,
    );
  }
  const exposure = await findExposure({
    organizationId: input.organizationId,
    workspaceId: input.workspaceId,
    exposureId,
    actor: input.actor,
  });
  return exposure
    ? { ok: true, exposure, created: !existing }
    : { ok: false, status: 500, error: 'The exposure record could not be read back.' };
}

export async function deletePublicExposure(input: {
  organizationId: string;
  workspaceId: string;
  exposureId: string;
  actor: Actor;
  now?: number;
}): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  const exposure = await findExposure(input);
  if (!exposure) return { ok: false, status: 404, error: 'Exposure not found.' };
  if (!exposure.canManage) return { ok: false, status: 403, error: 'This role cannot remove the route.' };
  const now = input.now ?? Date.now();
  const database = await db();
  await database.batch([
    database.prepare(
      `UPDATE exposure_domain SET exposureId = NULL, attachState = 'detached',
              tlsState = 'unavailable', detachedAt = ?, updatedAt = ?
        WHERE organizationId = ? AND workspaceId = ? AND exposureId = ? AND deletedAt IS NULL`,
    ).bind(now, now, input.organizationId, input.workspaceId, exposure.id),
    database.prepare(
      `UPDATE public_exposure SET mode = 'private', status = 'deleted',
              assignedHostname = NULL, healthState = 'failed',
              tlsState = 'unavailable', deletedAt = ?, updatedAt = ?
        WHERE organizationId = ? AND workspaceId = ? AND id = ? AND deletedAt IS NULL`,
    ).bind(now, now, input.organizationId, input.workspaceId, exposure.id),
  ]);
  return { ok: true };
}

type DomainRow = Omit<ExposureDomain, 'tls'> & { tlsState: ExposureDomain['tls'] };

function toDomain(row: DomainRow): ExposureDomain {
  const { tlsState, ...rest } = row;
  return { ...rest, tls: tlsState };
}

export async function listExposureDomains(
  organizationId: string,
  workspaceId: string,
): Promise<ExposureDomain[]> {
  const rows = await query<DomainRow>(
    `SELECT id, hostname, dnsRecordName, tokenPrefix, ownershipState,
            providerState, attachState, tlsState, exposureId, verifiedAt,
            lastError, updatedAt
       FROM exposure_domain
      WHERE organizationId = ? AND workspaceId = ? AND deletedAt IS NULL
      ORDER BY updatedAt DESC LIMIT 200`,
    organizationId,
    workspaceId,
  );
  return rows.map(toDomain);
}

export type DomainCreateResult =
  | { ok: true; domain: ExposureDomain; verificationRecord: { name: string; type: 'TXT'; value: string } }
  | { ok: false; status: number; error: string };

export async function createExposureDomain(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
  hostname: unknown;
  now?: number;
}): Promise<DomainCreateResult> {
  if (!can(input.actor, 'domain.manage')) return { ok: false, status: 403, error: 'Only owners and admins manage domains.' };
  const hostname = typeof input.hostname === 'string' ? normalizeCustomHostname(input.hostname) : null;
  if (!hostname) return { ok: false, status: 400, error: 'Enter a valid owned hostname. IPs, internal names, and workers.dev are not accepted.' };
  const conflict = await queryOne<{ organizationId: string }>(
    'SELECT organizationId FROM exposure_domain WHERE hostname = ? AND deletedAt IS NULL',
    hostname,
  );
  if (conflict) return { ok: false, status: 409, error: 'That hostname is already inventoried.' };
  const token = createOpaqueToken('ysd_domain');
  const id = createId('dom');
  const now = input.now ?? Date.now();
  const dnsRecordName = `_ysd-verification.${hostname}`;
  await execute(
    `INSERT INTO exposure_domain
     (id, organizationId, workspaceId, hostname, dnsRecordName, tokenHash,
      tokenPrefix, ownershipState, providerState, attachState, tlsState,
      exposureId, verifiedAt, attachedAt, detachedAt, lastError, createdBy,
      createdAt, updatedAt, deletedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 'no_owned_zone', 'detached',
             'unavailable', NULL, NULL, NULL, NULL, ?, ?, ?, ?, NULL)`,
    id,
    input.organizationId,
    input.workspaceId,
    hostname,
    dnsRecordName,
    await sha256Hex(token),
    token.slice(0, 18),
    'No owned domain is connected to this Cloudflare account; ownership can be proved, but attachment stays disabled.',
    input.actor.userId,
    now,
    now,
  );
  const row = (await queryOne<DomainRow>(
    `SELECT id, hostname, dnsRecordName, tokenPrefix, ownershipState,
            providerState, attachState, tlsState, exposureId, verifiedAt,
            lastError, updatedAt FROM exposure_domain WHERE id = ?`,
    id,
  ))!;
  return {
    ok: true,
    domain: toDomain(row),
    verificationRecord: { name: dnsRecordName, type: 'TXT', value: `ysd-domain-verification=${token}` },
  };
}

function txtValues(payload: unknown): string[] {
  if (typeof payload !== 'object' || payload === null || !Array.isArray((payload as { Answer?: unknown }).Answer)) return [];
  return (payload as { Answer: { data?: unknown }[] }).Answer
    .map((answer) => typeof answer?.data === 'string' ? answer.data.replace(/^"|"$/g, '').replaceAll('" "', '') : '')
    .filter(Boolean);
}

export async function verifyExposureDomain(input: {
  organizationId: string;
  workspaceId: string;
  domainId: string;
  actor: Actor;
  fetcher?: typeof fetch;
  now?: number;
}): Promise<{ ok: true; domain: ExposureDomain } | { ok: false; status: number; error: string }> {
  if (!can(input.actor, 'domain.manage')) return { ok: false, status: 403, error: 'Only owners and admins verify domains.' };
  const row = await queryOne<DomainRow & { tokenHash: string }>(
    `SELECT id, hostname, dnsRecordName, tokenPrefix, tokenHash, ownershipState,
            providerState, attachState, tlsState, exposureId, verifiedAt,
            lastError, updatedAt
       FROM exposure_domain
      WHERE id = ? AND organizationId = ? AND workspaceId = ? AND deletedAt IS NULL`,
    input.domainId,
    input.organizationId,
    input.workspaceId,
  );
  if (!row) return { ok: false, status: 404, error: 'Domain not found.' };
  const url = domainVerificationQueryUrl(row.hostname);
  if (!url) return { ok: false, status: 400, error: 'The stored hostname is invalid.' };
  let verified = false;
  try {
    const response = await (input.fetcher ?? fetch)(url, {
      headers: { Accept: 'application/dns-json' },
      redirect: 'error',
    });
    if (response.ok) {
      for (const value of txtValues(await response.json())) {
        const token = value.startsWith('ysd-domain-verification=')
          ? value.slice('ysd-domain-verification='.length)
          : '';
        if (token && await sha256Hex(token) === row.tokenHash) {
          verified = true;
          break;
        }
      }
    }
  } catch {
    verified = false;
  }
  const now = input.now ?? Date.now();
  await execute(
    `UPDATE exposure_domain
        SET ownershipState = ?, verifiedAt = CASE WHEN ? = 1 THEN ? ELSE verifiedAt END,
            lastError = ?, updatedAt = ?
      WHERE id = ? AND organizationId = ? AND workspaceId = ?`,
    verified ? 'verified' : 'failed',
    verified ? 1 : 0,
    now,
    verified
      ? 'Ownership verified. No owned Cloudflare zone is connected, so attachment and TLS remain unavailable.'
      : 'The required DNS TXT ownership proof was not found.',
    now,
    row.id,
    input.organizationId,
    input.workspaceId,
  );
  const updated = (await listExposureDomains(input.organizationId, input.workspaceId)).find((domain) => domain.id === row.id)!;
  return verified
    ? { ok: true, domain: updated }
    : { ok: false, status: 409, error: 'DNS ownership verification did not match.' };
}

export async function attachExposureDomain(input: {
  organizationId: string;
  workspaceId: string;
  domainId: string;
  exposureId: string | null;
  actor: Actor;
  now?: number;
}): Promise<{ ok: true; domain: ExposureDomain } | { ok: false; status: number; error: string }> {
  if (!can(input.actor, 'domain.manage')) return { ok: false, status: 403, error: 'Only owners and admins attach domains.' };
  const domain = (await listExposureDomains(input.organizationId, input.workspaceId)).find((item) => item.id === input.domainId);
  if (!domain) return { ok: false, status: 404, error: 'Domain not found.' };
  const now = input.now ?? Date.now();
  if (input.exposureId === null) {
    const database = await db();
    await database.batch([
      database.prepare(
        `UPDATE public_exposure SET assignedHostname = NULL, mode = CASE WHEN mode = 'custom-domain' THEN 'private' ELSE mode END,
                status = CASE WHEN mode = 'custom-domain' THEN 'disabled' ELSE status END,
                verificationState = CASE WHEN mode = 'custom-domain' THEN 'not_required' ELSE verificationState END,
                tlsState = 'unavailable', updatedAt = ?
          WHERE organizationId = ? AND workspaceId = ? AND id = ?`,
      ).bind(now, input.organizationId, input.workspaceId, domain.exposureId),
      database.prepare(
        `UPDATE exposure_domain SET exposureId = NULL, attachState = 'detached',
                tlsState = 'unavailable', detachedAt = ?, updatedAt = ?
          WHERE organizationId = ? AND workspaceId = ? AND id = ?`,
      ).bind(now, now, input.organizationId, input.workspaceId, domain.id),
    ]);
    const updated = (await listExposureDomains(input.organizationId, input.workspaceId)).find((item) => item.id === domain.id)!;
    return { ok: true, domain: updated };
  }
  const exposure = await findExposure({
    organizationId: input.organizationId,
    workspaceId: input.workspaceId,
    exposureId: input.exposureId,
    actor: input.actor,
  });
  if (!exposure) return { ok: false, status: 404, error: 'Exposure not found.' };
  if (domain.ownershipState !== 'verified') return { ok: false, status: 409, error: 'Verify domain ownership before attachment.' };
  if (domain.providerState !== 'ready' || !publicExposureAvailability().available) {
    return { ok: false, status: 409, error: 'No owned domain is connected. Custom Domain attachment is unavailable under Zero Mode.' };
  }
  // There is intentionally no attachment implementation in this account
  // state. Reaching here would mean a deployment attestation was changed
  // without the reviewed Cloudflare Custom Domain adapter.
  return { ok: false, status: 503, error: 'The reviewed Custom Domain adapter is not installed.' };
}

export async function deleteExposureDomain(input: {
  organizationId: string;
  workspaceId: string;
  domainId: string;
  actor: Actor;
  now?: number;
}): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  if (!can(input.actor, 'domain.manage')) return { ok: false, status: 403, error: 'Only owners and admins remove domains.' };
  const domain = (await listExposureDomains(input.organizationId, input.workspaceId)).find((item) => item.id === input.domainId);
  if (!domain) return { ok: false, status: 404, error: 'Domain not found.' };
  if (domain.attachState === 'attached') return { ok: false, status: 409, error: 'Detach the domain before removing it.' };
  const now = input.now ?? Date.now();
  await execute(
    `UPDATE exposure_domain SET deletedAt = ?, updatedAt = ?, tokenHash = ?, exposureId = NULL,
            attachState = 'detached', tlsState = 'unavailable'
      WHERE organizationId = ? AND workspaceId = ? AND id = ? AND deletedAt IS NULL`,
    now,
    now,
    await sha256Hex(`deleted|${domain.id}|${now}`),
    input.organizationId,
    input.workspaceId,
    domain.id,
  );
  return { ok: true };
}

export async function recordExposureSecurityEvent(input: {
  workspaceId: string;
  type: string;
  detail: string;
  nodeId?: string | null;
}): Promise<void> {
  await execute(
    `INSERT INTO node_security_event
     (id, workspaceId, nodeId, type, severity, detail, networkFingerprint, createdAt)
     VALUES (?, ?, ?, ?, 'critical', ?, NULL, ?)`,
    createId('nsec'),
    input.workspaceId,
    input.nodeId ?? null,
    input.type.slice(0, 100),
    input.detail.slice(0, 500),
    Date.now(),
  );
}

type GatewayRow = {
  id: string;
  organizationId: string;
  workspaceId: string;
  projectId: string;
  deploymentId: string;
  targetNodeId: string;
  targetArtifactId: string | null;
  mode: PublicExposure['mode'];
  status: PublicExposure['status'];
  accessPolicy: PublicExposure['accessPolicy'];
  transportState: 'unavailable_zero_mode' | 'disconnected' | 'ready' | 'revoked' | 'failed';
  healthState: ExposureHealth;
  tlsState: PublicExposure['tls'];
  verificationState: PublicExposure['verification'];
  fallbackPolicy: PublicExposure['fallbackPolicy'];
  rateLimitEnabled: number;
  rateLimitPerMinute: number;
  ipAllowlist: string;
  expiresAt: number | null;
  deploymentState: string;
  deploymentDeletedAt: number | null;
  currentArtifactId: string | null;
  artifactState: string | null;
  lastHeartbeatAt: number | null;
  revokedAt: number | null;
};

async function authenticatedProjectMember(request: Request, route: GatewayRow): Promise<boolean> {
  const user = await getSessionUser(request.headers);
  if (!user) return false;
  const member = await queryOne<{ ok: number }>(
    `SELECT 1 AS ok
       FROM organization_member m
       JOIN workspace_member wm
         ON wm.organizationId = m.organizationId AND wm.userId = m.userId
        AND wm.workspaceId = ?
      WHERE m.organizationId = ? AND m.userId = ? AND m.status = 'active'
        AND m.suspendedAt IS NULL
        AND (wm.projectScope = 'all' OR EXISTS (
          SELECT 1 FROM member_project_access a
           WHERE a.organizationId = m.organizationId AND a.workspaceId = wm.workspaceId
             AND a.userId = m.userId AND a.projectId = ?
        ))`,
    route.workspaceId,
    route.organizationId,
    user.id,
    route.projectId,
  );
  return Boolean(member);
}

function liveHealth(route: GatewayRow, now: number): ExposureHealth {
  const node = deriveNodeStatus({ revokedAt: route.revokedAt, lastHeartbeatAt: route.lastHeartbeatAt, now });
  if (node === 'revoked') return 'revoked';
  if (node === 'offline') return 'offline';
  if (node === 'stale') return 'stale';
  if (route.deploymentDeletedAt !== null || route.deploymentState !== 'healthy') return 'failed';
  if (!route.targetArtifactId || route.targetArtifactId !== route.currentArtifactId || route.artifactState !== 'verified') return 'failed';
  return 'healthy';
}

async function enforceGatewayLimit(route: GatewayRow, request: Request, now: number) {
  const rule = { limit: route.rateLimitPerMinute, windowMs: 60_000 };
  const key = `gateway|${route.id}|${await fingerprint(clientAddress(request) || 'anonymous')}`;
  try {
    const state = await queryOne<{ count: number; windowStart: number }>(
      'SELECT count, windowStart FROM rate_limit WHERE key = ?',
      key,
    );
    const decision = consume(rule, state, now);
    await execute(
      `INSERT INTO rate_limit (key, count, windowStart) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET count = excluded.count, windowStart = excluded.windowStart`,
      key,
      decision.next.count,
      decision.next.windowStart,
    );
    return { ok: true as const, decision, headers: rateLimitHeaders(rule, decision) };
  } catch {
    return { ok: false as const };
  }
}

function gatewayJson(status: number, message: string, headers?: HeadersInit): Response {
  return Response.json({ error: message }, { status, headers: gatewayResponseHeaders(headers) });
}

/**
 * Public Gateway entrypoint. It resolves only a registered route identity and
 * never calls fetch() with a database value or user-provided URL. Since this
 * account has no reviewed connector, every otherwise-valid route returns 503.
 */
export async function handlePublicGateway(request: Request, routeId: string): Promise<Response> {
  if (!/^(?:route|pvw)_[a-f0-9]{24}$/.test(routeId)) return gatewayJson(404, 'Not found.');
  const route = await queryOne<GatewayRow>(
    `SELECT e.id, e.organizationId, e.workspaceId, e.projectId, e.deploymentId,
            e.targetNodeId, e.targetArtifactId, e.mode, e.status, e.accessPolicy,
            e.transportState, e.healthState, e.tlsState, e.verificationState,
            e.fallbackPolicy, e.rateLimitEnabled, e.rateLimitPerMinute,
            e.ipAllowlist, e.expiresAt, d.state AS deploymentState,
            d.deletedAt AS deploymentDeletedAt, d.currentArtifactId,
            a.state AS artifactState, n.lastHeartbeatAt, n.revokedAt
       FROM public_exposure e
       JOIN workspace w ON w.id = e.workspaceId AND w.organizationId = e.organizationId
       JOIN project p ON p.id = e.projectId AND p.workspaceId = e.workspaceId
       JOIN deployment d ON d.id = e.deploymentId AND d.workspaceId = e.workspaceId
                         AND d.projectId = e.projectId AND d.nodeId = e.targetNodeId
       JOIN compute_node n ON n.id = e.targetNodeId AND n.workspaceId = e.workspaceId
       LEFT JOIN app_artifact a ON a.id = e.targetArtifactId
      WHERE e.routeId = ? AND e.deletedAt IS NULL`,
    routeId,
  );
  const now = Date.now();
  if (!route) return gatewayJson(404, 'Not found.');
  if (route.expiresAt !== null && route.expiresAt <= now) {
    await execute(
      `UPDATE public_exposure SET mode = 'private', status = 'expired', deletedAt = ?, updatedAt = ?
        WHERE id = ? AND deletedAt IS NULL`,
      now,
      now,
      route.id,
    );
    return gatewayJson(404, 'Not found.');
  }
  const health = liveHealth(route, now);
  if (health !== route.healthState) {
    await execute('UPDATE public_exposure SET healthState = ?, updatedAt = ? WHERE id = ?', health, now, route.id);
  }
  const authenticatedMember = route.accessPolicy === 'authenticated'
    ? await authenticatedProjectMember(request, route)
    : false;
  const allowedAddress = ipAllowed(clientAddress(request), parseAllowlist(route.ipAllowlist));
  const decision = gatewayDecision({
    route: {
      mode: route.mode,
      status: route.status,
      accessPolicy: route.accessPolicy,
      transportState: route.transportState,
      health,
      tls: route.tlsState,
      verification: route.verificationState,
      expiresAt: route.expiresAt,
      rateLimitEnabled: route.rateLimitEnabled === 1,
    },
    now,
    authenticatedMember,
    ipAllowed: allowedAddress,
  });
  if (decision.action === 'not-found') return gatewayJson(404, 'Not found.');
  if (decision.action === 'authenticate') return gatewayJson(401, 'Authentication required.');
  if (decision.action === 'deny') return gatewayJson(403, 'Access denied.');
  if (route.rateLimitEnabled !== 1) return gatewayJson(503, 'Application unavailable.', { 'Retry-After': '60' });
  const limited = await enforceGatewayLimit(route, request, now);
  if (!limited.ok) return gatewayJson(503, 'Application unavailable.', { 'Retry-After': '60' });
  if (!limited.decision.allowed) {
    return gatewayJson(429, 'Too many requests.', limited.headers);
  }
  await execute(
    `UPDATE public_exposure SET lastRequestAt = ?, lastError = ?, updatedAt = ? WHERE id = ?`,
    now,
    decision.action === 'unavailable' ? UNAVAILABLE_REASON : null,
    now,
    route.id,
  );
  if (decision.action !== 'forward') {
    return gatewayJson(503, 'Application unavailable.', { ...Object.fromEntries(new Headers(limited.headers)), 'Retry-After': '60' });
  }
  await recordExposureSecurityEvent({
    workspaceId: route.workspaceId,
    nodeId: route.targetNodeId,
    type: 'exposure-unexpected-connector-target',
    detail: `Route ${route.id} reached an unimplemented connector and was failed closed.`,
  });
  return gatewayJson(503, 'Application unavailable.', { 'Retry-After': '60' });
}

export type PublicExposureShieldState = {
  unavailableUnderZeroMode: boolean;
  unexpectedPublic: number;
  staleRoutes: number;
  offlineOrRevokedRoutes: number;
  unverifiedDomains: number;
  tlsUnavailable: number;
  originLeakIndicators: number;
  openProxyAttempts: number;
  excessivePublicRoutes: number;
  rateLimitDisabled: number;
  suspiciousDomainChurn: number;
  lowPrivilegeChanges: number;
  tunnelCredentialAnomaly: number;
  unexpectedConnectorTarget: number;
  orphanRoutes: number;
  crossOrgDomainConflict: number;
  zeroModeBypass: number;
};

export async function publicExposureForShield(
  workspaceId: string,
  now = Date.now(),
): Promise<PublicExposureShieldState> {
  const total = async (sql: string, ...params: unknown[]) =>
    (await queryOne<{ total: number }>(sql, ...params))?.total ?? 0;
  const eventCount = async (types: string[]) => total(
    `SELECT COUNT(*) AS total FROM node_security_event
      WHERE workspaceId = ? AND type IN (${types.map(() => '?').join(',')}) AND createdAt >= ?`,
    workspaceId,
    ...types,
    now - 24 * 60 * 60_000,
  );
  const activeRoutes = await total(
    `SELECT COUNT(*) AS total FROM public_exposure
      WHERE workspaceId = ? AND mode <> 'private' AND status = 'active' AND deletedAt IS NULL`,
    workspaceId,
  );
  const churn = await total(
    `SELECT COUNT(*) AS total FROM exposure_domain
      WHERE workspaceId = ? AND (createdAt >= ? OR deletedAt >= ?)`,
    workspaceId,
    now - 24 * 60 * 60_000,
    now - 24 * 60 * 60_000,
  );
  return {
    unavailableUnderZeroMode: !publicExposureAvailability().available,
    unexpectedPublic: await total(
      `SELECT COUNT(*) AS total FROM public_exposure
        WHERE workspaceId = ? AND status = 'active' AND mode <> 'private'
          AND (transport <> 'cloudflare_tunnel' OR transportState <> 'ready') AND deletedAt IS NULL`,
      workspaceId,
    ),
    staleRoutes: await total(
      `SELECT COUNT(*) AS total FROM public_exposure e
        JOIN deployment d ON d.id = e.deploymentId
        WHERE e.workspaceId = ? AND e.status = 'active' AND e.deletedAt IS NULL
          AND (e.healthState <> 'healthy' OR d.state <> 'healthy' OR d.deletedAt IS NOT NULL)`,
      workspaceId,
    ),
    offlineOrRevokedRoutes: await total(
      `SELECT COUNT(*) AS total FROM public_exposure e
        JOIN compute_node n ON n.id = e.targetNodeId
        WHERE e.workspaceId = ? AND e.status = 'active' AND e.deletedAt IS NULL
          AND (n.revokedAt IS NOT NULL OR n.lastHeartbeatAt IS NULL OR n.lastHeartbeatAt < ?)`,
      workspaceId,
      now - 3 * 60_000,
    ),
    unverifiedDomains: await total(
      `SELECT COUNT(*) AS total FROM exposure_domain
        WHERE workspaceId = ? AND attachState = 'attached'
          AND ownershipState <> 'verified' AND deletedAt IS NULL`,
      workspaceId,
    ),
    tlsUnavailable: await total(
      `SELECT COUNT(*) AS total FROM public_exposure
        WHERE workspaceId = ? AND status = 'active' AND mode <> 'private'
          AND tlsState <> 'cloudflare' AND deletedAt IS NULL`,
      workspaceId,
    ),
    originLeakIndicators: await eventCount(['exposure-origin-leak']),
    openProxyAttempts: await eventCount(['gateway-upstream-rejected', 'gateway-ssrf-attempt']),
    excessivePublicRoutes: Math.max(0, activeRoutes - 100),
    rateLimitDisabled: await total(
      `SELECT COUNT(*) AS total FROM public_exposure
        WHERE workspaceId = ? AND mode <> 'private' AND rateLimitEnabled = 0 AND deletedAt IS NULL`,
      workspaceId,
    ),
    suspiciousDomainChurn: churn > 20 ? churn : 0,
    lowPrivilegeChanges: await total(
      `SELECT COUNT(*) AS total FROM audit_event
        WHERE workspaceId = ? AND action LIKE 'exposure.%' AND createdAt >= ?
          AND (metadata LIKE '%"role":"developer"%' OR metadata LIKE '%"role":"viewer"%')`,
      workspaceId,
      now - 24 * 60 * 60_000,
    ),
    tunnelCredentialAnomaly: await eventCount(['exposure-tunnel-credential-anomaly']),
    unexpectedConnectorTarget: await eventCount(['exposure-unexpected-connector-target']),
    orphanRoutes: await total(
      `SELECT COUNT(*) AS total FROM public_exposure e
        LEFT JOIN workspace w ON w.id = e.workspaceId AND w.organizationId = e.organizationId
        LEFT JOIN project p ON p.id = e.projectId AND p.workspaceId = e.workspaceId
        LEFT JOIN deployment d ON d.id = e.deploymentId AND d.workspaceId = e.workspaceId
        LEFT JOIN compute_node n ON n.id = e.targetNodeId AND n.workspaceId = e.workspaceId
        WHERE e.workspaceId = ? AND e.deletedAt IS NULL
          AND (w.id IS NULL OR p.id IS NULL OR d.id IS NULL OR n.id IS NULL)`,
      workspaceId,
    ),
    crossOrgDomainConflict: await total(
      `SELECT COUNT(*) AS total FROM (
         SELECT hostname FROM exposure_domain WHERE deletedAt IS NULL
          GROUP BY hostname HAVING COUNT(DISTINCT organizationId) > 1
       )`,
    ),
    zeroModeBypass: await eventCount(['exposure-zero-mode-bypass', 'exposure-paid-provider-bypass']),
  };
}
