/**
 * Release history and rollback preview.
 *
 * Reads only. Nothing here queues a job, writes an artifact, or moves
 * `currentArtifactId` -- a preview that mutated anything would be a worse lie
 * than no preview at all. Execution lives in `deployments.ts` and re-runs
 * every check this module runs, because a preview is advisory and the gap
 * between looking and clicking is exactly where things change.
 */

import type { AppArtifact } from '@/lib/domain';
import { deriveNodeStatus, parseCapabilities } from '@/lib/nodes';
import { deploymentBlockers } from '@/lib/node-preflight';
import {
  boundedReleasePageSize,
  classifyRelease,
  evaluateRollbackEligibility,
  parseReleaseCursor,
  releaseLabel,
  releaseStatusLabel,
  rollbackReasonMessage,
  type ReleaseStatus,
  type RollbackReasonCode,
} from '@/lib/releases';
import { getDeployment } from './deployments';
import { query, queryOne } from './db';

export type ReleaseSummary = {
  artifactId: string;
  label: string;
  version: number;
  status: ReleaseStatus;
  statusLabel: string;
  isCurrent: boolean;
  commitSha: string;
  /** Short fingerprint only. The full digest is never a browser concern. */
  checksumPrefix: string | null;
  sizeBytes: number;
  createdAt: number;
  verifiedAt: number | null;
  activatedAt: number | null;
  canRollback: boolean;
  reasons: RollbackReasonCode[];
};

export type ReleaseHistory = {
  deploymentId: string;
  currentArtifactId: string | null;
  node: { id: string; name: string | null; status: string } | null;
  releases: ReleaseSummary[];
  nextCursor: string | null;
};

type NodeFacts = {
  status: 'online' | 'stale' | 'offline' | 'revoked';
  appRuntimeAvailable: boolean;
  blockers: readonly string[];
};

type NodeRow = {
  id: string;
  name: string;
  capabilities: string;
  lastHeartbeatAt: number | null;
  revokedAt: number | null;
  agentVersion: string | null;
  protocolVersion: number | null;
};

/**
 * Node readiness, resolved once per request.
 *
 * A history page of 25 releases still costs one node read, because every row
 * on a page shares the same node -- an artifact cannot belong to a different
 * one and remain restorable.
 */
async function nodeFacts(workspaceId: string, nodeId: string | null): Promise<{ facts: NodeFacts | null; row: NodeRow | null }> {
  if (!nodeId) return { facts: null, row: null };
  const row = await queryOne<NodeRow>(
    `SELECT id, name, capabilities, lastHeartbeatAt, revokedAt, agentVersion, protocolVersion
     FROM compute_node WHERE workspaceId = ? AND id = ?`,
    workspaceId,
    nodeId,
  );
  if (!row) return { facts: null, row: null };
  const status = deriveNodeStatus({
    revokedAt: row.revokedAt,
    lastHeartbeatAt: row.lastHeartbeatAt,
    now: Date.now(),
  });
  let capabilities = null;
  try {
    capabilities = parseCapabilities(JSON.parse(row.capabilities) as unknown);
  } catch {
    capabilities = null;
  }
  return {
    row,
    facts: {
      status,
      appRuntimeAvailable: Boolean(capabilities?.contracts.appRuntime && capabilities.appRuntime?.available),
      blockers: capabilities
        ? deploymentBlockers({
            belongsToWorkspace: true,
            status,
            agentVersion: row.agentVersion,
            protocolVersion: row.protocolVersion,
            capabilities,
          })
        : ['app-runtime-contract'],
    },
  };
}

function summarize(
  artifact: AppArtifact,
  deployment: { id: string; projectId: string | null; nodeId: string | null; state: string; currentArtifactId: string | null; deletedAt: number | null },
  facts: NodeFacts | null,
): ReleaseSummary {
  const status = classifyRelease({ artifact, currentArtifactId: deployment.currentArtifactId });
  const eligibility = evaluateRollbackEligibility({ artifact, deployment, node: facts });
  return {
    artifactId: artifact.id,
    label: releaseLabel(artifact.version),
    version: artifact.version,
    status,
    statusLabel: releaseStatusLabel(status),
    isCurrent: artifact.id === deployment.currentArtifactId,
    commitSha: artifact.commitSha,
    checksumPrefix: artifact.checksum ? artifact.checksum.replace(/^sha256:/, '').slice(0, 12) : null,
    sizeBytes: artifact.sizeBytes,
    createdAt: artifact.createdAt,
    verifiedAt: artifact.verifiedAt,
    activatedAt: artifact.activatedAt,
    canRollback: eligibility.eligible,
    reasons: eligibility.reasons,
  };
}

/**
 * One page of a deployment's releases, newest first.
 *
 * Failed and superseded releases stay in the list. Hiding a failed build
 * would make the history read as though it never happened, and the whole
 * point of this view is that it matches what occurred.
 *
 * Cost is fixed: one deployment read, one node read, one artifact page.
 * Nothing is fetched per row.
 */
export async function listReleases(input: {
  workspaceId: string;
  deploymentId: string;
  allowedProjectIds?: readonly string[] | null;
  limit?: unknown;
  cursor?: unknown;
}): Promise<ReleaseHistory | null> {
  const deployment = await getDeployment(input.workspaceId, input.deploymentId, input.allowedProjectIds);
  if (!deployment) return null;
  const pageSize = boundedReleasePageSize(input.limit);
  const cursor = parseReleaseCursor(input.cursor);
  const { facts, row } = await nodeFacts(input.workspaceId, deployment.nodeId);

  // `version` is unique per (project, node) and therefore a total order
  // within one deployment, which makes it a stable cursor even while new
  // releases are being appended above the page being read.
  const artifacts = await query<AppArtifact>(
    `SELECT id, deploymentId, projectId, nodeId, commitSha, version, state,
            checksum, sizeBytes, createdAt, verifiedAt, activatedAt
       FROM app_artifact
      WHERE workspaceId = ? AND deploymentId = ?${cursor === null ? '' : ' AND version < ?'}
      ORDER BY version DESC
      LIMIT ?`,
    input.workspaceId,
    input.deploymentId,
    ...(cursor === null ? [] : [cursor]),
    pageSize + 1,
  );
  const page = artifacts.slice(0, pageSize);
  const scope = {
    id: deployment.id,
    projectId: deployment.projectId,
    nodeId: deployment.nodeId,
    state: deployment.state,
    currentArtifactId: deployment.currentArtifactId,
    deletedAt: deployment.deletedAt,
  };
  return {
    deploymentId: deployment.id,
    currentArtifactId: deployment.currentArtifactId,
    node: row ? { id: row.id, name: row.name, status: facts?.status ?? 'offline' } : null,
    releases: page.map((artifact) => summarize(artifact, scope, facts)),
    nextCursor: artifacts.length > pageSize ? String(page[page.length - 1]!.version) : null,
  };
}

export type RollbackPreview = {
  deploymentId: string;
  current: ReleaseSummary | null;
  target: ReleaseSummary | null;
  eligible: boolean;
  reasons: RollbackReasonCode[];
  messages: string[];
  node: { id: string; name: string | null; status: string } | null;
  /** What the caller must echo back to execute, so a stale view cannot act. */
  expectedCurrentArtifactId: string | null;
  impact: string;
};

/**
 * Answer "what would happen if I restored this release" without doing any of
 * it.
 *
 * The answer is advisory by construction: it is recomputed from live state at
 * execute time, and the only thing carried forward is
 * `expectedCurrentArtifactId`, which the server compares rather than trusts.
 */
export async function previewRollback(input: {
  workspaceId: string;
  deploymentId: string;
  targetArtifactId: string;
  allowedProjectIds?: readonly string[] | null;
}): Promise<RollbackPreview | null> {
  const deployment = await getDeployment(input.workspaceId, input.deploymentId, input.allowedProjectIds);
  if (!deployment) return null;
  const { facts, row } = await nodeFacts(input.workspaceId, deployment.nodeId);
  const scope = {
    id: deployment.id,
    projectId: deployment.projectId,
    nodeId: deployment.nodeId,
    state: deployment.state,
    currentArtifactId: deployment.currentArtifactId,
    deletedAt: deployment.deletedAt,
  };

  // Scoped exactly like the execute-time lookup, so a foreign or mismatched
  // id produces the same "not recorded here" answer in both places.
  const target = /^art_[a-f0-9]{24}$/.test(input.targetArtifactId)
    ? await queryOne<AppArtifact>(
        `SELECT id, deploymentId, projectId, nodeId, commitSha, version, state,
                checksum, sizeBytes, createdAt, verifiedAt, activatedAt
           FROM app_artifact
          WHERE workspaceId = ? AND deploymentId = ? AND id = ? AND deletedAt IS NULL`,
        input.workspaceId,
        input.deploymentId,
        input.targetArtifactId,
      )
    : null;
  const current = deployment.currentArtifactId
    ? await queryOne<AppArtifact>(
        `SELECT id, deploymentId, projectId, nodeId, commitSha, version, state,
                checksum, sizeBytes, createdAt, verifiedAt, activatedAt
           FROM app_artifact
          WHERE workspaceId = ? AND deploymentId = ? AND id = ?`,
        input.workspaceId,
        input.deploymentId,
        deployment.currentArtifactId,
      )
    : null;

  const eligibility = evaluateRollbackEligibility({ artifact: target, deployment: scope, node: facts });
  return {
    deploymentId: deployment.id,
    current: current ? summarize(current, scope, facts) : null,
    target: target ? summarize(target, scope, facts) : null,
    eligible: eligibility.eligible,
    reasons: eligibility.reasons,
    messages: eligibility.reasons.map(rollbackReasonMessage),
    node: row ? { id: row.id, name: row.name, status: facts?.status ?? 'offline' } : null,
    expectedCurrentArtifactId: deployment.currentArtifactId,
    // No downtime claim. The node stops the running process before it starts
    // the target one, so there is a gap, and saying otherwise would be
    // inventing a guarantee the runtime does not offer.
    impact: target
      ? `This private service will stop and restart from release ${releaseLabel(target.version)}. It is briefly unavailable while it switches.`
      : 'No release is selected.',
  };
}
