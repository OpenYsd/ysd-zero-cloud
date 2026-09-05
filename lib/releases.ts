/**
 * Release history and rollback eligibility.
 *
 * A *deployment* is one long-lived service: one node, one private port, one
 * directory on that node. An *artifact* is one release of that service. The
 * current release is whichever artifact `deployment.currentArtifactId` points
 * at -- runtime truth the node reported, never "the newest row".
 *
 * Rollback re-activates an already-built, already-verified artifact. It never
 * rebuilds, and it cannot reach across deployments or across nodes, because
 * the bytes only exist in one place:
 *
 *   <root>/workspaces/<ws>/projects/<prj>/deployments/<dpl>/artifacts/<art>
 *
 * The agent resolves that path from the deployment the *job* names, so an
 * artifact belonging to another deployment simply is not there. Everything
 * below treats that as a hard boundary rather than something to work around.
 *
 * This module is pure so it can be tested without D1 or `cloudflare:workers`.
 * It decides nothing on its own: the server re-runs it where it is
 * authoritative, and a browser cannot pass a verdict in.
 */

import type { AppArtifact } from './domain';

export const RELEASE_PAGE_SIZE = 25;
export const RELEASE_PAGE_MAXIMUM = 50;

/**
 * How a release is labelled to a person.
 *
 * `app_artifact.version` is `MAX(version) + 1` scoped to project *and node*,
 * so one service's releases can read v2, v5, v8 when other services on the
 * same node consumed the numbers between. That is honest and, more
 * importantly, stable: a label never renumbers because an older row was
 * removed, which is what makes it safe to quote in evidence. A derived
 * per-deployment row number would not survive a deletion.
 */
export function releaseLabel(version: number): string {
  return `v${version}`;
}

export type ReleaseStatus =
  | 'current'
  | 'superseded'
  | 'building'
  | 'failed'
  | 'corrupted'
  | 'unavailable';

/**
 * Deployment states in which the runtime can accept a lifecycle action.
 * Anything else is either mid-flight or gone.
 */
const IDLE_DEPLOYMENT_STATES = new Set(['healthy', 'stopped', 'failed', 'crash_loop']);

const BUSY_DEPLOYMENT_STATES = new Set([
  'queued',
  'building',
  'starting',
  'stopping',
  'restarting',
  'rolling_back',
  'deleting',
  'cancelling',
]);

export function classifyRelease(input: {
  artifact: Pick<AppArtifact, 'id' | 'state'>;
  currentArtifactId: string | null;
}): ReleaseStatus {
  const { artifact } = input;
  if (artifact.state === 'deleted') return 'unavailable';
  if (artifact.state === 'corrupted') return 'corrupted';
  if (artifact.state === 'failed') return 'failed';
  if (artifact.state === 'building') return 'building';
  return artifact.id === input.currentArtifactId ? 'current' : 'superseded';
}

/**
 * Wording that does not overclaim.
 *
 * A superseded artifact was healthy when it was replaced; it is not running
 * now, and calling it "Healthy" in a history list would say otherwise.
 */
export function releaseStatusLabel(status: ReleaseStatus): string {
  switch (status) {
    case 'current':
      return 'Current release';
    case 'superseded':
      return 'Verified · previously active';
    case 'building':
      return 'Building';
    case 'failed':
      return 'Build failed';
    case 'corrupted':
      return 'Integrity check failed';
    case 'unavailable':
      return 'Artifact no longer on the node';
  }
}

export type RollbackReasonCode =
  | 'current_release'
  | 'artifact_missing'
  | 'artifact_unverified'
  | 'artifact_corrupted'
  | 'artifact_deleted'
  | 'wrong_deployment'
  | 'wrong_project'
  | 'wrong_node'
  | 'node_offline'
  | 'node_incompatible'
  | 'runtime_unavailable'
  | 'deployment_busy'
  | 'deployment_unavailable'
  | 'stale_current_release';

/** Fixed, server-authored remediation. Node-supplied text never reaches this. */
export function rollbackReasonMessage(code: RollbackReasonCode): string {
  switch (code) {
    case 'current_release':
      return 'This release is already running.';
    case 'artifact_missing':
      return 'That release is not recorded for this deployment.';
    case 'artifact_unverified':
      return 'Only a release that finished building and passed verification can be restored.';
    case 'artifact_corrupted':
      return 'This release failed its integrity check and will not be started.';
    case 'artifact_deleted':
      return 'The node no longer holds this release. Deploy a new release instead.';
    case 'wrong_deployment':
      return 'That release belongs to a different service.';
    case 'wrong_project':
      return 'That release belongs to a different project.';
    case 'wrong_node':
      return 'That release was built on a different Compute Node and its files only exist there.';
    case 'node_offline':
      return 'The Compute Node holding this release is not online.';
    case 'node_incompatible':
      return 'The Compute Node needs an agent update before it can run this action.';
    case 'runtime_unavailable':
      return 'The Compute Node is not offering the App Runtime right now.';
    case 'deployment_busy':
      return 'Another action is already running on this deployment.';
    case 'deployment_unavailable':
      return 'This deployment cannot accept actions.';
    case 'stale_current_release':
      return 'The running release changed while you were deciding. Review the history again.';
  }
}

export type RollbackEligibilityInput = {
  artifact: Pick<AppArtifact, 'id' | 'deploymentId' | 'projectId' | 'nodeId' | 'state'> | null;
  deployment: {
    id: string;
    projectId: string | null;
    nodeId: string | null;
    state: string;
    currentArtifactId: string | null;
    deletedAt: number | null;
  };
  /**
   * Node facts. `null` means "not evaluated here" -- the list view leaves
   * these out so it stays cheap, and preview/execute fill them in.
   */
  node: {
    status: 'online' | 'stale' | 'offline' | 'revoked';
    appRuntimeAvailable: boolean;
    blockers: readonly string[];
  } | null;
};

export type RollbackEligibility = {
  eligible: boolean;
  reasons: RollbackReasonCode[];
};

/**
 * The single place that decides whether a release may be restored.
 *
 * Ordered so the most specific, least leaky reason wins: a caller probing for
 * another tenant's artifact gets `artifact_missing`, the same answer an
 * entirely made-up id gets, because the lookup that feeds this is scoped and
 * simply returns nothing.
 */
export function evaluateRollbackEligibility(input: RollbackEligibilityInput): RollbackEligibility {
  const reasons: RollbackReasonCode[] = [];
  const { artifact, deployment, node } = input;

  if (deployment.deletedAt !== null || deployment.state === 'blocked' || deployment.state === 'deleted') {
    reasons.push('deployment_unavailable');
  } else if (BUSY_DEPLOYMENT_STATES.has(deployment.state)) {
    reasons.push('deployment_busy');
  } else if (!IDLE_DEPLOYMENT_STATES.has(deployment.state)) {
    reasons.push('deployment_unavailable');
  }

  if (!artifact) {
    reasons.push('artifact_missing');
    return { eligible: false, reasons };
  }

  if (artifact.deploymentId !== deployment.id) reasons.push('wrong_deployment');
  if (deployment.projectId && artifact.projectId !== deployment.projectId) reasons.push('wrong_project');
  if (deployment.nodeId && artifact.nodeId !== deployment.nodeId) reasons.push('wrong_node');

  if (artifact.id === deployment.currentArtifactId) reasons.push('current_release');

  if (artifact.state === 'deleted') reasons.push('artifact_deleted');
  else if (artifact.state === 'corrupted') reasons.push('artifact_corrupted');
  else if (artifact.state !== 'verified') reasons.push('artifact_unverified');

  if (node) {
    if (node.status !== 'online') reasons.push('node_offline');
    else if (!node.appRuntimeAvailable) reasons.push('runtime_unavailable');
    if (node.blockers.length > 0) reasons.push('node_incompatible');
  }

  return { eligible: reasons.length === 0, reasons };
}

/**
 * Cheap eligibility for a history page.
 *
 * Node readiness is evaluated once for the whole page, not per row, so a list
 * of 25 releases still costs one node read. A row that looks restorable here
 * is re-checked in full at preview and again at execute; this only decides
 * whether the button is offered.
 */
export function releaseRollbackSummary(input: RollbackEligibilityInput): RollbackEligibility {
  return evaluateRollbackEligibility(input);
}

export function boundedReleasePageSize(requested: unknown): number {
  const value =
    typeof requested === 'number'
      ? requested
      : typeof requested === 'string'
        ? Number.parseInt(requested, 10)
        : Number.NaN;
  if (!Number.isSafeInteger(value) || value < 1) return RELEASE_PAGE_SIZE;
  return Math.min(RELEASE_PAGE_MAXIMUM, value);
}

/**
 * History pages walk backwards through `version`, which is unique per
 * (project, node) and therefore a total order within one deployment. Using it
 * as the cursor keeps paging stable while new releases are being added at the
 * top.
 */
export function parseReleaseCursor(value: unknown): number | null {
  if (typeof value !== 'string' || !/^[0-9]{1,9}$/.test(value)) return null;
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

/** Artifact ids the node reports as pruned, filtered to a shape we will act on. */
export function parsePrunedArtifactIds(value: unknown, maximum = 32): string[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  for (const entry of value) {
    if (typeof entry !== 'string' || !/^art_[a-f0-9]{24}$/.test(entry)) continue;
    seen.add(entry);
    if (seen.size >= maximum) break;
  }
  return [...seen];
}
