import type { AppRuntimeOperation } from './app-runtime.ts';

export const RECOVERY_MINIMUM_AGENT_VERSION = '0.5.0' as const;

export const DEPLOYMENT_DESIRED_STATES = ['running', 'stopped'] as const;
export type DeploymentDesiredState = (typeof DEPLOYMENT_DESIRED_STATES)[number];

export const DEPLOYMENT_OBSERVED_STATES = [
  'unknown', 'healthy', 'stopped', 'missing', 'recovering', 'unhealthy', 'blocked',
] as const;
export type DeploymentObservedState = (typeof DEPLOYMENT_OBSERVED_STATES)[number];

export const RECOVERY_STATUSES = ['pending', 'succeeded', 'blocked', 'failed'] as const;
export type RecoveryStatus = (typeof RECOVERY_STATUSES)[number];

export const ARTIFACT_AVAILABILITY_STATES = ['unknown', 'present', 'missing', 'corrupted'] as const;
export type ArtifactAvailabilityState = (typeof ARTIFACT_AVAILABILITY_STATES)[number];

export const RUNTIME_HEALTH_STATES = ['unknown', 'healthy', 'unhealthy'] as const;
export type RuntimeHealthState = (typeof RUNTIME_HEALTH_STATES)[number];

export const RECOVERY_PHASES = [
  'reconcile', 'artifact_verify', 'activate', 'start', 'health', 'retention',
] as const;
export type RecoveryPhase = (typeof RECOVERY_PHASES)[number];

export const RECOVERY_REASON_CODES = [
  'recovery_succeeded',
  'desired_stopped',
  'process_missing',
  'artifact_missing',
  'artifact_corrupted',
  'artifact_unavailable',
  'port_in_use',
  'runtime_incompatible',
  'node_revoked',
  'node_lost',
  'awaiting_import',
  'health_failed',
  'disk_low',
  'recovery_busy',
  'stale_desired_revision',
  'reconciliation_failed',
] as const;
export type RecoveryReasonCode = (typeof RECOVERY_REASON_CODES)[number];

export function recoveryReasonMessage(code: RecoveryReasonCode): string {
  const messages: Record<RecoveryReasonCode, string> = {
    recovery_succeeded: 'The current verified artifact recovered successfully.',
    desired_stopped: 'This deployment is intentionally stopped.',
    process_missing: 'The expected runtime process is not managed by this Agent.',
    artifact_missing: 'The current artifact is missing from this Compute Node.',
    artifact_corrupted: 'The current artifact failed integrity verification.',
    artifact_unavailable: 'The current artifact is unavailable on this Compute Node.',
    port_in_use: 'The assigned private port is already in use. No process was stopped or adopted.',
    runtime_incompatible: 'Upgrade this Compute Node to Agent 0.5.0 before recovery.',
    node_revoked: 'This Compute Node is revoked and cannot recover deployments.',
    node_lost: 'This Compute Node was declared permanently lost. Transfer this deployment to a replacement node.',
    awaiting_import: 'This deployment is waiting for its artifact backup to be imported on the replacement node.',
    health_failed: 'The recovered runtime did not pass its health check.',
    disk_low: 'The Compute Node does not have enough free disk for safe recovery.',
    recovery_busy: 'Another deployment lifecycle action is already in progress.',
    stale_desired_revision: 'The deployment intent changed before recovery completed.',
    reconciliation_failed: 'Runtime reconciliation could not complete safely.',
  };
  return messages[code];
}

function versionParts(value: string): number[] | null {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(value);
  return match ? match.slice(1).map(Number) : null;
}

export function recoveryAgentCompatible(version: string): boolean {
  const actual = versionParts(version);
  const required = versionParts(RECOVERY_MINIMUM_AGENT_VERSION)!;
  if (!actual) return false;
  for (let index = 0; index < required.length; index += 1) {
    if (actual[index]! !== required[index]!) return actual[index]! > required[index]!;
  }
  return true;
}

export function desiredStateAfterOperation(
  current: DeploymentDesiredState,
  operation: AppRuntimeOperation,
): DeploymentDesiredState {
  if (operation === 'stop' || operation === 'delete') return 'stopped';
  if (operation === 'status' || operation === 'recover') return current;
  return 'running';
}

export function operationBumpsDesiredRevision(operation: AppRuntimeOperation): boolean {
  return operation !== 'status' && operation !== 'recover';
}

export function deriveLegacyRuntimeTruth(state: string): {
  desiredState: DeploymentDesiredState;
  desiredRevision: 1;
  observedState: DeploymentObservedState;
} {
  const stopped = new Set([
    'planned', 'blocked', 'stopping', 'stopped', 'deleting', 'deleted',
    'cancelled', 'node_revoked',
  ]);
  return {
    desiredState: stopped.has(state) ? 'stopped' : 'running',
    desiredRevision: 1,
    observedState: state === 'stopped' || state === 'deleted' ? 'stopped' : 'unknown',
  };
}

export function observedStateFromRuntime(input: {
  processRunning: boolean;
  health: RuntimeHealthState;
  crashLoop: boolean;
}): DeploymentObservedState {
  if (input.crashLoop) return 'blocked';
  if (!input.processRunning) return 'missing';
  if (input.health === 'healthy') return 'healthy';
  if (input.health === 'unhealthy') return 'unhealthy';
  return 'unknown';
}

export function shouldSpawnCrashReplacement(input: {
  scheduledRevision: number;
  currentRevision: number;
  desiredRunning: boolean;
  intentionalStop: boolean;
  sameRuntime: boolean;
}): boolean {
  return input.sameRuntime && input.desiredRunning && !input.intentionalStop &&
    input.scheduledRevision === input.currentRevision;
}

export function availabilityFromVerificationFailure(input: {
  code: string | null;
  integrityFailure: boolean;
}): ArtifactAvailabilityState {
  if (input.code === 'ENOENT') return 'missing';
  return input.integrityFailure ? 'corrupted' : 'unknown';
}

export function selectRetainedArtifacts(input: {
  currentArtifactId: string;
  previousVerifiedArtifactId: string | null;
  cap: number;
  artifacts: readonly { id: string; modifiedAt: number; verified: boolean }[];
}): Set<string> {
  const cap = Math.max(1, Math.floor(input.cap));
  const keep: string[] = [input.currentArtifactId];
  if (input.previousVerifiedArtifactId && input.previousVerifiedArtifactId !== input.currentArtifactId) {
    keep.push(input.previousVerifiedArtifactId);
  }
  for (const artifact of [...input.artifacts]
    .filter((item) => item.verified && /^art_[a-f0-9]{24}$/.test(item.id))
    .sort((left, right) => right.modifiedAt - left.modifiedAt)) {
    if (keep.length >= cap) break;
    if (!keep.includes(artifact.id)) keep.push(artifact.id);
  }
  return new Set(keep.slice(0, cap));
}

export type ReconciliationDeployment = {
  deploymentId: string;
  desiredState: DeploymentDesiredState;
  desiredRevision: number;
  currentArtifactId: string | null;
  busy: boolean;
  recoveryStatus: RecoveryStatus | null;
  recoveryRevision: number | null;
  recoveryGeneration?: string | null;
};

export function planRuntimeReconciliation(input: {
  agentVersion: string;
  managedDeploymentIds: readonly string[];
  deployments: readonly ReconciliationDeployment[];
  runtimeGeneration?: string | null;
}): { deploymentId: string; artifactId: string; expectedDesiredRevision: number }[] {
  if (!recoveryAgentCompatible(input.agentVersion)) return [];
  const managed = new Set(input.managedDeploymentIds);
  const plans: { deploymentId: string; artifactId: string; expectedDesiredRevision: number }[] = [];
  for (const deployment of input.deployments.slice(0, 12)) {
    if (deployment.desiredState !== 'running' || deployment.busy || !deployment.currentArtifactId ||
        managed.has(deployment.deploymentId)) continue;
    const sameRevision = deployment.recoveryRevision === deployment.desiredRevision;
    // A blocked or failed condition needs remediation or a new authoritative
    // intent revision; repeatedly restarting the Agent must not turn it into
    // an automatic retry loop. A prior success is different: a later Agent
    // generation can represent a genuinely new reboot/missing-runtime event.
    const attemptedThisRevision = sameRevision && (
      deployment.recoveryStatus === 'pending' ||
      deployment.recoveryStatus === 'blocked' ||
      deployment.recoveryStatus === 'failed' ||
      input.runtimeGeneration === undefined ||
      deployment.recoveryGeneration === input.runtimeGeneration
    );
    if (attemptedThisRevision) continue;
    plans.push({
      deploymentId: deployment.deploymentId,
      artifactId: deployment.currentArtifactId,
      expectedDesiredRevision: deployment.desiredRevision,
    });
  }
  return plans;
}
