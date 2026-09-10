/**
 * The decisions behind the replacement-recovery screen, kept out of the
 * component so they can be tested as what they are: rules, not rendering.
 */

export type RecoveryDeployment = {
  id: string;
  name: string;
  nodeId: string | null;
  nodeName: string | null;
  desiredState: 'running' | 'stopped';
  recoveryReasonCode: string | null;
  observedState: string | null;
  health: string | null;
  desiredRevision: number;
  currentArtifactId: string | null;
  artifactChecksum: string | null;
  localPort: number | null;
};

export type ReplacementCandidate = {
  id: string;
  name: string;
  agentVersion: string;
  status: 'online' | 'stale' | 'offline' | 'revoked';
  assignmentsDisabled: boolean;
  replacementImport: boolean;
};

/** The placeholder is deliberate: this is a template, not a path we know. */
export const IMPORT_COMMAND_PLACEHOLDER = '<path-to-backup>.ysdbak';

export function importCommand(): string {
  return `ysd-node-agent artifact backup import "${IMPORT_COMMAND_PLACEHOLDER}"`;
}

/**
 * A node may take a transferred deployment only if the control plane would
 * accept it, and only if its Agent can actually perform the import. A 0.8.0
 * node is a perfectly healthy node that simply cannot do this, so it is named
 * as incompatible rather than silently missing -- and it cannot be selected.
 */
export function eligibleReplacements(
  candidates: readonly ReplacementCandidate[],
  lostNodeId: string | null,
): ReplacementCandidate[] {
  return candidates.filter((candidate) =>
    candidate.id !== lostNodeId &&
    candidate.status !== 'revoked' &&
    !candidate.assignmentsDisabled &&
    candidate.replacementImport);
}

/** What the deployment is truthfully doing, in the operator's words. */
export function recoveryPhase(deployment: RecoveryDeployment): {
  label: string;
  detail: string;
} {
  if (deployment.recoveryReasonCode === 'node_lost') {
    return {
      label: 'Deployment preserved',
      detail: 'Waiting for a replacement Compute Node. Nothing was deleted, and the desired state below is unchanged.',
    };
  }
  if (deployment.recoveryReasonCode === 'awaiting_import') {
    return {
      label: 'Ownership transferred',
      detail: 'Waiting for the artifact backup to be imported on the replacement Compute Node.',
    };
  }
  if (deployment.health === 'healthy') {
    return { label: 'Healthy', detail: 'The replacement node is serving this deployment.' };
  }
  if (deployment.desiredState === 'stopped') {
    return {
      label: 'Artifact restored, runtime stopped',
      detail: 'The imported artifact is verified and present. This deployment is intentionally stopped, so nothing will start it.',
    };
  }
  return {
    label: 'Waiting for reconciliation',
    detail: 'The artifact is verified. Recovery starts it on its own; no Start command is needed.',
  };
}
