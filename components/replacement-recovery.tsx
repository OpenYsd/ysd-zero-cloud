'use client';

import { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AlertTriangle, Loader2 } from 'lucide-react';

import { Button } from '@/components/ui/button';
import {
  eligibleReplacements,
  importCommand,
  recoveryPhase,
  type RecoveryDeployment,
  type ReplacementCandidate,
} from '@/lib/replacement-recovery';
import { cn } from '@/lib/utils';

/**
 * Replacement-node disaster recovery, from the operator's side.
 *
 * This screen exists for a bad day: a machine is gone and the applications that
 * ran on it are not. It is deliberately unhurried -- every step names what is
 * about to happen, and the irreversible ones ask before they act. Nothing here
 * starts an application; the last thing the operator does is hand the
 * deployment back to ordinary reconciliation.
 */

export function ReplacementRecovery({
  deployment,
  candidates,
}: {
  deployment: RecoveryDeployment;
  candidates: readonly ReplacementCandidate[];
}): React.JSX.Element | null {
  const router = useRouter();
  const [replacementNodeId, setReplacementNodeId] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stale, setStale] = useState(false);

  const eligible = useMemo(
    () => eligibleReplacements(candidates, deployment.nodeId),
    [candidates, deployment.nodeId],
  );
  const phase = recoveryPhase(deployment);
  const lost = deployment.recoveryReasonCode === 'node_lost';
  const awaiting = deployment.recoveryReasonCode === 'awaiting_import';

  async function transfer(): Promise<void> {
    const replacement = eligible.find((candidate) => candidate.id === replacementNodeId);
    if (!replacement || !deployment.nodeId || !deployment.currentArtifactId) return;
    const confirmed = window.confirm(
      [
        `Transfer ${deployment.name} to ${replacement.name}?`,
        '',
        `Source node: ${deployment.nodeName ?? deployment.nodeId}`,
        `Replacement node: ${replacement.name}`,
        `Deployment: ${deployment.id}`,
        `Desired state: ${deployment.desiredState}`,
        `Source artifact: ${deployment.currentArtifactId}`,
        '',
        'The replacement node becomes the only node YSD will accept control-plane work from for this deployment. A process on the lost machine may still exist if that machine is ever powered on.',
      ].join('\n'),
    );
    if (!confirmed) return;
    setPending(true);
    setError(null);
    try {
      const response = await fetch(`/api/deployments/${deployment.id}/transfer`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          sourceNodeId: deployment.nodeId,
          replacementNodeId: replacement.id,
          expectedDesiredRevision: deployment.desiredRevision,
          expectedArtifactId: deployment.currentArtifactId,
        }),
      });
      const body = (await response.json()) as { error?: string };
      if (response.status === 409) {
        // Something moved while this screen was open. Sending the same values
        // again would only lose the same race, so the view is refreshed and the
        // operator decides against what is actually true now.
        setStale(true);
        setError(body.error ?? 'This deployment changed. The view has been refreshed.');
        router.refresh();
        return;
      }
      if (!response.ok) throw new Error(body.error ?? 'The transfer was refused.');
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The transfer failed.');
    } finally {
      setPending(false);
    }
  }

  if (!lost && !awaiting) return null;

  return (
    <section
      aria-labelledby="replacement-recovery-heading"
      className="rounded-xl border border-amber-300/20 bg-amber-300/[0.04] p-4 sm:p-5"
    >
      <div className="flex items-start gap-3">
        <AlertTriangle aria-hidden className="mt-0.5 size-4 shrink-0 text-amber-200" />
        <div className="min-w-0">
          <h2 id="replacement-recovery-heading" className="text-sm font-medium text-amber-100">
            {phase.label}
          </h2>
          <p className="mt-1 text-xs leading-relaxed text-white/60">{phase.detail}</p>
        </div>
      </div>

      <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
        <div className="flex justify-between gap-3 sm:block">
          <dt className="text-white/38">Desired state</dt>
          <dd className="text-white/75">{deployment.desiredState}</dd>
        </div>
        <div className="flex justify-between gap-3 sm:block">
          <dt className="text-white/38">{lost ? 'Lost node' : 'Replacement node'}</dt>
          <dd className="truncate text-white/75">{deployment.nodeName ?? deployment.nodeId ?? 'Unknown'}</dd>
        </div>
        <div className="flex justify-between gap-3 sm:block">
          <dt className="text-white/38">Source artifact</dt>
          <dd className="truncate font-mono text-[11px] text-white/75">
            {deployment.currentArtifactId ?? 'None'}
          </dd>
        </div>
        {deployment.artifactChecksum ? (
          <div className="flex justify-between gap-3 sm:block">
            <dt className="text-white/38">Artifact checksum</dt>
            <dd className="truncate font-mono text-[11px] text-white/75">{deployment.artifactChecksum}</dd>
          </div>
        ) : null}
        {deployment.localPort ? (
          <div className="flex justify-between gap-3 sm:block">
            <dt className="text-white/38">Preferred private port</dt>
            <dd className="text-white/75">
              {deployment.localPort}
              {awaiting ? (
                <span className="ml-1 text-white/38">renegotiated on the replacement node</span>
              ) : null}
            </dd>
          </div>
        ) : null}
      </dl>

      {lost ? (
        <div className="mt-5 border-t border-white/[0.06] pt-4">
          <label htmlFor="replacement-node" className="block text-xs text-white/60">
            Replacement Compute Node
          </label>
          {eligible.length === 0 ? (
            <p className="mt-2 text-xs text-amber-200/80">
              No compatible replacement Compute Node is available. Pair a node running Agent 0.9.0 or
              later, with assignments enabled, then return here.
            </p>
          ) : (
            <div className="mt-2 flex flex-col gap-2 sm:flex-row sm:items-center">
              <select
                id="replacement-node"
                value={replacementNodeId}
                onChange={(event) => setReplacementNodeId(event.target.value)}
                className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-white/80 sm:max-w-xs"
              >
                <option value="">Select a node</option>
                {eligible.map((candidate) => (
                  <option key={candidate.id} value={candidate.id}>
                    {candidate.name} - Agent {candidate.agentVersion}
                  </option>
                ))}
              </select>
              <Button
                variant="secondary"
                size="sm"
                disabled={pending || !replacementNodeId}
                onClick={() => void transfer()}
              >
                {pending ? <Loader2 className="animate-spin" /> : null}
                Transfer ownership
              </Button>
            </div>
          )}
          {candidates.some((candidate) => !candidate.replacementImport && candidate.status !== 'revoked') ? (
            <p className="mt-2 text-[11px] text-white/38">
              Nodes running an Agent older than 0.9.0 cannot import a replacement artifact and are not
              listed.
            </p>
          ) : null}
        </div>
      ) : null}

      {awaiting ? (
        <div className="mt-5 border-t border-white/[0.06] pt-4">
          <p className="text-xs text-white/60">
            On the replacement Compute Node, import the backup you already hold:
          </p>
          <pre className="mt-2 overflow-x-auto rounded-lg border border-white/10 bg-black/40 px-3 py-2 font-mono text-[11px] text-white/75">
            <code>{importCommand()}</code>
          </pre>
          <p className="mt-2 text-[11px] text-white/38">
            The Agent verifies the bundle offline first, installs it under a new artifact id issued by
            the control plane, and reports back. It starts nothing:{' '}
            {deployment.desiredState === 'stopped'
              ? 'this deployment is intentionally stopped, so the artifact is restored and left stopped.'
              : 'recovery starts it once the import completes. No Start command is needed.'}
          </p>
        </div>
      ) : null}

      <div className="mt-5 border-t border-white/[0.06] pt-4 text-[11px] leading-relaxed text-white/38">
        <p>
          <span className="text-white/55">A backup contains</span> the immutable application artifact.{' '}
          <span className="text-white/55">It does not contain</span> runtime data, databases,
          game-world data, or machine state.
        </p>
        <p className="mt-1">
          This is replacement-node disaster recovery. It is not automatic failover, not high
          availability, and not zero-downtime migration.
        </p>
        <p className="mt-1">
          <span className="text-white/55">Public exposure stays disabled after disaster recovery.</span>{' '}
          Nothing records which mode it was serving before the machine was lost, so it is not
          guessed. Review the recovered application and re-enable exposure when you are ready.
        </p>
      </div>

      {error ? (
        <output className={cn('mt-4 block text-xs', stale ? 'text-amber-200' : 'text-red-300')}>
          {error}
        </output>
      ) : null}
    </section>
  );
}
