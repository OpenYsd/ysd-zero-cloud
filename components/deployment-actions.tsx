'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { DeploymentReleases } from '@/components/deployment-releases';
import type { Deployment } from '@/lib/domain';

export function DeploymentActions({ deployment }: { deployment: Deployment }) {
  const router = useRouter();
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (deployment.target !== 'user-node' || deployment.state === 'blocked' || deployment.state === 'deleted') return null;
  const busy = ['queued', 'building', 'starting', 'restarting', 'rolling_back', 'stopping', 'deleting', 'cancelling'].includes(deployment.state);

  async function act(operation: string) {
    setPending(operation);
    setError(null);
    try {
      const response = await fetch(`/api/deployments/${deployment.id}/actions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Idempotency-Key': `ui:${deployment.id}:${operation}:${deployment.updatedAt}` },
        body: JSON.stringify({ operation }),
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(body.error ?? `The ${operation} action was refused.`);
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The action failed.');
    } finally {
      setPending(null);
    }
  }

  const actions = busy
    ? ['cancel']
    : deployment.state === 'healthy'
      ? ['stop', 'restart', 'redeploy', 'delete']
      : ['start', 'redeploy', 'delete'];
  return (
    <div className="min-w-44">
      <div className="flex flex-wrap gap-1">
        {actions.map((action) => <Button key={action} variant="outline" size="sm" className="h-6 px-2 text-[9px]" disabled={pending !== null} onClick={() => void act(action)}>{pending === action ? '…' : action}</Button>)}
        {/* Rollback lives in Releases, where a target is chosen and previewed
            rather than guessed at from the newest verified artifact. */}
        <DeploymentReleases deployment={deployment} />
      </div>
      {error && <p className="mt-1 max-w-52 text-[9px] text-red-300">{error}</p>}
    </div>
  );
}
