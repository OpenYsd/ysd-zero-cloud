'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import type { AppArtifact, Deployment } from '@/lib/domain';

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
      let targetArtifactId: string | undefined;
      if (operation === 'rollback') {
        const detailResponse = await fetch(`/api/deployments/${deployment.id}`);
        const detail = (await detailResponse.json()) as { deployment?: { artifacts?: AppArtifact[] }; error?: string };
        targetArtifactId = detail.deployment?.artifacts?.find((artifact) => artifact.state === 'verified' && artifact.id !== deployment.currentArtifactId)?.id;
        if (!targetArtifactId) throw new Error('No earlier verified artifact is available on this node.');
      }
      const response = await fetch(`/api/deployments/${deployment.id}/actions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Idempotency-Key': `ui:${deployment.id}:${operation}:${deployment.updatedAt}` },
        body: JSON.stringify({ operation, targetArtifactId }),
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
      ? ['stop', 'restart', 'redeploy', 'rollback', 'delete']
      : ['start', 'redeploy', 'rollback', 'delete'];
  return (
    <div className="min-w-44">
      <div className="flex flex-wrap gap-1">{actions.map((action) => <Button key={action} variant="outline" size="sm" className="h-6 px-2 text-[9px]" disabled={pending !== null} onClick={() => void act(action)}>{pending === action ? '…' : action}</Button>)}</div>
      {error && <p className="mt-1 max-w-52 text-[9px] text-red-300">{error}</p>}
    </div>
  );
}
