'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { AlertTriangle, CheckCircle2, GitBranch, Loader2, LockKeyhole, Rocket, Server } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NativeSelect } from '@/components/ui/native-select';
import type { ComputeNode, Deployment } from '@/lib/domain';
import type { SmartDeployPlan } from '@/lib/smart-deploy';

export function SmartDeployPanel({ nodes, repositoryHint }: { nodes: ComputeNode[]; repositoryHint?: string }) {
  const router = useRouter();
  const eligible = nodes.filter((node) => node.status === 'online' && node.capabilities.appRuntime?.available);
  const [repository, setRepository] = useState(repositoryHint ?? 'owner/node-api');
  const [branch, setBranch] = useState('main');
  const [commit, setCommit] = useState('');
  const [nodeId, setNodeId] = useState(eligible[0]?.id ?? '');
  const [environment, setEnvironment] = useState('Production');
  const [healthPath, setHealthPath] = useState('/');
  const [plan, setPlan] = useState<SmartDeployPlan | null>(null);
  const [deployment, setDeployment] = useState<Deployment | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function deploy() {
    setPending(true);
    setError(null);
    try {
      const response = await fetch('/api/smart-deploy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': `ui:${repository}:${branch}:${commit || 'head'}:${nodeId}`.slice(0, 128),
        },
        body: JSON.stringify({ repository, branch, commit: commit || undefined, nodeId, environment, healthPath, target: 'user-node' }),
      });
      const body = (await response.json()) as { plan?: SmartDeployPlan; deployment?: Deployment; error?: string };
      if (body.plan) setPlan(body.plan);
      if (body.deployment) setDeployment(body.deployment);
      if (!response.ok) throw new Error(body.error ?? 'The safe deployment was refused.');
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The safe deployment was refused.');
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="cloud-card overflow-hidden">
      <div className="flex flex-col justify-between gap-3 border-b border-white/[0.065] px-5 py-4 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2"><Rocket className="size-4 text-[#b7ff3c]" /><h2 className="text-sm font-semibold text-white">YSD App Runtime</h2></div>
          <p className="mt-1 text-[11px] text-white/30">GitHub source → signed queue → selected user-owned Node → private localhost service.</p>
        </div>
        <div className="flex items-center gap-2 rounded-full border border-[#b7ff3c]/15 bg-[#b7ff3c]/5 px-2.5 py-1.5 text-[10px] font-semibold text-[#c8ff69]">
          <LockKeyhole className="size-3" /> Zero Mode enforced
        </div>
      </div>

      <div className="grid gap-4 p-5 lg:grid-cols-3">
        <label htmlFor="smart-deploy-repository" className="space-y-1.5 text-[11px] text-white/45">
          GitHub repository
          <div className="relative"><GitBranch className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-white/25" /><Input id="smart-deploy-repository" value={repository} onChange={(event) => setRepository(event.target.value)} placeholder="owner/repository" className="h-9 border-white/[0.08] bg-black/15 pl-9 text-xs" /></div>
        </label>
        <label htmlFor="smart-deploy-branch" className="space-y-1.5 text-[11px] text-white/45">Branch<Input id="smart-deploy-branch" value={branch} onChange={(event) => setBranch(event.target.value)} className="h-9 border-white/[0.08] bg-black/15 text-xs" /></label>
        <label htmlFor="smart-deploy-commit" className="space-y-1.5 text-[11px] text-white/45">Pinned commit <span className="text-white/20">optional full SHA</span><Input id="smart-deploy-commit" value={commit} onChange={(event) => setCommit(event.target.value)} placeholder="resolved from branch" className="h-9 border-white/[0.08] bg-black/15 font-mono text-xs" /></label>
        <label htmlFor="smart-deploy-node" className="space-y-1.5 text-[11px] text-white/45">Compute Node<NativeSelect id="smart-deploy-node" value={nodeId} onChange={(event) => setNodeId(event.target.value)} className="h-9 w-full border-white/[0.08] bg-black/15 text-xs"><option value="">Select a secure online node</option>{eligible.map((node) => <option key={node.id} value={node.id}>{node.name} · Node {node.capabilities.appRuntime?.nodeMajor}</option>)}</NativeSelect></label>
        <label htmlFor="smart-deploy-environment" className="space-y-1.5 text-[11px] text-white/45">Environment<NativeSelect id="smart-deploy-environment" value={environment} onChange={(event) => setEnvironment(event.target.value)} className="h-9 w-full border-white/[0.08] bg-black/15 text-xs"><option>Production</option><option>Preview</option><option>Development</option></NativeSelect></label>
        <label htmlFor="smart-deploy-health" className="space-y-1.5 text-[11px] text-white/45">Health path<Input id="smart-deploy-health" value={healthPath} onChange={(event) => setHealthPath(event.target.value)} className="h-9 border-white/[0.08] bg-black/15 font-mono text-xs" /></label>
      </div>
      <div className="flex items-center justify-between border-t border-white/[0.06] px-5 py-4">
        <p className="text-[10px] text-white/28">No public port, domain, tunnel, UPnP, R2, paid build, or provider fallback.</p>
        <Button onClick={deploy} disabled={pending || !repository || !branch || !nodeId} className="h-9 bg-[#b7ff3c] text-xs font-semibold text-[#07100c] hover:bg-[#cbff72]">{pending ? <Loader2 className="animate-spin" /> : <Server />} Deploy privately</Button>
      </div>

      {error && <p role="alert" className="border-t border-white/[0.065] bg-red-400/[0.04] px-5 py-3 text-[11px] text-red-300">{error}</p>}
      {plan && (
        <div className="border-t border-white/[0.065] bg-black/10 p-5">
          <div className="grid gap-4 lg:grid-cols-[1fr_1fr_1.2fr]">
            <div><p className="text-[10px] uppercase tracking-[0.14em] text-white/25">Detected contract</p><p className="mt-2 text-sm font-semibold text-white/78">{plan.framework} · {plan.analysis.packageManager ?? 'blocked'} · Node {plan.analysis.nodeMajor ?? '—'}</p><p className="mt-2 font-mono text-[10px] text-white/30">{plan.source.commit.slice(0, 12)} · {plan.nodeName}</p></div>
            <div className={plan.protection.allowed ? 'rounded-lg border border-[#b7ff3c]/15 bg-[#b7ff3c]/5 p-3' : 'rounded-lg border border-amber-400/15 bg-amber-400/5 p-3'}><div className={plan.protection.allowed ? 'flex items-center gap-2 text-xs font-semibold text-[#c8ff69]' : 'flex items-center gap-2 text-xs font-semibold text-amber-300'}>{plan.protection.allowed ? <CheckCircle2 className="size-3.5" /> : <AlertTriangle className="size-3.5" />}{plan.protection.allowed ? 'Signed deploy queued' : 'Policy blocked'}</div><p className="mt-1 text-[10px] leading-4 text-white/35">{plan.protection.reason}</p></div>
            <div><p className="text-[10px] uppercase tracking-[0.14em] text-white/25">Private service</p><p className="mt-2 font-mono text-xs text-white/65">{plan.localAddress}</p><p className="mt-1 text-[10px] text-white/30">Exposure: Private · public URL/TLS unavailable</p>{deployment && <Badge variant="outline" className="mt-2 border-white/[0.09] text-white/45">{deployment.state}</Badge>}</div>
          </div>
          {plan.blockedReasons.length > 0 && <ul className="mt-4 list-inside list-disc text-[10px] leading-5 text-amber-200/70">{plan.blockedReasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
        </div>
      )}
    </section>
  );
}
