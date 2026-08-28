'use client';

import { useState } from 'react';
import { AlertTriangle, CheckCircle2, GitBranch, LockKeyhole, Play, ScanSearch, Sparkles } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { createSmartDeployPlan, type DeployTarget, type SmartDeployPlan } from '@/lib/smart-deploy';
import { useZeroMode } from '@/components/zero-mode-provider';

export function SmartDeployPanel() {
  const zeroMode = useZeroMode();
  const [repository, setRepository] = useState('OpenYsd/ysd-zero-cloud');
  const [target, setTarget] = useState<DeployTarget>('auto');
  const [plan, setPlan] = useState<SmartDeployPlan | null>(null);
  const [deployed, setDeployed] = useState(false);

  function analyze() {
    setDeployed(false);
    setPlan(createSmartDeployPlan(repository, target, zeroMode.enabled));
  }

  return (
    <section className="cloud-card overflow-hidden">
      <div className="flex flex-col justify-between gap-3 border-b border-white/[0.065] px-5 py-4 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2"><Sparkles className="size-4 text-[#b7ff3c]" /><h2 className="text-sm font-semibold text-white">Smart Deploy</h2></div>
          <p className="mt-1 text-[11px] text-white/30">Repository analysis and provider planning with a zero-cost guardrail.</p>
        </div>
        <div className="flex items-center gap-2 rounded-full border border-[#b7ff3c]/15 bg-[#b7ff3c]/5 px-2.5 py-1.5 text-[10px] font-semibold text-[#c8ff69]">
          <LockKeyhole className="size-3" /> Zero Mode {zeroMode.enabled ? 'enforced' : 'paused'}
        </div>
      </div>

      <div className="grid gap-4 p-5 lg:grid-cols-[minmax(0,1fr)_190px_auto]">
        <label htmlFor="smart-deploy-repository" className="space-y-1.5 text-[11px] font-medium text-white/45">
          Repository
          <div className="relative"><GitBranch className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-white/25" /><Input id="smart-deploy-repository" value={repository} onChange={(event) => setRepository(event.target.value)} className="h-9 border-white/[0.08] bg-black/15 pl-9 text-xs" /></div>
        </label>
        <label htmlFor="smart-deploy-target" className="space-y-1.5 text-[11px] font-medium text-white/45">
          Target
          <Select value={target} onValueChange={(value) => setTarget(value as DeployTarget)}>
            <SelectTrigger id="smart-deploy-target" className="h-9 w-full border-white/[0.08] bg-black/15 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="auto">Auto · best free tier</SelectItem>
              <SelectItem value="cloudflare">Cloudflare Workers</SelectItem>
              <SelectItem value="supabase">Supabase</SelectItem>
              <SelectItem value="gpu">GPU compute · paid</SelectItem>
            </SelectContent>
          </Select>
        </label>
        <Button onClick={analyze} className="mt-auto h-9 bg-[#b7ff3c] text-xs font-semibold text-[#07100c] hover:bg-[#cbff72]" disabled={!repository.trim()}><ScanSearch /> Analyze</Button>
      </div>

      {plan && (
        <div className="border-t border-white/[0.065] bg-black/10 p-5">
          <div className="grid gap-4 lg:grid-cols-[1fr_1fr_auto] lg:items-end">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-white/25">Detected</p>
              <p className="mt-2 text-sm font-semibold text-white/78">{plan.framework} · {plan.resources[0]?.provider}</p>
              <p className="mt-1 font-mono text-[10px] text-white/28">{plan.id}</p>
            </div>
            <div className={plan.protection.allowed ? 'rounded-lg border border-[#b7ff3c]/15 bg-[#b7ff3c]/5 p-3' : 'rounded-lg border border-amber-400/15 bg-amber-400/5 p-3'}>
              <div className={plan.protection.allowed ? 'flex items-center gap-2 text-xs font-semibold text-[#c8ff69]' : 'flex items-center gap-2 text-xs font-semibold text-amber-300'}>
                {plan.protection.allowed ? <CheckCircle2 className="size-3.5" /> : <AlertTriangle className="size-3.5" />}
                {plan.protection.allowed ? 'Safe to deploy' : 'Deployment blocked'}
              </div>
              <p className="mt-1 text-[10px] leading-4 text-white/35">{plan.protection.reason} Estimate: ${plan.protection.estimatedMonthlyCost.toFixed(2)}/mo.</p>
            </div>
            <Button
              onClick={() => setDeployed(true)}
              disabled={!plan.protection.allowed}
              className="h-9 bg-[#7569ff] text-xs text-white hover:bg-[#887eff]"
            >
              <Play /> {deployed ? 'Queued' : 'Deploy plan'}
            </Button>
          </div>
        </div>
      )}
    </section>
  );
}
