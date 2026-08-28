'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  GitBranch,
  Loader2,
  LockKeyhole,
  ScanSearch,
  Sparkles,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NativeSelect } from '@/components/ui/native-select';
import { useZeroMode } from '@/components/zero-mode-provider';
import type { Deployment } from '@/lib/domain';
import { money } from '@/lib/format';
import type { DeployTarget, SmartDeployPlan } from '@/lib/smart-deploy';

/**
 * Smart Deploy.
 *
 * The plan is built on the server so the cost guard cannot be argued with from
 * a browser. This panel sends the repository and target, then renders whatever
 * decision came back — including a refusal.
 */
export function SmartDeployPanel({
  repositoryHint,
}: {
  repositoryHint?: string;
}) {
  const router = useRouter();
  const zeroMode = useZeroMode();
  const [repository, setRepository] = useState(
    repositoryHint ?? 'OpenYsd/ysd-zero-cloud',
  );
  const [target, setTarget] = useState<DeployTarget>('auto');
  const [plan, setPlan] = useState<SmartDeployPlan | null>(null);
  const [deployment, setDeployment] = useState<Deployment | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function analyze() {
    setPending(true);
    setError(null);
    try {
      const response = await fetch('/api/smart-deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repository, target }),
      });
      const body = (await response.json()) as {
        plan?: SmartDeployPlan;
        deployment?: Deployment;
        error?: string;
      };

      // 403 is the guard doing its job, not a failure: the body still carries
      // the plan that explains what was rejected and why.
      if (!body.plan)
        throw new Error(body.error ?? 'The repository could not be analysed.');

      setPlan(body.plan);
      setDeployment(body.deployment ?? null);
      router.refresh();
    } catch (cause) {
      setPlan(null);
      setDeployment(null);
      setError(
        cause instanceof Error
          ? cause.message
          : 'The repository could not be analysed.',
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="cloud-card overflow-hidden">
      <div className="flex flex-col justify-between gap-3 border-b border-white/[0.065] px-5 py-4 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="size-4 text-[#b7ff3c]" />
            <h2 className="text-sm font-semibold text-white">Smart Deploy</h2>
          </div>
          <p className="mt-1 text-[11px] text-white/30">
            Repository analysis and provider planning, with the cost guard
            enforced server-side.
          </p>
        </div>
        <div
          className={
            zeroMode.enabled
              ? 'flex items-center gap-2 rounded-full border border-[#b7ff3c]/15 bg-[#b7ff3c]/5 px-2.5 py-1.5 text-[10px] font-semibold text-[#c8ff69]'
              : 'flex items-center gap-2 rounded-full border border-amber-400/20 bg-amber-400/5 px-2.5 py-1.5 text-[10px] font-semibold text-amber-300'
          }
        >
          <LockKeyhole className="size-3" /> Zero Mode{' '}
          {zeroMode.enabled ? 'enforced' : 'paused'}
        </div>
      </div>

      <div className="grid gap-4 p-5 lg:grid-cols-[minmax(0,1fr)_210px_auto] lg:items-end">
        <div className="space-y-1.5">
          <label
            htmlFor="smart-deploy-repository"
            className="text-[11px] font-medium text-white/45"
          >
            Repository
          </label>
          <div className="relative">
            <GitBranch className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-white/25" />
            <Input
              id="smart-deploy-repository"
              value={repository}
              onChange={(event) => setRepository(event.target.value)}
              placeholder="owner/repo"
              className="h-9 border-white/[0.08] bg-black/15 pl-9 text-xs"
            />
          </div>
        </div>

        <div className="space-y-1.5">
          <label
            htmlFor="smart-deploy-target"
            className="text-[11px] font-medium text-white/45"
          >
            Target
          </label>
          <NativeSelect
            id="smart-deploy-target"
            value={target}
            onChange={(event) => setTarget(event.target.value as DeployTarget)}
            className="h-9 w-full border-white/[0.08] bg-black/15 text-xs"
          >
            <option value="auto">Auto · best free tier</option>
            <option value="cloudflare">Cloudflare Workers</option>
            <option value="d1">Cloudflare Worker + D1</option>
            <option value="gpu">GPU compute · paid</option>
          </NativeSelect>
        </div>

        <Button
          onClick={analyze}
          className="h-9 bg-[#b7ff3c] text-xs font-semibold text-[#07100c] hover:bg-[#cbff72]"
          disabled={!repository.trim() || pending}
        >
          {pending ? <Loader2 className="animate-spin" /> : <ScanSearch />}{' '}
          Analyze
        </Button>
      </div>

      {error && (
        <p
          role="alert"
          className="border-t border-white/[0.065] bg-black/10 px-5 py-3 text-[11px] text-red-300"
        >
          {error}
        </p>
      )}

      {plan && (
        <div className="border-t border-white/[0.065] bg-black/10 p-5">
          <div className="grid gap-4 lg:grid-cols-[1fr_1fr_auto] lg:items-start">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-white/25">
                Detected
              </p>
              <p className="mt-2 text-sm font-semibold text-white/78">
                {plan.framework} · {plan.resources[0]?.provider}
              </p>
              <Badge
                variant="outline"
                className={
                  plan.confidence === 'inspected'
                    ? 'mt-2 border-[#b7ff3c]/15 text-[#c8ff69]'
                    : 'mt-2 border-white/[0.09] text-white/40'
                }
              >
                {plan.confidence === 'inspected'
                  ? 'Read from the repository'
                  : 'Inferred from the name'}
              </Badge>
              {deployment && (
                <p className="mt-2 font-mono text-[10px] text-white/28">
                  {deployment.id} · {deployment.commitSha}
                </p>
              )}
            </div>

            <div
              className={
                plan.protection.allowed
                  ? 'rounded-lg border border-[#b7ff3c]/15 bg-[#b7ff3c]/5 p-3'
                  : 'rounded-lg border border-amber-400/15 bg-amber-400/5 p-3'
              }
            >
              <div
                className={
                  plan.protection.allowed
                    ? 'flex items-center gap-2 text-xs font-semibold text-[#c8ff69]'
                    : 'flex items-center gap-2 text-xs font-semibold text-amber-300'
                }
              >
                {plan.protection.allowed ? (
                  <CheckCircle2 className="size-3.5" />
                ) : (
                  <AlertTriangle className="size-3.5" />
                )}
                {plan.protection.allowed ? 'Plan recorded' : 'Plan blocked'}
              </div>
              <p className="mt-1 text-[10px] leading-4 text-white/35">
                {plan.protection.reason} Estimate:{' '}
                {money(plan.protection.estimatedMonthlyCost)}/mo.
              </p>
              {plan.protection.blockedResources.length > 0 && (
                <ul className="mt-2 space-y-1 text-[10px] text-amber-200/70">
                  {plan.protection.blockedResources.map((resource) => (
                    <li key={resource.name}>
                      {resource.name} · {money(resource.estimatedMonthlyCost)}
                      /mo
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="text-[10px] leading-5 text-white/32">
              <p className="mb-1 font-semibold uppercase tracking-[0.14em] text-white/25">
                Steps
              </p>
              <ol className="list-inside list-decimal space-y-0.5">
                {plan.steps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </div>
          </div>

          <div className="mt-4 grid gap-2 border-t border-white/[0.06] pt-4 sm:grid-cols-2 lg:grid-cols-3">
            {plan.resources.map((resource) => (
              <div
                key={resource.name}
                className="rounded-lg border border-white/[0.06] bg-white/[0.015] p-3"
              >
                <p className="text-[11px] font-medium text-white/65">
                  {resource.name}
                </p>
                <p className="mt-1 text-[10px] text-white/28">
                  {resource.provider} · {money(resource.estimatedMonthlyCost)}
                  /mo
                </p>
                {resource.note && (
                  <p className="mt-1 text-[10px] text-white/22">
                    {resource.note}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
