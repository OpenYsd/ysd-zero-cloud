'use client';

import { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CalendarClock,
  Database,
  Gauge,
  ShieldQuestion,
  Trash2,
} from 'lucide-react';
import type { CapacityForecast, CapacityState } from '@/lib/capacity';
import {
  CAPACITY_STATE_LABELS,
  CAPACITY_THRESHOLDS,
} from '@/lib/capacity';
import type {
  DataLifecycleState,
  RetentionPolicyView,
  RetentionRunView,
} from '@/lib/domain';
import { formatUsage } from '@/lib/free-tier';
import { relativeTime } from '@/lib/format';
import {
  RETENTION_LIMITS,
  RETENTION_PROTECTED_RECORDS,
  type RetentionDataClass,
} from '@/lib/retention';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';

type Operation =
  | { operation: 'dry-run' }
  | { operation: 'enable' }
  | { operation: 'disable' }
  | { operation: 'set-window'; retentionDays: number };

function stateVariant(state: CapacityState) {
  if (state === 'critical') return 'destructive' as const;
  if (state === 'at-risk') return 'secondary' as const;
  return 'outline' as const;
}

function StateBadge({ state }: { state: CapacityState }) {
  return <Badge variant={stateVariant(state)}>{CAPACITY_STATE_LABELS[state]}</Badge>;
}

function trendLabel(forecast: CapacityForecast): string {
  if (forecast.growthPerDay === null) return 'No trend yet';
  if (forecast.growthPerDay === 0) return 'Flat or falling';
  const perDay =
    forecast.unit === 'bytes'
      ? `${Math.round(forecast.growthPerDay).toLocaleString('en-US')} B`
      : Math.round(forecast.growthPerDay).toLocaleString('en-US');
  return `+${perDay} per day`;
}

function horizonLabel(forecast: CapacityForecast): string {
  if (!forecast.measured) return 'Not reported by the provider';
  if (forecast.insufficientHistory) {
    return `Needs ${CAPACITY_THRESHOLDS.minimumSamples} snapshots over ${Math.round(CAPACITY_THRESHOLDS.minimumSpanMs / (60 * 60 * 1000))}h`;
  }
  if (forecast.daysRemaining === null) return 'No breach projected';
  const days = Math.max(0, Math.round(forecast.daysRemaining));
  return days === 0 ? 'At the limit now' : `About ${days} day${days === 1 ? '' : 's'} remaining`;
}

function CapacityRow({ forecast, now }: { forecast: CapacityForecast; now: number }) {
  return (
    <li className="cloud-card space-y-2 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-white">{forecast.label}</p>
          <p className="text-xs text-white/45">
            {formatUsage({
              used: forecast.used,
              limit: forecast.limit,
              unit: forecast.unit,
              measured: forecast.measured,
            })}
          </p>
        </div>
        <StateBadge state={forecast.state} />
      </div>
      <Progress
        value={forecast.percent}
        className="h-1.5 [&_[data-slot=progress-track]]:bg-white/[0.06]"
        aria-label={`${Math.round(forecast.percent)} percent of the free-tier allowance used`}
      />
      <dl className="grid grid-cols-3 gap-2 text-[11px]">
        <div>
          <dt className="text-white/30">Used</dt>
          <dd className="text-white/65">{Math.round(forecast.percent)}%</dd>
        </div>
        <div>
          <dt className="text-white/30">Trend</dt>
          <dd className="text-white/65">{trendLabel(forecast)}</dd>
        </div>
        <div>
          <dt className="text-white/30">Forecast</dt>
          <dd className="text-white/65">{horizonLabel(forecast)}</dd>
        </div>
      </dl>
      {forecast.projectedBreachAt !== null ? (
        <p className="text-[11px] text-white/35">
          Projected to reach the trusted limit {relativeTime(forecast.projectedBreachAt, now)}.
        </p>
      ) : null}
    </li>
  );
}

function runSummary(run: RetentionRunView | undefined, now: number): string {
  if (!run) return 'Never run';
  const when = relativeTime(run.startedAt, now);
  if (run.status === 'failed') return `Failed ${when} (${run.failureCode ?? 'unknown'})`;
  if (run.mode === 'dry-run') {
    return `${run.candidateRows.toLocaleString('en-US')} candidate rows ${when}`;
  }
  return `${run.deletedRows.toLocaleString('en-US')} rows deleted ${when} (${run.status})`;
}

function PolicyCard({
  policy,
  runs,
  canManage,
  pending,
  now,
  onMutate,
}: {
  policy: RetentionPolicyView;
  runs: RetentionRunView[];
  canManage: boolean;
  pending: boolean;
  now: number;
  onMutate: (policy: RetentionPolicyView, operation: Operation) => void;
}) {
  const [days, setDays] = useState(String(policy.retentionDays));
  const lastDryRun = runs.find(
    (run) => run.dataClass === policy.dataClass && run.mode === 'dry-run',
  );
  const lastPrune = runs.find(
    (run) => run.dataClass === policy.dataClass && run.mode === 'prune',
  );
  const dryRunFresh =
    policy.lastDryRunAt !== null &&
    policy.lastDryRunRevision === policy.revision &&
    policy.lastDryRunRetentionDays === policy.retentionDays &&
    now - policy.lastDryRunAt <= RETENTION_LIMITS.dryRunFreshnessMs;

  return (
    <li className="cloud-card space-y-3 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-white">{policy.label}</p>
          <p className="mt-0.5 text-xs text-white/45">{policy.description}</p>
        </div>
        <Badge variant={policy.enabled ? 'secondary' : 'outline'}>
          {policy.enabled ? 'Deleting' : 'Disabled'}
        </Badge>
      </div>

      <dl className="grid grid-cols-2 gap-2 text-[11px] sm:grid-cols-4">
        <div>
          <dt className="text-white/30">Retention</dt>
          <dd className="text-white/65">{policy.retentionDays} days</dd>
        </div>
        <div>
          <dt className="text-white/30">Minimum allowed</dt>
          <dd className="text-white/65">{policy.minimumRetentionDays} days</dd>
        </div>
        <div>
          <dt className="text-white/30">Eligible rows</dt>
          <dd className="text-white/65">
            {policy.candidateRows === null
              ? 'Unknown'
              : policy.candidateRows.toLocaleString('en-US')}
          </dd>
        </div>
        <div>
          <dt className="text-white/30">Per pass cap</dt>
          <dd className="text-white/65">{policy.maximumRowsPerRun.toLocaleString('en-US')}</dd>
        </div>
      </dl>

      <div className="space-y-1 text-[11px] text-white/40">
        <p>Latest dry-run · {runSummary(lastDryRun, now)}</p>
        <p>Latest prune · {runSummary(lastPrune, now)}</p>
        <p>Latest run status · {policy.lastRunStatus ?? 'Never run'}</p>
        {policy.consecutiveFailures > 0 ? (
          <p className="text-amber-300/70">
            {policy.consecutiveFailures} consecutive failure
            {policy.consecutiveFailures === 1 ? '' : 's'}.
          </p>
        ) : null}
      </div>

      {canManage ? (
        <div className="flex flex-wrap items-center gap-2 border-t border-white/[0.06] pt-3">
          <Input
            className="h-8 w-24"
            inputMode="numeric"
            aria-label={`${policy.label} retention days`}
            value={days}
            disabled={pending || policy.enabled}
            onChange={(event) => setDays(event.target.value)}
          />
          <Button
            size="sm"
            variant="outline"
            disabled={pending || policy.enabled || Number(days) === policy.retentionDays}
            onClick={() =>
              onMutate(policy, { operation: 'set-window', retentionDays: Number(days) })
            }
          >
            Save window
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={pending}
            onClick={() => onMutate(policy, { operation: 'dry-run' })}
          >
            Dry run (deletes nothing)
          </Button>
          {policy.enabled ? (
            <Button
              size="sm"
              variant="outline"
              disabled={pending}
              onClick={() => onMutate(policy, { operation: 'disable' })}
            >
              Stop deleting
            </Button>
          ) : (
            <Button
              size="sm"
              variant="destructive"
              disabled={pending || !dryRunFresh}
              onClick={() => onMutate(policy, { operation: 'enable' })}
            >
              <Trash2 className="mr-1.5 size-3.5" />
              Start deleting permanently
            </Button>
          )}
          {!policy.enabled && !dryRunFresh ? (
            <span className="text-[11px] text-white/35">
              Run a preview first. Activation needs one from the last 24 hours matching this window.
            </span>
          ) : null}
        </div>
      ) : (
        <p className="border-t border-white/[0.06] pt-3 text-[11px] text-white/35">
          Retention policies are managed by owners and admins.
        </p>
      )}
    </li>
  );
}

export function CapacityView({
  initialState,
  now,
}: {
  initialState: DataLifecycleState;
  now: number;
}) {
  const [state, setState] = useState(initialState);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function mutate(policy: RetentionPolicyView, operation: Operation) {
    setPending(true);
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(
        `/api/retention/${encodeURIComponent(policy.dataClass)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...operation, expectedRevision: policy.revision }),
        },
      );
      const payload = (await response.json()) as {
        policy?: RetentionPolicyView;
        error?: string;
      };
      if (!response.ok || !payload.policy) {
        throw new Error(payload.error ?? 'The retention policy could not be updated.');
      }
      const updated = payload.policy;
      // Refresh the authoritative state so newly-written dry-run/prune evidence
      // and candidate counts appear together. If the refresh itself is
      // unavailable, retain the successful mutation response instead of
      // misleading the operator that the mutation failed.
      const refreshed = await fetch('/api/retention', {
        method: 'GET',
        headers: { Accept: 'application/json' },
      });
      if (refreshed.ok) {
        setState((await refreshed.json()) as DataLifecycleState);
      } else {
        setState((current) => ({
          ...current,
          policies: current.policies.map((item) =>
            item.dataClass === updated.dataClass ? updated : item,
          ),
        }));
      }
      if (operation.operation === 'dry-run') {
        setNotice(
          `${updated.label} preview complete. ${(updated.lastDryRunCandidateRows ?? 0).toLocaleString('en-US')} rows are older than ${updated.retentionDays} days. Nothing was deleted.`,
        );
      }
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : 'The retention policy could not be updated.',
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="space-y-5">
      <section aria-label="Capacity forecast" className="space-y-3">
        <header className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Gauge className="size-4 text-white/45" />
            <h2 className="text-sm font-medium text-white">Capacity forecast</h2>
            <StateBadge state={state.capacityState} />
          </div>
          <p className="text-[11px] text-white/35">
            {state.snapshots} snapshot{state.snapshots === 1 ? '' : 's'}
            {state.latestSnapshotAt !== null
              ? ` · latest ${relativeTime(state.latestSnapshotAt, now)}`
              : ' · none captured yet'}
            {' · every '}
            {Math.round(state.snapshotIntervalMs / (60 * 60 * 1000))}h
          </p>
        </header>
        <ul className="grid gap-3 lg:grid-cols-2">
          {state.capacity.map((forecast) => (
            <CapacityRow key={forecast.metricId} forecast={forecast} now={now} />
          ))}
        </ul>
        <p className="flex items-start gap-2 text-[11px] text-white/30">
          <Activity className="mt-0.5 size-3.5 shrink-0" />
          Limits come from the same free-tier catalog the meters above use. A projection is
          withheld rather than guessed when history is short or growth is flat.
        </p>
      </section>

      <section aria-label="Retention policies" className="space-y-3">
        <header className="flex items-center gap-2">
          <Database className="size-4 text-white/45" />
          <h2 className="text-sm font-medium text-white">Retention</h2>
        </header>

        <p className="cloud-card flex items-start gap-2 p-3 text-[11px] text-white/45">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-amber-300/70" />
          Every policy starts disabled and deletes nothing. Activating one permanently removes
          rows older than its window on a schedule; deleted rows cannot be restored. Preview
          first, read the row count, then decide.
        </p>

        {error ? (
          <p role="alert" className="cloud-card p-3 text-xs text-red-300/80">
            {error}
          </p>
        ) : null}
        {notice ? (
          <output className="cloud-card block p-3 text-xs text-white/60">
            {notice}
          </output>
        ) : null}

        <ul className="space-y-3">
          {state.policies.map((policy) => (
            <PolicyCard
              key={`${policy.dataClass}:${policy.retentionDays}`}
              policy={policy}
              runs={state.runs}
              canManage={state.canManage}
              pending={pending}
              now={now}
              onMutate={mutate}
            />
          ))}
        </ul>
      </section>

      <section aria-label="Never deleted automatically" className="space-y-2">
        <header className="flex items-center gap-2">
          <ShieldQuestion className="size-4 text-white/45" />
          <h2 className="text-sm font-medium text-white">Never deleted automatically</h2>
        </header>
        <ul className="cloud-card divide-y divide-white/[0.06] p-0 text-[11px]">
          {RETENTION_PROTECTED_RECORDS.map((entry) => (
            <li key={entry.id} className="flex flex-col gap-0.5 p-3">
              <span className="font-medium text-white/70">{entry.label}</span>
              <span className="text-white/40">{entry.reason}</span>
            </li>
          ))}
        </ul>
        <p className="flex items-start gap-2 text-[11px] text-white/30">
          <CalendarClock className="mt-0.5 size-3.5 shrink-0" />
          Retention and snapshots run on the existing one-minute tick. No queue, no external
          archive, and no new binding — projected cost stays at $0.00 per month.
        </p>
      </section>
    </div>
  );
}

export type { RetentionDataClass };
