'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { CheckCircle2, Clock, Loader2, RefreshCcw, ShieldAlert, ShieldCheck, TriangleAlert } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState } from '@/components/ui-bits';
import { relativeTime } from '@/lib/format';
import {
  cadenceCopy,
  describePostureDelta,
  displayGrade,
  findingAge,
  scanTriggerLabel,
  type StoredPostureDelta,
} from '@/lib/shield-posture';
import type { Severity, ShieldCheck as Check } from '@/lib/shield';

export type ShieldFindingView = {
  id: string;
  code: string;
  title: string;
  detail: string;
  resource: string;
  severity: Severity;
  remediation: string;
  status: 'open' | 'resolved';
  firstSeenAt: number;
  lastSeenAt: number;
};

/** One recorded attempt, successful or not. */
export type ScanAttemptView = {
  id: string;
  score: number;
  grade: string;
  createdAt: number;
  trigger: 'manual' | 'scheduled' | null;
  status: 'completed' | 'failed' | null;
  findingCount: number;
  delta: StoredPostureDelta | null;
};

export type ShieldViewData = {
  score: number | null;
  grade: 'strong' | 'fair' | 'at-risk' | null;
  headline: string | null;
  scannedAt: number | null;
  /** Where the scan behind the score came from. null on pre-0.15.0 rows. */
  scanTrigger: 'manual' | 'scheduled' | null;
  /** What that scan moved. null when movement was never recorded. */
  delta: StoredPostureDelta | null;
  /** Newest attempt of any kind, so a failed sweep is visible, not silent. */
  lastAttempt: ScanAttemptView | null;
  /** Newest automatic attempt. null when this workspace has never been swept. */
  lastScheduled: ScanAttemptView | null;
  /** Recent attempts, newest first. */
  history: ScanAttemptView[];
  /** Whether automatic scans are switched on for this workspace. */
  autoScan: boolean;
  checks: Check[];
  findings: ShieldFindingView[];
  now: number;
};

const SEVERITY_TONE: Record<Severity, string> = {
  critical: 'border-red-400/25 bg-red-400/[0.07] text-red-300',
  high: 'border-orange-400/25 bg-orange-400/[0.07] text-orange-300',
  medium: 'border-amber-400/20 bg-amber-400/[0.06] text-amber-300',
  low: 'border-white/[0.1] text-white/45',
};

const GRADE_LABEL = {
  strong: 'Strong posture',
  fair: 'Needs attention',
  'at-risk': 'At risk',
} as const;

export function ShieldView({ data }: { data: ShieldViewData }) {
  const router = useRouter();
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function scan() {
    setScanning(true);
    setError(null);
    try {
      const response = await fetch('/api/shield/scan', { method: 'POST' });
      if (!response.ok) {
        const body = (await response.json().catch(() => ({}))) as { error?: string };
        throw new Error(body.error ?? 'The scan could not be completed.');
      }
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The scan could not be completed.');
    } finally {
      setScanning(false);
    }
  }

  const open = data.findings.filter((finding) => finding.status === 'open');
  const resolved = data.findings.filter((finding) => finding.status === 'resolved');

  // The newest attempt is only worth calling out when it did not finish. The
  // score below it comes from the last scan that did, so the page has to say
  // that rather than let a stale number read as current.
  const failedAttempt =
    data.lastAttempt && data.lastAttempt.status === 'failed' ? data.lastAttempt : null;

  const oldestOpen = open.reduce<ShieldFindingView | null>(
    (oldest, finding) =>
      oldest === null || finding.firstSeenAt < oldest.firstSeenAt ? finding : oldest,
    null,
  );

  const scoreTone =
    data.grade === 'strong'
      ? { ring: 'border-[#b7ff3c]/18 bg-[#b7ff3c]/8 text-[#b7ff3c]', label: 'text-[#c8ff69]' }
      : data.grade === 'fair'
        ? { ring: 'border-amber-400/20 bg-amber-400/8 text-amber-300', label: 'text-amber-300' }
        : { ring: 'border-red-400/20 bg-red-400/8 text-red-300', label: 'text-red-300' };

  return (
    <>
      {failedAttempt && (
        <output className="cloud-card flex items-start gap-3 border-amber-400/20 bg-amber-400/[0.04] px-5 py-4">
          <TriangleAlert className="mt-0.5 size-4 shrink-0 text-amber-300" />
          <p className="text-[11px] leading-5 text-amber-100/75">
            The most recent attempt ({scanTriggerLabel(failedAttempt.trigger).toLowerCase()},{' '}
            {relativeTime(failedAttempt.createdAt, data.now)}) did not complete, so it recorded no
            posture. Everything below comes from the last scan that finished.
          </p>
        </output>
      )}

      <div className="grid gap-4 lg:grid-cols-[.72fr_1.28fr]">
        <article className="cloud-card relative overflow-hidden p-6">
          <div className="absolute -right-16 -top-16 size-48 rounded-full bg-[#b7ff3c]/[0.055] blur-3xl" />
          <div className="relative">
            <span className={`grid size-12 place-items-center rounded-full border ${scoreTone.ring}`}>
              <ShieldCheck className="size-6" />
            </span>

            {data.score === null ? (
              <>
                <p className="mt-6 text-2xl font-semibold tracking-[-0.04em] text-white">Not scanned yet</p>
                <p className="mt-3 max-w-xs text-[11px] leading-5 text-white/32">
                  Run the first scan to check secrets, identity, database policies, and the cost guard
                  against this workspace.
                </p>
              </>
            ) : (
              <>
                <p className="mt-6 text-5xl font-semibold tracking-[-0.06em] text-white">{data.score}</p>
                <p className={`mt-1 text-sm font-semibold ${scoreTone.label}`}>
                  {data.grade ? GRADE_LABEL[data.grade] : ''}
                </p>
                <p className="mt-3 max-w-xs text-[11px] leading-5 text-white/32">{data.headline}</p>
                {data.scannedAt && (
                  <p className="mt-2 text-[10px] text-white/22">
                    Last scan {relativeTime(data.scannedAt, data.now)} ·{' '}
                    {scanTriggerLabel(data.scanTrigger)}
                  </p>
                )}
                <p className="mt-1 text-[10px] text-white/22">{describePostureDelta(data.delta)}</p>
              </>
            )}

            <Button
              onClick={scan}
              disabled={scanning}
              className="mt-6 bg-[#b7ff3c] text-xs font-semibold text-[#07100c] hover:bg-[#cbff72]"
            >
              {scanning ? <Loader2 className="animate-spin" /> : <RefreshCcw />}
              {data.score === null ? 'Run first scan' : 'Run full scan'}
            </Button>
            {error && <p role="alert" className="mt-3 text-[11px] text-red-300">{error}</p>}
          </div>
        </article>

        <article className="cloud-card overflow-hidden">
          <div className="border-b border-white/[0.065] px-5 py-4">
            <h2 className="text-sm font-semibold text-white/80">Security checks</h2>
            <p className="mt-1 text-[10px] text-white/27">
              {data.scannedAt ? `Last full scan ${relativeTime(data.scannedAt, data.now)}` : 'Awaiting the first scan'}
            </p>
          </div>
          {data.checks.length === 0 ? (
            <p className="px-5 py-12 text-center text-[11px] text-white/28">
              Check results appear here once a scan has run.
            </p>
          ) : (
            <div className="divide-y divide-white/[0.055]">
              {data.checks.map((check) => (
                <div key={check.id} className="flex items-center gap-3 px-5 py-4">
                  <span
                    className={
                      check.state === 'passed'
                        ? 'grid size-8 place-items-center rounded-lg bg-[#b7ff3c]/6 text-[#b7ff3c]'
                        : check.state === 'review'
                          ? 'grid size-8 place-items-center rounded-lg bg-amber-400/6 text-amber-300'
                          : 'grid size-8 place-items-center rounded-lg bg-red-400/6 text-red-300'
                    }
                  >
                    {check.state === 'passed' ? <CheckCircle2 className="size-4" /> : <TriangleAlert className="size-4" />}
                  </span>
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-white/68">{check.name}</p>
                    <p className="mt-1 text-[10px] text-white/27">{check.detail}</p>
                  </div>
                  <Badge
                    variant="outline"
                    className={
                      check.state === 'passed'
                        ? 'ml-auto border-[#b7ff3c]/12 text-[#c8ff69]'
                        : check.state === 'review'
                          ? 'ml-auto border-amber-300/15 text-amber-300'
                          : 'ml-auto border-red-300/20 text-red-300'
                    }
                  >
                    {check.state === 'passed' ? 'Passed' : check.state === 'review' ? 'Review' : 'Failed'}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </article>
      </div>

      <section className="cloud-card overflow-hidden">
        <div className="border-b border-white/[0.065] px-5 py-4">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-white/80">
            <Clock className="size-3.5 text-white/35" />
            Automatic scans
          </h2>
          <p className="mt-1 text-[10px] text-white/27">
            {!data.autoScan
              ? 'Off for this workspace. Shield runs only when someone presses Run full scan.'
              : data.lastScheduled === null
                ? 'On. This workspace has not been swept automatically yet.'
                : `On. Last automatic scan ${relativeTime(data.lastScheduled.createdAt, data.now)}.`}
          </p>
          {data.autoScan && <p className="mt-1 text-[10px] text-white/22">{cadenceCopy()}</p>}
        </div>

        {data.history.length === 0 ? (
          <p className="px-5 py-10 text-center text-[11px] text-white/28">
            Scan history appears here once a scan has run.
          </p>
        ) : (
          <Table className="text-[11px]">
            <TableHeader>
              <TableRow className="border-white/[0.06] hover:bg-transparent">
                {['When', 'Source', 'Result', 'Score', 'Movement'].map((column) => (
                  <TableHead key={column} className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25">
                    {column}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.history.map((attempt) => {
                const failed = attempt.status === 'failed';
                const grade = displayGrade(attempt.grade);
                return (
                  <TableRow key={attempt.id} className="border-white/[0.05] hover:bg-white/[0.02]">
                    <TableCell className="px-4 py-3 text-white/55">
                      {relativeTime(attempt.createdAt, data.now)}
                    </TableCell>
                    <TableCell className="px-4 py-3 text-white/42">
                      {scanTriggerLabel(attempt.trigger)}
                    </TableCell>
                    <TableCell className="px-4 py-3">
                      <Badge
                        variant="outline"
                        className={
                          failed
                            ? 'border-red-300/20 text-red-300'
                            : 'border-[#b7ff3c]/12 text-[#c8ff69]'
                        }
                      >
                        {failed ? 'Did not complete' : 'Completed'}
                      </Badge>
                    </TableCell>
                    {/* A failed attempt has no score. The placeholder it stores
                        is never printed, because a number in this column would
                        be read as a posture. */}
                    <TableCell className="px-4 py-3 text-white/42">
                      {failed ? '—' : `${attempt.score}${grade ? ` · ${GRADE_LABEL[grade]}` : ''}`}
                    </TableCell>
                    <TableCell className="px-4 py-3 text-white/42">
                      {failed ? '—' : describePostureDelta(attempt.delta)}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </section>

      {open.length === 0 ? (
        <EmptyState
          title={data.score === null ? 'No scan on record' : 'No open findings'}
          copy={
            data.score === null
              ? 'Run a scan and any findings will be listed here with the fix.'
              : 'Every rule passed on the last scan. Findings you fix are kept as history.'
          }
        />
      ) : (
        <section className="cloud-card overflow-hidden">
          <div className="border-b border-white/[0.065] px-5 py-4">
            <h2 className="text-sm font-semibold text-white/80">Open findings</h2>
            <p className="mt-1 text-[10px] text-white/27">
              Each row includes the change that clears it.
              {oldestOpen &&
                ` Oldest has been open ${findingAge(oldestOpen.firstSeenAt, data.now)}.`}
            </p>
          </div>
          <Table className="text-[11px]">
            <TableHeader>
              <TableRow className="border-white/[0.06] hover:bg-transparent">
                {['Finding', 'Resource', 'Severity', 'How to fix', 'Open for'].map((column) => (
                  <TableHead key={column} className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25">
                    {column}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {open.map((finding) => (
                <TableRow key={finding.id} className="border-white/[0.05] hover:bg-white/[0.02]">
                  <TableCell className="px-4 py-3">
                    <span className="flex items-center gap-2 font-medium text-white/72">
                      <ShieldAlert className="size-3.5 shrink-0 text-[#b7ff3c]/65" />
                      {finding.title}
                    </span>
                    <span className="mt-1 block text-[10px] text-white/30">{finding.detail}</span>
                  </TableCell>
                  <TableCell className="px-4 py-3 font-mono text-[10px] text-white/40">{finding.resource}</TableCell>
                  <TableCell className="px-4 py-3">
                    <Badge variant="outline" className={SEVERITY_TONE[finding.severity]}>{finding.severity}</Badge>
                  </TableCell>
                  <TableCell className="px-4 py-3 text-white/42">{finding.remediation}</TableCell>
                  <TableCell className="px-4 py-3 text-white/42">
                    {findingAge(finding.firstSeenAt, data.now)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </section>
      )}

      {resolved.length > 0 && (
        <p className="text-[11px] text-white/28">
          {resolved.length} finding{resolved.length === 1 ? '' : 's'} resolved and kept as history.
        </p>
      )}
    </>
  );
}
