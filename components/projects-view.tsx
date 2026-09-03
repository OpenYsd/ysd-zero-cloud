'use client';

import { useRouter } from 'next/navigation';
import { Fragment, useState } from 'react';
import {
  AlertTriangle,
  Box,
  CheckCircle2,
  ChevronDown,
  GitBranch,
  Info,
  Loader2,
  Plus,
  Rocket,
  Sparkles,
  Trash2,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState } from '@/components/ui-bits';
import { NavLink } from '@/components/nav-link';
import { relativeTime } from '@/lib/format';
import type { Project } from '@/lib/domain';
import { repositoryUrl, type ReadinessReport } from '@/lib/readiness';

const STATUS_TONE: Record<Project['status'], string> = {
  live: 'border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]',
  building: 'border-[#4ac7ff]/15 bg-[#4ac7ff]/5 text-[#79d6ff]',
  idle: 'border-white/[0.08] text-white/40',
  blocked: 'border-amber-400/20 bg-amber-400/5 text-amber-300',
};

const READINESS_TONE: Record<Project['readiness']['state'], string> = {
  never: 'border-white/[0.08] text-white/35',
  ready: 'border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]',
  blocked: 'border-amber-400/20 bg-amber-400/5 text-amber-300',
};

const READINESS_LABEL: Record<Project['readiness']['state'], string> = {
  never: 'Not analyzed',
  ready: 'Ready',
  blocked: 'Blocked',
};

/** The canonical `owner/repo` link, rebuilt from validated parts only. */
function safeRepositoryLink(repository: string | null): string | null {
  if (!repository) return null;
  const parts = repository.split('/');
  if (parts.length !== 2) return null;
  return repositoryUrl(parts[0]!, parts[1]!);
}

function ReadinessDetail({
  project,
  report,
  loading,
  error,
  analyzing,
  onAnalyze,
  now,
}: {
  project: Project;
  report: ReadinessReport | null;
  loading: boolean;
  error: string | null;
  analyzing: boolean;
  onAnalyze: () => void;
  now: number;
}) {
  const link = safeRepositoryLink(project.repository);

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-6 text-[11px] text-white/35">
        <Loader2 className="size-3.5 animate-spin" /> Loading the stored result…
      </div>
    );
  }

  // State F -- STALE is deliberately not auto-detected: that would mean an
  // extra GitHub call on every page load, which the product contract forbids.
  // The commit label is the honest substitute: the user always sees exactly
  // which commit the verdict is about, and re-analyze is one click away.
  const commitLabel = report ? (
    <p className="font-mono text-[10px] text-white/30">
      Analyzed at commit {report.commit.slice(0, 7)}
      {report.branch ? ` on ${report.branch}` : ''} · {relativeTime(project.updatedAt, now)}
    </p>
  ) : null;

  return (
    <div className="space-y-4 py-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-1">
          {link ? (
            <NavLink
              href={link}
              target="_blank"
              rel="noreferrer noopener"
              className="font-mono text-xs text-white/55 underline decoration-white/20 underline-offset-2 hover:text-white/80"
            >
              {project.repository}
            </NavLink>
          ) : (
            <p className="font-mono text-xs text-white/55">{project.repository ?? 'No repository'}</p>
          )}
          {commitLabel}
        </div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={analyzing || !project.repository}
          onClick={onAnalyze}
          className="h-8 border-white/[0.1] text-[11px] text-white/70"
        >
          {analyzing ? <Loader2 className="animate-spin" /> : <Sparkles />}
          {report ? 'Re-analyze' : 'Analyze repository'}
        </Button>
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-red-400/20 bg-red-400/[0.04] px-3 py-2 text-[11px] text-red-300">
          {error}
        </p>
      )}

      {/* State A -- NEVER ANALYZED */}
      {!report && !error && (
        <p className="text-[11px] text-white/35">
          {project.repository
            ? 'This repository has not been analyzed yet. Analyzing reads the public repository and checks it against the App Runtime contract -- nothing is built or deployed.'
            : 'Add a repository to this project before it can be analyzed.'}
        </p>
      )}

      {/* States C/D -- READY / BLOCKED */}
      {report && (
        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-3">
            <div>
              <p className="text-[10px] uppercase tracking-[0.14em] text-white/25">Detected contract</p>
              <p className="mt-1.5 text-xs font-medium text-white/72">
                {report.framework ?? 'Unknown'} · {report.packageManager ?? 'unresolved'} · Node {report.nodeMajor ?? '—'}
              </p>
              <p className="mt-1 font-mono text-[10px] text-white/30">{report.entrypoint ?? 'no entrypoint resolved'}</p>
            </div>
            <div
              className={
                report.verdict === 'ready'
                  ? 'rounded-lg border border-[#b7ff3c]/15 bg-[#b7ff3c]/5 p-3'
                  : 'rounded-lg border border-amber-400/15 bg-amber-400/5 p-3'
              }
            >
              <div
                className={
                  report.verdict === 'ready'
                    ? 'flex items-center gap-2 text-xs font-semibold text-[#c8ff69]'
                    : 'flex items-center gap-2 text-xs font-semibold text-amber-300'
                }
              >
                {report.verdict === 'ready' ? <CheckCircle2 className="size-3.5" /> : <AlertTriangle className="size-3.5" />}
                {report.verdict === 'ready' ? 'Ready to deploy' : `${report.blockedCount} blocker${report.blockedCount === 1 ? '' : 's'}`}
              </div>
              <p className="mt-1 text-[10px] leading-4 text-white/35">
                {report.verdict === 'ready'
                  ? 'The repository satisfies the App Runtime contract.'
                  : 'Fix the items below, then re-analyze.'}
              </p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-[0.14em] text-white/25">Zero Mode preview</p>
              <p className="mt-1.5 text-xs font-semibold text-white/78">${report.preview.estimatedMonthlyCost.toFixed(2)}/month</p>
              {/* This is the one sentence that must never be missing: nothing
                  in this panel builds or runs anything. */}
              <p className="mt-1 text-[10px] leading-4 text-white/35">
                Preview only. No deployment has occurred. A Compute Node is still required to build and run this project.
              </p>
            </div>
          </div>

          {report.blockers.length > 0 && (
            <ul className="space-y-2">
              {report.blockers.map((blocker, index) => (
                <li
                  key={`${blocker.code}-${index}`}
                  className="flex items-start gap-2 rounded-md border border-white/[0.06] bg-white/[0.02] p-2.5 text-[11px] leading-5"
                >
                  <Info aria-hidden="true" className="mt-0.5 size-3.5 shrink-0 text-amber-300/70" />
                  <span>
                    <span className="text-white/70">{blocker.title}</span>
                    <span className="block text-white/35">{blocker.remediation}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
          {report.truncated && (
            <p className="text-[10px] text-white/25">
              Showing {report.blockers.length} of {report.blockedCount} blockers.
            </p>
          )}

          {/* Step 12 -- node selection is presented only once a project is
              genuinely ready, never as the first required step. */}
          {report.verdict === 'ready' && project.repository && (
            <NavLink
              href={`/deployments?repository=${encodeURIComponent(project.repository)}${
                report.branch ? `&branch=${encodeURIComponent(report.branch)}` : ''
              }&commit=${encodeURIComponent(report.commit)}`}
              className="inline-flex h-8 items-center gap-1.5 rounded-md bg-[#b7ff3c] px-3 text-[11px] font-semibold text-[#07100c] hover:bg-[#cbff72]"
            >
              <Rocket className="size-3.5" /> Select Compute Node to deploy
            </NavLink>
          )}
        </div>
      )}
    </div>
  );
}

export function ProjectsView({ projects, now }: { projects: Project[]; now: number }) {
  const router = useRouter();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [repository, setRepository] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [analyzingId, setAnalyzingId] = useState<string | null>(null);
  const [reportsById, setReportsById] = useState<Record<string, ReadinessReport | null>>({});
  const [readinessErrorById, setReadinessErrorById] = useState<Record<string, string | null>>({});

  async function create(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const response = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, repository: repository.trim() || null }),
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(body.error ?? 'The project could not be created.');
      setName('');
      setRepository('');
      setCreating(false);
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The project could not be created.');
    } finally {
      setPending(false);
    }
  }

  async function remove(id: string) {
    setRemoving(id);
    try {
      await fetch(`/api/projects/${id}`, { method: 'DELETE' });
      router.refresh();
    } finally {
      setRemoving(null);
    }
  }

  // Persistence after refresh: the summary badge is already correct from the
  // server-rendered `project.readiness`; this fetches the full stored report
  // the one time a row is actually opened, rather than parsing every row's
  // report up front.
  async function toggle(project: Project) {
    if (expandedId === project.id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(project.id);
    if (project.readiness.state === 'never' || reportsById[project.id] !== undefined) return;
    setLoadingId(project.id);
    try {
      const response = await fetch(`/api/projects/${project.id}`);
      const body = (await response.json()) as { report?: ReadinessReport | null };
      setReportsById((prior) => ({ ...prior, [project.id]: body.report ?? null }));
    } catch {
      // The summary badge from the server render still stands; the detail
      // panel simply falls back to the never-analyzed state below.
    } finally {
      setLoadingId(null);
    }
  }

  // State B -- ANALYZING, guarded so a repeated click cannot double-submit.
  async function analyze(project: Project) {
    if (analyzingId) return;
    setAnalyzingId(project.id);
    setReadinessErrorById((prior) => ({ ...prior, [project.id]: null }));
    try {
      const response = await fetch(`/api/projects/${project.id}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      const body = (await response.json()) as { report?: ReadinessReport; error?: string };
      if (!response.ok || !body.report) {
        throw new Error(body.error ?? 'The repository could not be analyzed.');
      }
      setReportsById((prior) => ({ ...prior, [project.id]: body.report! }));
      router.refresh();
    } catch (cause) {
      setReadinessErrorById((prior) => ({
        ...prior,
        [project.id]: cause instanceof Error ? cause.message : 'The repository could not be analyzed.',
      }));
    } finally {
      setAnalyzingId(null);
    }
  }

  return (
    <>
      <div className="flex justify-end">
        <Button
          onClick={() => setCreating((open) => !open)}
          className="h-9 bg-[#b7ff3c] px-3.5 text-xs font-semibold text-[#07100c] hover:bg-[#cbff72]"
        >
          <Plus /> New project
        </Button>
      </div>

      {creating && (
        <form onSubmit={create} className="cloud-card grid gap-4 p-5 lg:grid-cols-[1fr_1fr_auto] lg:items-end">
          <div className="space-y-1.5">
            <Label htmlFor="project-name" className="text-[11px] text-white/45">Name</Label>
            <Input
              id="project-name"
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="my-service"
              className="h-9 border-white/[0.08] bg-black/15 text-xs"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="project-repository" className="text-[11px] text-white/45">Repository (optional)</Label>
            <div className="relative">
              <GitBranch className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-white/25" />
              <Input
                id="project-repository"
                value={repository}
                onChange={(event) => setRepository(event.target.value)}
                placeholder="owner/repo"
                className="h-9 border-white/[0.08] bg-black/15 pl-9 text-xs"
              />
            </div>
          </div>
          <Button type="submit" disabled={pending} className="h-9 bg-[#7569ff] text-xs text-white hover:bg-[#887eff]">
            {pending ? <Loader2 className="animate-spin" /> : <Plus />} Create
          </Button>
          {error && (
            <p role="alert" className="text-[11px] text-red-300 lg:col-span-3">
              {error}
            </p>
          )}
        </form>
      )}

      {projects.length === 0 ? (
        <EmptyState
          title="No projects yet"
          copy="Create one here, or let Smart Deploy create it from a repository when a plan clears the cost guard."
        />
      ) : (
        <section className="cloud-card overflow-hidden">
          <div className="overflow-x-auto">
            <Table className="text-[11px]">
              <TableHeader>
                <TableRow className="border-white/[0.06] hover:bg-transparent">
                  {['Project', 'Framework', 'Repository', 'Readiness', 'Environment', 'Region', 'Status', 'Updated', ''].map((column, index) => (
                    <TableHead key={column || `actions-${index}`} className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25">
                      {column}
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {projects.map((project) => {
                  const expanded = expandedId === project.id;
                  const detailId = `project-readiness-${project.id}`;
                  return (
                    <Fragment key={project.id}>
                      <TableRow className="border-white/[0.05] hover:bg-white/[0.02]">
                        <TableCell className="px-4 py-3">
                          <span className="flex items-center gap-2 font-medium text-white/72">
                            <Box className="size-3.5 text-[#b7ff3c]/65" />
                            {project.name}
                          </span>
                        </TableCell>
                        <TableCell className="px-4 py-3 text-white/42">{project.framework}</TableCell>
                        <TableCell className="px-4 py-3 font-mono text-[10px] text-white/35">{project.repository ?? '—'}</TableCell>
                        <TableCell className="px-4 py-3">
                          <button
                            type="button"
                            aria-expanded={expanded}
                            aria-controls={detailId}
                            onClick={() => void toggle(project)}
                            className="inline-flex items-center gap-1.5 rounded-full px-0.5 py-0.5 text-[10px] font-medium transition-colors hover:opacity-90"
                          >
                            <Badge variant="outline" className={READINESS_TONE[project.readiness.state]}>
                              {READINESS_LABEL[project.readiness.state]}
                              {project.readiness.state === 'blocked' ? ` · ${project.readiness.blockedCount}` : ''}
                            </Badge>
                            <ChevronDown
                              aria-hidden="true"
                              className={`size-3 text-white/25 transition-transform ${expanded ? 'rotate-180' : ''}`}
                            />
                          </button>
                        </TableCell>
                        <TableCell className="px-4 py-3 text-white/42">{project.environment}</TableCell>
                        <TableCell className="px-4 py-3 text-white/42">{project.region}</TableCell>
                        <TableCell className="px-4 py-3">
                          <Badge variant="outline" className={STATUS_TONE[project.status]}>{project.status}</Badge>
                        </TableCell>
                        <TableCell className="px-4 py-3 text-white/42">{relativeTime(project.updatedAt, now)}</TableCell>
                        <TableCell className="px-4 py-3 text-right">
                          <Button
                            variant="ghost"
                            size="icon-xs"
                            aria-label={`Delete ${project.name}`}
                            disabled={removing === project.id}
                            onClick={() => void remove(project.id)}
                          >
                            {removing === project.id ? <Loader2 className="animate-spin" /> : <Trash2 />}
                          </Button>
                        </TableCell>
                      </TableRow>
                      {expanded && (
                        <TableRow className="border-white/[0.05] hover:bg-transparent">
                          <TableCell id={detailId} colSpan={9} className="bg-black/10 px-4">
                            <ReadinessDetail
                              project={project}
                              report={reportsById[project.id] ?? null}
                              loading={loadingId === project.id}
                              error={readinessErrorById[project.id] ?? null}
                              analyzing={analyzingId === project.id}
                              onAnalyze={() => void analyze(project)}
                              now={now}
                            />
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </section>
      )}
    </>
  );
}
