'use client';

import { useMemo, useState } from 'react';
import { AlertTriangle, BellRing, CheckCircle2, Clock3, RefreshCw, ShieldAlert, UserRound } from 'lucide-react';
import type { Incident, IncidentState, OrganizationMember, Project } from '@/lib/domain';
import type { IncidentSeverity } from '@/lib/incidents';
import { duration, relativeTime } from '@/lib/format';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NativeSelect } from '@/components/ui/native-select';
import { Textarea } from '@/components/ui/textarea';

type Operation =
  | { operation: 'assign'; assigneeId: string }
  | { operation: 'unassign' | 'acknowledge' | 'reopen' }
  | { operation: 'severity'; severity: IncidentSeverity }
  | { operation: 'note'; note: string }
  | { operation: 'resolve'; resolution: string };

function SeverityBadge({ severity }: { severity: IncidentSeverity }) {
  return (
    <Badge variant={severity === 'critical' ? 'destructive' : severity === 'high' ? 'secondary' : 'outline'}>
      {severity}
    </Badge>
  );
}

function Metric({ label, value, icon: Icon }: { label: string; value: string | number; icon: typeof AlertTriangle }) {
  return (
    <div className="cloud-card flex items-center gap-3 p-4">
      <span className="rounded-lg border border-white/10 bg-white/[0.035] p-2"><Icon className="size-4 text-white/55" /></span>
      <div><p className="text-xl font-semibold text-white">{value}</p><p className="text-[10px] uppercase tracking-[0.12em] text-white/35">{label}</p></div>
    </div>
  );
}

function Timeline({ incident, now }: { incident: Incident; now: number }) {
  if (incident.timeline.length === 0) return <p className="text-xs text-white/40">No timeline events.</p>;
  return (
    <ol className="space-y-2" aria-label="Incident timeline">
      {incident.timeline.map((event) => (
        <li key={event.id} className="border-l border-white/10 pl-3 text-xs">
          <div className="flex items-center justify-between gap-3">
            <span className="font-medium text-white/75">{event.type.replace('incident.', '').replaceAll('_', ' ')}</span>
            <time className="text-white/30" dateTime={new Date(event.createdAt).toISOString()}>{relativeTime(event.createdAt, now)}</time>
          </div>
          {event.message ? <p className="mt-1 whitespace-pre-wrap text-white/55">{event.message}</p> : null}
          <p className="mt-1 text-[10px] text-white/30">{event.actorType} · {event.actorId}</p>
        </li>
      ))}
    </ol>
  );
}

export function IncidentsView({
  initialState,
  members,
  projects,
  canManage,
  canResolveCritical,
  now,
}: {
  initialState: IncidentState;
  members: OrganizationMember[];
  projects: Project[];
  canManage: boolean;
  canResolveCritical: boolean;
  now: number;
}) {
  const [incidents, setIncidents] = useState(initialState.incidents);
  const [selectedId, setSelectedId] = useState(initialState.incidents[0]?.id ?? null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState('');
  const [resolution, setResolution] = useState('');
  const selected = useMemo(
    () => incidents.find((incident) => incident.id === selectedId) ?? incidents[0] ?? null,
    [incidents, selectedId],
  );

  async function mutate(incident: Incident, operation: Operation) {
    setPending(true);
    setError(null);
    try {
      const response = await fetch(`/api/incidents/${encodeURIComponent(incident.id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...operation, expectedRevision: incident.revision }),
      });
      const payload = await response.json() as { incident?: Incident; error?: string };
      if (!response.ok || !payload.incident) throw new Error(payload.error ?? 'Incident could not be updated.');
      setIncidents((current) => current.map((item) => item.id === payload.incident!.id ? payload.incident! : item));
      setNote('');
      setResolution('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Incident could not be updated.');
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="space-y-5">
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-8" aria-label="Operations summary">
        <Metric label="Open" value={initialState.summary.open} icon={AlertTriangle} />
        <Metric label="Acknowledged" value={initialState.summary.acknowledged} icon={CheckCircle2} />
        <Metric label="Critical" value={initialState.summary.critical} icon={ShieldAlert} />
        <Metric label="Resolved" value={initialState.summary.resolved} icon={CheckCircle2} />
        <Metric label="Unassigned" value={initialState.summary.unassigned} icon={UserRound} />
        <Metric label="Occurrences" value={initialState.summary.occurrences} icon={BellRing} />
        <Metric label="MTTA" value={duration(initialState.summary.mttaMs)} icon={Clock3} />
        <Metric label="MTTR" value={duration(initialState.summary.mttrMs)} icon={CheckCircle2} />
      </section>

      <form method="get" className="cloud-card grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-7" aria-label="Incident filters">
        <Input name="search" defaultValue={initialState.filters.search} placeholder="Search title, resource, correlation…" aria-label="Search incidents" />
        <NativeSelect name="status" defaultValue={initialState.filters.status} aria-label="Status">
          <option value="all">All statuses</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option>
        </NativeSelect>
        <NativeSelect name="severity" defaultValue={initialState.filters.severity} aria-label="Severity">
          <option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
        </NativeSelect>
        <NativeSelect name="projectId" defaultValue={initialState.filters.projectId} aria-label="Project">
          <option value="all">All projects</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
        </NativeSelect>
        <NativeSelect name="assignee" defaultValue={initialState.filters.assignee} aria-label="Assignee">
          <option value="all">All assignees</option><option value="unassigned">Unassigned</option>{members.filter((member) => member.status === 'active').map((member) => <option key={member.userId} value={member.userId}>{member.name}</option>)}
        </NativeSelect>
        <Input name="resourceType" defaultValue={initialState.filters.resourceType === 'all' ? '' : initialState.filters.resourceType} placeholder="Resource type" aria-label="Resource type" />
        <Button type="submit" variant="secondary">Apply filters</Button>
      </form>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,0.85fr)_minmax(0,1.35fr)]">
        <section className="cloud-card overflow-hidden" aria-label="Incident inbox">
          <div className="border-b border-white/[0.07] px-4 py-3"><h2 className="text-sm font-semibold text-white">Incident inbox</h2><p className="text-[11px] text-white/35">Bounded to {initialState.hardLimits.list} results.</p></div>
          {incidents.length === 0 ? <p className="p-6 text-sm text-white/45">No incidents match these filters.</p> : (
            <div className="max-h-[720px] divide-y divide-white/[0.055] overflow-y-auto [content-visibility:auto]">
              {incidents.map((incident) => (
                <button key={incident.id} type="button" onClick={() => setSelectedId(incident.id)}
                  className={`w-full p-4 text-left transition hover:bg-white/[0.035] ${selected?.id === incident.id ? 'bg-white/[0.05]' : ''}`}>
                  <div className="flex items-start justify-between gap-3"><p className="text-sm font-medium text-white/85">{incident.title}</p><SeverityBadge severity={incident.severity} /></div>
                  <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-white/35"><span>{incident.status}</span><span>×{incident.occurrenceCount}</span><span>{relativeTime(incident.lastSeenAt, now)}</span><span>{incident.assigneeName ?? 'Unassigned'}</span></div>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="cloud-card min-h-[440px] p-5" aria-label="Incident inspector">
          {!selected ? <p className="text-sm text-white/45">Select an incident to inspect it.</p> : (
            <div className="space-y-5">
              <header>
                <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={selected.severity} /><Badge variant="outline">{selected.status}</Badge><Badge variant="outline">revision {selected.revision}</Badge></div>
                <h2 className="mt-3 text-xl font-semibold text-white">{selected.title}</h2>
                <p className="mt-2 whitespace-pre-wrap text-sm text-white/55">{selected.detail}</p>
                <dl className="mt-3 grid gap-2 text-[11px] text-white/40 sm:grid-cols-2">
                  <div><dt>Correlation ID</dt><dd className="break-all font-mono text-white/65">{selected.correlationId}</dd></div>
                  <div><dt>Resource</dt><dd className="break-all font-mono text-white/65">{selected.resourceType}:{selected.resourceId ?? 'workspace'}</dd></div>
                  <div><dt>Project</dt><dd className="break-all font-mono text-white/65">{selected.projectId ?? 'workspace-wide'}</dd></div>
                  <div><dt>Occurrences</dt><dd className="text-white/65">{selected.occurrenceCount} · last seen {relativeTime(selected.lastSeenAt, now)}</dd></div>
                  <div><dt>Workflow</dt><dd className="break-all font-mono text-white/65">{selected.workflowId ?? 'system'}</dd></div>
                  <div><dt>Execution</dt><dd className="break-all font-mono text-white/65">{selected.executionId ?? 'none'}</dd></div>
                  <div><dt>Created</dt><dd className="text-white/65">{new Date(selected.createdAt).toISOString()}</dd></div>
                  <div><dt>Acknowledged / resolved</dt><dd className="text-white/65">{selected.acknowledgedAt ? new Date(selected.acknowledgedAt).toISOString() : 'not acknowledged'} · {selected.resolvedAt ? new Date(selected.resolvedAt).toISOString() : 'not resolved'}</dd></div>
                </dl>
              </header>

              {canManage ? (
                <div className="grid gap-3 rounded-xl border border-white/[0.07] bg-black/10 p-4">
                  <div className="flex flex-wrap gap-2">
                    {selected.status === 'open' ? <Button disabled={pending} onClick={() => mutate(selected, { operation: 'acknowledge' })}>Acknowledge</Button> : null}
                    {selected.status === 'resolved' ? <Button disabled={pending} onClick={() => mutate(selected, { operation: 'reopen' })}><RefreshCw />Reopen</Button> : null}
                    <NativeSelect aria-label="Change severity" disabled={pending} value={selected.severity} onChange={(event) => mutate(selected, { operation: 'severity', severity: event.target.value as IncidentSeverity })}>
                      <option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option>
                    </NativeSelect>
                    <NativeSelect aria-label="Assign incident" disabled={pending} value={selected.assignedTo ?? ''} onChange={(event) => mutate(selected, event.target.value ? { operation: 'assign', assigneeId: event.target.value } : { operation: 'unassign' })}>
                      <option value="">Unassigned</option>{members.filter((member) => member.status === 'active').map((member) => <option key={member.userId} value={member.userId}>{member.name} · {member.role}</option>)}
                    </NativeSelect>
                  </div>
                  <div className="grid gap-2 sm:grid-cols-[1fr_auto]"><Textarea value={note} onChange={(event) => setNote(event.target.value)} maxLength={1000} placeholder="Add a safe plain-text note (no URLs, secrets, or commands)" aria-label="Incident note" /><Button disabled={pending || !note.trim()} variant="secondary" onClick={() => mutate(selected, { operation: 'note', note })}>Add note</Button></div>
                  {selected.status !== 'resolved' ? <div className="grid gap-2 sm:grid-cols-[1fr_auto]"><Textarea value={resolution} onChange={(event) => setResolution(event.target.value)} maxLength={1000} placeholder="Resolution summary" aria-label="Resolution summary" /><Button disabled={pending || !resolution.trim() || (selected.severity === 'critical' && !canResolveCritical)} variant="outline" onClick={() => mutate(selected, { operation: 'resolve', resolution })}>Resolve</Button></div> : null}
                  {selected.severity === 'critical' && !canResolveCritical ? <p className="text-[11px] text-amber-300/70">Critical resolution requires an owner or admin.</p> : null}
                  {error ? <p role="alert" className="text-xs text-red-300">{error}</p> : null}
                </div>
              ) : <p className="rounded-lg border border-white/[0.07] p-3 text-xs text-white/45">Read-only incident access.</p>}

              <div><h3 className="mb-3 text-sm font-semibold text-white">Timeline</h3><Timeline incident={selected} now={now} /></div>
            </div>
          )}
        </section>
      </div>
      <p className="text-[11px] text-white/30">Zero Mode enforced · D1-only operations · projected monthly cost $0.00</p>
    </div>
  );
}
