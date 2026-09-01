'use client';

import { useRouter } from 'next/navigation';
import { useMemo, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowRight, Bell, CheckCircle2, Clock3,
  Copy, GitBranch, History, KeyRound, Loader2, Pause, Play, Plus,
  Radio, RefreshCcw, RotateCcw, ShieldCheck, Trash2, Variable, Workflow as WorkflowIcon,
  XCircle,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NativeSelect } from '@/components/ui/native-select';
import { EmptyState } from '@/components/ui-bits';
import type { Project, Secret, WorkflowsState } from '@/lib/domain';
import { relativeTime } from '@/lib/format';
import type { Role } from '@/lib/roles';
import {
  CONDITION_OPERATORS,
  WORKFLOW_ACTION_TYPES,
  WORKFLOW_EVENT_PATHS,
  WORKFLOW_EXTERNAL_EVENT_PATHS,
  WORKFLOW_TRIGGER_TYPES,
  type WorkflowAction,
  type WorkflowActionType,
  type WorkflowDefinition,
  type WorkflowTriggerType,
} from '@/lib/workflows';

type Props = {
  state: WorkflowsState;
  actor: { userId: string; role: Role };
  projects: Project[];
  secrets: Secret[];
  now: number;
};

const privilegedActions = new Set<WorkflowActionType>([
  'node.disable_assignments', 'node.revoke', 'game_server.stop',
  'game_server.restart', 'ai.job.cancel', 'shield.acknowledge',
]);

const executionTone: Record<string, string> = {
  succeeded: 'border-[#b7ff3c]/20 text-[#c8ff69]',
  running: 'border-sky-300/20 text-sky-300',
  queued: 'border-white/15 text-white/55',
  waiting: 'border-amber-300/20 text-amber-300',
  failed: 'border-red-300/20 text-red-300',
  timed_out: 'border-red-300/20 text-red-300',
  cancelled: 'border-white/12 text-white/35',
  skipped: 'border-white/12 text-white/35',
};

function label(value: string): string {
  return value.replaceAll('_', ' ').replaceAll('.', ' · ');
}

function compatibleActions(trigger: WorkflowTriggerType, role: Role): WorkflowActionType[] {
  const prefix = trigger.split('.')[0];
  return WORKFLOW_ACTION_TYPES.filter((action) => {
    if (role === 'developer' && privilegedActions.has(action)) return false;
    if (['notification.create', 'audit.note', 'shield.create_incident', 'workflow.pause'].includes(action)) return true;
    return action.split('.')[0] === prefix;
  });
}

function actionDefinition(type: WorkflowActionType): WorkflowAction {
  if (type === 'workflow.pause') return { type, target: 'self' };
  if (type === 'notification.create') {
    return { type, target: 'event.resource', title: 'Workflow notification', message: 'A reviewed YSD workflow condition matched.', severity: 'medium' };
  }
  if (type === 'shield.create_incident') {
    return { type, target: 'event.resource', title: 'Workflow incident', message: 'A reviewed YSD workflow action opened this incident.', severity: 'high' };
  }
  if (type === 'audit.note') {
    return { type, target: 'event.resource', message: 'A reviewed YSD workflow condition matched.' };
  }
  if (type === 'node.revoke') return { type, target: 'event.resource', confirmationPolicy: 'owner-admin' };
  return { type, target: 'event.resource' };
}

function Pipeline({ definition }: { definition: WorkflowDefinition }) {
  return (
    <div className="mt-4 grid items-stretch gap-2 md:grid-cols-[1fr_auto_1fr_auto_1.2fr]">
      <div className="rounded-xl border border-sky-300/10 bg-sky-300/[0.035] p-3">
        <p className="text-[9px] font-semibold uppercase tracking-[0.14em] text-sky-300/55">Trigger</p>
        <p className="mt-2 break-words font-mono text-[10px] text-white/65">{label(definition.trigger.type)}</p>
        {definition.trigger.type === 'external.event' && <p className="mt-1 break-all font-mono text-[8px] text-white/28">{definition.trigger.sourceId}</p>}
      </div>
      <ArrowRight className="m-auto hidden size-4 text-white/18 md:block" />
      <div className="rounded-xl border border-amber-300/10 bg-amber-300/[0.03] p-3">
        <p className="text-[9px] font-semibold uppercase tracking-[0.14em] text-amber-300/55">Conditions</p>
        <p className="mt-2 text-[10px] text-white/55">
          {definition.conditions.length === 0 ? 'Always' : `${definition.conditions.length} allowlisted rule${definition.conditions.length === 1 ? '' : 's'}`}
        </p>
      </div>
      <ArrowRight className="m-auto hidden size-4 text-white/18 md:block" />
      <div className="rounded-xl border border-[#b7ff3c]/10 bg-[#b7ff3c]/[0.025] p-3">
        <p className="text-[9px] font-semibold uppercase tracking-[0.14em] text-[#c8ff69]/55">Actions</p>
        <p className="mt-2 text-[10px] leading-4 text-white/55">{definition.actions.map((action) => label(action.type)).join(' → ')}</p>
      </div>
    </div>
  );
}

export function WorkflowsView({ state, actor, projects, secrets, now }: Props) {
  const router = useRouter();
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('Internal workflow notification');
  const [projectId, setProjectId] = useState(projects[0]?.id ?? '');
  const [trigger, setTrigger] = useState<WorkflowTriggerType>('manual');
  const availableActions = useMemo(() => compatibleActions(trigger, actor.role), [trigger, actor.role]);
  const [action, setAction] = useState<WorkflowActionType>('notification.create');
  const [useCondition, setUseCondition] = useState(false);
  const [conditionPath, setConditionPath] = useState<(typeof WORKFLOW_EVENT_PATHS)[number]>('event.payload.status');
  const [conditionOperator, setConditionOperator] = useState<(typeof CONDITION_OPERATORS)[number]>('equals');
  const [conditionValue, setConditionValue] = useState('failed');
  const [intervalMinutes, setIntervalMinutes] = useState('15');
  const [externalSourceId, setExternalSourceId] = useState(
    state.webhookGateway.sources.find((source) => source.status === 'enabled' && source.projectId === null)?.id ?? '',
  );
  const [sourceName, setSourceName] = useState('External event source');
  const [sourceDescription, setSourceDescription] = useState('Signed JSON events for reviewed YSD workflows.');
  const [sourceProjectId, setSourceProjectId] = useState(actor.role === 'developer' ? projects[0]?.id ?? '' : '');
  const [revealedSecret, setRevealedSecret] = useState<{ sourceId: string; secret: string } | null>(null);
  const [variableWorkflow, setVariableWorkflow] = useState(state.workflows[0]?.id ?? '');
  const [variableName, setVariableName] = useState('SAFE_VALUE');
  const [variableKind, setVariableKind] = useState<'text' | 'number' | 'boolean' | 'secret'>('text');
  const [variableValue, setVariableValue] = useState('enabled');
  const [variableSecret, setVariableSecret] = useState(secrets[0]?.id ?? '');

  const canCreate = actor.role !== 'viewer';
  const canRetry = actor.role === 'owner' || actor.role === 'admin';
  const canManageSources = actor.role === 'owner' || actor.role === 'admin';
  const eligibleSources = state.webhookGateway.sources.filter(
    (source) => source.status === 'enabled' && source.projectId === (projectId || null),
  );
  const conditionPaths = trigger === 'external.event'
    ? WORKFLOW_EXTERNAL_EVENT_PATHS
    : WORKFLOW_EVENT_PATHS.filter((path) => ![
        'event.payload.sourceId', 'event.payload.externalEventType', 'event.payload.externalEventId',
        'event.payload.subject', 'event.payload.category', 'event.payload.action', 'event.payload.ref',
        'event.payload.label', 'event.payload.count', 'event.payload.value', 'event.payload.success',
      ].includes(path));

  async function request<T = Record<string, never>>(key: string, url: string, init: RequestInit): Promise<T | null> {
    setPending(key);
    setError(null);
    try {
      const response = await fetch(url, init);
      const body = (response.status === 204
        ? {}
        : await response.json().catch(() => ({}))) as { error?: string } & T;
      if (!response.ok) throw new Error(body.error ?? 'The operation failed.');
      router.refresh();
      return body as T;
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The operation failed.');
      return null;
    } finally {
      setPending(null);
    }
  }

  async function workflowOperation(workflowId: string, operation: string, extra: Record<string, unknown> = {}) {
    return request(`${workflowId}:${operation}`, `/api/workflows/${workflowId}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ operation, ...extra }),
    });
  }

  async function createCustom() {
    const pickedAction = compatibleActions(trigger, actor.role).includes(action)
      ? action
      : 'notification.create';
    const numeric = ['greater_than', 'greater_or_equal', 'less_than', 'less_or_equal'].includes(conditionOperator);
    const inList = conditionOperator === 'in';
    const parsedCondition = numeric
      ? Number(conditionValue)
      : inList ? conditionValue.split(',').map((item) => item.trim()).filter(Boolean) : conditionValue;
    const definition: WorkflowDefinition = {
      trigger: trigger === 'schedule'
        ? { type: 'schedule', intervalMinutes: Math.max(5, Math.min(1440, Number(intervalMinutes) || 15)) }
        : trigger === 'external.event'
          ? { type: 'external.event', sourceId: externalSourceId }
        : { type: trigger },
      conditions: useCondition ? [{ path: conditionPath, operator: conditionOperator, value: parsedCondition }] : [],
      actions: [actionDefinition(pickedAction)],
      retry: { maxAttempts: 3, initialDelaySeconds: 10, maximumDelaySeconds: 120 },
      timeoutSeconds: 120,
      concurrency: { workflow: 1, workspace: 4 },
    };
    await request('create-custom', '/api/workflows', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name,
        description: 'Created with the bounded YSD visual workflow builder.',
        projectId: projectId || null,
        definition,
      }),
    });
  }

  async function createTemplate(templateId: string, templateName: string, projectScoped: boolean) {
    const scopedProject = projectScoped || actor.role === 'developer' ? projectId : projectId || null;
    await request(`template:${templateId}`, '/api/workflows', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ templateId, name: templateName, projectId: scopedProject }),
    });
  }

  async function setVariable() {
    if (!variableWorkflow) return;
    await request(`variable:${variableWorkflow}`, `/api/workflows/${variableWorkflow}/variables`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        operation: 'set', name: variableName, kind: variableKind,
        ...(variableKind === 'secret' ? { secretId: variableSecret } : { value: variableValue }),
      }),
    });
  }

  async function createSource() {
    const result = await request<{ source: { id: string }; secret: string }>(
      'source:create', '/api/webhook-sources', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: sourceName,
          description: sourceDescription,
          projectId: sourceProjectId || null,
        }),
      },
    );
    if (result) setRevealedSecret({ sourceId: result.source.id, secret: result.secret });
  }

  async function sourceOperation(sourceId: string, operation: 'rotate' | 'enable' | 'disable') {
    const result = await request<{ source: { id: string }; secret?: string }>(
      `source:${sourceId}:${operation}`, `/api/webhook-sources/${sourceId}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operation }),
      },
    );
    if (result?.secret) setRevealedSecret({ sourceId, secret: result.secret });
  }

  async function copyText(value: string) {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      setError('Copy was blocked by the browser. Select the value manually.');
    }
  }

  return (
    <div className="space-y-5">
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {[
          { title: 'Workflows', value: state.summary.total, Icon: WorkflowIcon },
          { title: 'Active', value: state.summary.active, Icon: Play },
          { title: 'Paused', value: state.summary.paused, Icon: Pause },
          { title: 'Failed', value: state.summary.failedExecutions, Icon: AlertTriangle },
          { title: 'Unread', value: state.summary.unreadNotifications, Icon: Bell },
        ].map(({ title, value, Icon }) => (
          <article key={title} className="cloud-card p-4">
            <Icon className="size-4 text-[#b7ff3c]/65" />
            <p className="mt-4 text-2xl font-semibold tracking-tight text-white">{value}</p>
            <p className="mt-1 text-[9px] uppercase tracking-[0.14em] text-white/28">{title}</p>
          </article>
        ))}
      </section>

      <section className="cloud-card overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-white/[0.065] px-5 py-4 md:flex-row md:items-center">
          <div>
            <h2 className="text-sm font-semibold text-white/80">Zero Mode execution plane</h2>
            <p className="mt-1 text-[10px] text-white/30">One free global Cron Trigger → current Worker → current D1 state machine. No Queue, Durable Object, external provider, URL, shell, or script.</p>
          </div>
          <div className="md:ml-auto flex items-center gap-2">
            <Badge variant="outline" className="border-[#b7ff3c]/15 text-[#c8ff69]">$0.00 / month</Badge>
            <Badge variant="outline" className="border-white/10 text-white/45">{state.schedule.tickMinutes} min tick</Badge>
          </div>
        </div>
        {error && <p role="alert" className="border-b border-red-300/10 bg-red-300/[0.04] px-5 py-3 text-[11px] text-red-300">{error}</p>}
      </section>

      <section className="cloud-card overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-white/[0.065] px-5 py-4 md:flex-row md:items-center">
          <div>
            <div className="flex items-center gap-2"><Radio className="size-4 text-[#b7ff3c]/65" /><h2 className="text-sm font-semibold text-white/80">External Event Gateway</h2></div>
            <p className="mt-1 text-[10px] text-white/30">Signed inbound JSON only. HMAC v1, 5-minute timestamp window, single-use event IDs and nonces, bounded allowlisted fields, and no outbound HTTP.</p>
          </div>
          <div className="md:ml-auto flex flex-wrap gap-2">
            <Badge variant="outline" className="border-white/10 text-white/42">received {state.webhookGateway.summary.received}</Badge>
            <Badge variant="outline" className="border-[#b7ff3c]/15 text-[#c8ff69]">accepted {state.webhookGateway.summary.accepted}</Badge>
            <Badge variant="outline" className="border-red-300/15 text-red-300">rejected {state.webhookGateway.summary.rejected}</Badge>
            <Badge variant="outline" className="border-amber-300/15 text-amber-300">deduped {state.webhookGateway.summary.deduplicated}</Badge>
            <Badge variant="outline" className="border-sky-300/15 text-sky-300">executions {state.webhookGateway.summary.workflowExecutionsCreated}</Badge>
          </div>
        </div>

        {revealedSecret && <div className="border-b border-amber-300/10 bg-amber-300/[0.035] px-5 py-4">
          <div className="flex items-center gap-2"><KeyRound className="size-4 text-amber-300" /><p className="text-[11px] font-semibold text-amber-200">Copy this secret now. It will not be shown again.</p></div>
          <div className="mt-3 flex flex-col gap-2 sm:flex-row">
            <code className="min-w-0 flex-1 overflow-x-auto rounded-lg border border-amber-300/10 bg-black/20 px-3 py-2 text-[10px] text-amber-100">{revealedSecret.secret}</code>
            <Button size="sm" variant="outline" onClick={() => void copyText(revealedSecret.secret)}><Copy /> Copy secret</Button>
            <Button size="sm" variant="ghost" onClick={() => setRevealedSecret(null)}>Dismiss</Button>
          </div>
        </div>}

        {canManageSources && <div className="grid gap-3 border-b border-white/[0.055] p-5 lg:grid-cols-[1fr_1.4fr_1fr_auto]">
          <Input value={sourceName} onChange={(event) => setSourceName(event.target.value)} aria-label="Webhook source name" className="text-xs" />
          <Input value={sourceDescription} onChange={(event) => setSourceDescription(event.target.value)} aria-label="Webhook source description" className="text-xs" />
          <NativeSelect value={sourceProjectId} onChange={(event) => setSourceProjectId(event.target.value)} className="w-full text-xs" aria-label="Webhook source scope">
            <option value="">Workspace scope</option>
            {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
          </NativeSelect>
          <Button disabled={pending !== null || !sourceName.trim()} onClick={() => void createSource()}>{pending === 'source:create' ? <Loader2 className="animate-spin" /> : <Plus />} Create source</Button>
        </div>}

        {state.webhookGateway.sources.length === 0 ? <p className="px-5 py-10 text-center text-[10px] text-white/25">No webhook sources in this workspace.</p> : <div className="divide-y divide-white/[0.05]">
          {state.webhookGateway.sources.map((source) => (
            <div key={source.id} className="px-5 py-4">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-xs font-semibold text-white/68">{source.name}</p>
                    <Badge variant="outline" className={source.status === 'enabled' ? 'border-[#b7ff3c]/15 text-[#c8ff69]' : 'border-white/10 text-white/35'}>{source.status}</Badge>
                    <span className="font-mono text-[8px] text-white/22">secret v{source.secretVersion}</span>
                  </div>
                  <p className="mt-1 text-[10px] text-white/28">{source.description || 'No description.'}</p>
                  <div className="mt-2 flex min-w-0 items-center gap-2">
                    <code className="truncate text-[9px] text-sky-300/55">{source.webhookPath}</code>
                    <Button size="icon-xs" variant="ghost" aria-label={`Copy URL for ${source.name}`} onClick={() => void copyText(`${window.location.origin}${source.webhookPath}`)}><Copy /></Button>
                  </div>
                  <p className="mt-2 text-[9px] text-white/22">last received {source.lastReceivedAt ? relativeTime(source.lastReceivedAt, now) : 'never'} · accepted {source.acceptedCount} · rejected {source.rejectedCount} · deduped {source.deduplicatedCount} · executions {source.workflowExecutionsCreated}</p>
                </div>
                {canManageSources && <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="outline" disabled={pending !== null} onClick={() => void sourceOperation(source.id, 'rotate')}><KeyRound /> Rotate</Button>
                  <Button size="sm" variant="outline" disabled={pending !== null} onClick={() => void sourceOperation(source.id, source.status === 'enabled' ? 'disable' : 'enable')}>{source.status === 'enabled' ? <Pause /> : <Play />} {source.status === 'enabled' ? 'Disable' : 'Enable'}</Button>
                  <Button size="icon-sm" variant="destructive" aria-label={`Archive ${source.name}`} disabled={pending !== null} onClick={() => { if (window.confirm(`Archive webhook source “${source.name}”? Existing signatures will stop working.`)) void request(`source:${source.id}:archive`, `/api/webhook-sources/${source.id}`, { method: 'DELETE' }); }}><Trash2 /></Button>
                </div>}
              </div>
            </div>
          ))}
        </div>}

        <div className="border-t border-white/[0.05] px-5 py-4">
          <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-white/38">Signing contract</p>
          <p className="mt-2 text-[9px] leading-5 text-white/26">Headers: x-ysd-timestamp, x-ysd-event-id, x-ysd-nonce, x-ysd-signature. Sign <span className="font-mono text-white/40">timestamp.eventId.nonce.rawJsonBody</span> with HMAC-SHA256 and prefix the lowercase hex digest with <span className="font-mono text-white/40">v1=</span>.</p>
        </div>
      </section>

      {state.webhookGateway.recentEvents.length > 0 && <section className="cloud-card overflow-hidden">
        <div className="border-b border-white/[0.06] px-5 py-4"><h2 className="text-sm font-semibold text-white/75">Recent safe webhook history</h2><p className="mt-1 text-[10px] text-white/28">Metadata only; signed bodies, signatures, nonces, and secret values are never retained.</p></div>
        <div className="divide-y divide-white/[0.05]">{state.webhookGateway.recentEvents.map((event) => (
          <div key={event.id} className="flex flex-wrap items-center gap-2 px-5 py-3">
            <Badge variant="outline" className={event.status === 'accepted' ? 'border-[#b7ff3c]/15 text-[#c8ff69]' : event.status === 'deduplicated' ? 'border-amber-300/15 text-amber-300' : 'border-red-300/15 text-red-300'}>{event.status}</Badge>
            <span className="font-mono text-[9px] text-white/38">{event.eventType ?? event.reasonCode ?? 'rejected before parsing'}</span>
            {event.subject && <span className="text-[9px] text-white/30">{event.subject}</span>}
            {event.externalEventId && <span className="font-mono text-[8px] text-white/22">event {event.externalEventId}</span>}
            <span className="ml-auto text-[9px] text-white/22">{event.workflowExecutionsCreated} executions · {relativeTime(event.receivedAt, now)}</span>
          </div>
        ))}</div>
      </section>}

      {canCreate && (
        <section className="cloud-card overflow-hidden">
          <div className="border-b border-white/[0.065] px-5 py-4">
            <h2 className="text-sm font-semibold text-white/80">Safe workflow builder</h2>
            <p className="mt-1 text-[10px] text-white/28">A bounded form creates an immutable draft. Publishing runs the same server-side security validation again.</p>
          </div>
          <div className="grid gap-4 p-5 xl:grid-cols-[1fr_1fr_1fr]">
            <div className="rounded-xl border border-sky-300/10 bg-sky-300/[0.025] p-4">
              <p className="text-[9px] font-semibold uppercase tracking-[0.14em] text-sky-300/55">1 · Trigger</p>
              <Input value={name} onChange={(event) => setName(event.target.value)} aria-label="Workflow name" className="mt-3 text-xs" />
              <NativeSelect value={trigger} onChange={(event) => {
                const next = event.target.value as WorkflowTriggerType;
                setTrigger(next);
                setAction(compatibleActions(next, actor.role)[0] ?? 'notification.create');
                if (next === 'external.event') {
                  setConditionPath('event.payload.externalEventType');
                  setExternalSourceId(state.webhookGateway.sources.find((source) => source.status === 'enabled' && source.projectId === (projectId || null))?.id ?? '');
                }
              }} className="mt-2 w-full text-xs" aria-label="Workflow trigger">
                {WORKFLOW_TRIGGER_TYPES.map((item) => <option key={item} value={item}>{label(item)}</option>)}
              </NativeSelect>
              {trigger === 'schedule' && <Input type="number" min={5} max={1440} value={intervalMinutes} onChange={(event) => setIntervalMinutes(event.target.value)} className="mt-2 text-xs" aria-label="Schedule interval minutes" />}
              {trigger === 'external.event' && <NativeSelect value={eligibleSources.some((source) => source.id === externalSourceId) ? externalSourceId : ''} onChange={(event) => setExternalSourceId(event.target.value)} className="mt-2 w-full text-xs" aria-label="External event source">
                <option value="">Choose an enabled source</option>
                {eligibleSources.map((source) => <option key={source.id} value={source.id}>{source.name}</option>)}
              </NativeSelect>}
              <NativeSelect value={projectId} onChange={(event) => {
                const nextProjectId = event.target.value;
                setProjectId(nextProjectId);
                setExternalSourceId(state.webhookGateway.sources.find((source) => source.status === 'enabled' && source.projectId === (nextProjectId || null))?.id ?? '');
              }} className="mt-2 w-full text-xs" aria-label="Workflow project">
                {actor.role !== 'developer' && <option value="">Workspace scope</option>}
                {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
              </NativeSelect>
            </div>
            <div className="rounded-xl border border-amber-300/10 bg-amber-300/[0.025] p-4">
              <div className="flex items-center justify-between">
                <p className="text-[9px] font-semibold uppercase tracking-[0.14em] text-amber-300/55">2 · Conditions</p>
                <Button size="xs" variant="ghost" onClick={() => setUseCondition((value) => !value)}>{useCondition ? 'Remove' : 'Add rule'}</Button>
              </div>
              {useCondition ? <>
                <NativeSelect value={conditionPath} onChange={(event) => setConditionPath(event.target.value as typeof conditionPath)} className="mt-3 w-full text-xs" aria-label="Condition field">
                  {conditionPaths.map((item) => <option key={item} value={item}>{item}</option>)}
                </NativeSelect>
                <NativeSelect value={conditionOperator} onChange={(event) => setConditionOperator(event.target.value as typeof conditionOperator)} className="mt-2 w-full text-xs" aria-label="Condition operator">
                  {CONDITION_OPERATORS.map((item) => <option key={item} value={item}>{label(item)}</option>)}
                </NativeSelect>
                <Input value={conditionValue} onChange={(event) => setConditionValue(event.target.value)} className="mt-2 text-xs" aria-label="Condition value" />
              </> : <p className="mt-4 text-[10px] leading-5 text-white/30">No condition means every trusted matching event proceeds. Raw client events and arbitrary JSON paths are never accepted.</p>}
            </div>
            <div className="rounded-xl border border-[#b7ff3c]/10 bg-[#b7ff3c]/[0.02] p-4">
              <p className="text-[9px] font-semibold uppercase tracking-[0.14em] text-[#c8ff69]/55">3 · Actions</p>
              <NativeSelect value={availableActions.includes(action) ? action : availableActions[0]} onChange={(event) => setAction(event.target.value as WorkflowActionType)} className="mt-3 w-full text-xs" aria-label="Workflow action">
                {availableActions.map((item) => <option key={item} value={item}>{label(item)}</option>)}
              </NativeSelect>
              <p className="mt-3 text-[10px] leading-5 text-white/30">Retries 3 · timeout 120s · workflow concurrency 1 · workspace concurrency 4.</p>
              <Button disabled={pending !== null || !name.trim() || (actor.role === 'developer' && !projectId) || (trigger === 'external.event' && !eligibleSources.some((source) => source.id === externalSourceId))} onClick={() => void createCustom()} className="mt-4 w-full bg-[#b7ff3c] text-[#07100c] hover:bg-[#cbff72]">
                {pending === 'create-custom' ? <Loader2 className="animate-spin" /> : <Plus />} Create immutable draft
              </Button>
            </div>
          </div>
        </section>
      )}

      {canCreate && (
        <section>
          <div className="mb-3 flex items-end justify-between">
            <div><h2 className="text-sm font-semibold text-white/75">Guarded templates</h2><p className="mt-1 text-[10px] text-white/28">Internal configs only; no paid provider or external transport.</p></div>
          </div>
          <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
            {state.templates.map((template) => {
              const needsProject = template.projectScoped || actor.role === 'developer';
              const blocked = needsProject && !projectId;
              const privileged = template.definition.actions.some((item) => privilegedActions.has(item.type));
              const roleBlocked = actor.role === 'developer' && privileged;
              return (
                <article key={template.id} className="cloud-card flex flex-col p-4">
                  <GitBranch className="size-4 text-[#b7ff3c]/60" />
                  <h3 className="mt-4 text-xs font-semibold text-white/72">{template.name}</h3>
                  <p className="mt-2 flex-1 text-[10px] leading-5 text-white/30">{template.description}</p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    <Badge variant="outline" className="border-white/10 text-[8px] text-white/38">{label(template.definition.trigger.type)}</Badge>
                    <Badge variant="outline" className="border-white/10 text-[8px] text-white/38">{template.definition.actions.length} actions</Badge>
                  </div>
                  <Button variant="outline" size="sm" className="mt-4" disabled={pending !== null || blocked || roleBlocked} onClick={() => void createTemplate(template.id, template.name, template.projectScoped)}>
                    {pending === `template:${template.id}` ? <Loader2 className="animate-spin" /> : <Plus />}
                    {roleBlocked ? 'Owner/admin required' : blocked ? 'Choose a project' : 'Use template'}
                  </Button>
                </article>
              );
            })}
          </div>
        </section>
      )}

      <section className="space-y-3">
        <div><h2 className="text-sm font-semibold text-white/75">Workflow library</h2><p className="mt-1 text-[10px] text-white/28">Status, immutable versions, execution history, retries, and correlation chains.</p></div>
        {state.workflows.length === 0 ? <EmptyState title="No workflows yet" copy="Start with a guarded template or create a bounded manual workflow above." /> : state.workflows.map((workflow) => {
          const definition = workflow.activeVersion?.definition ?? workflow.versions[0]?.definition;
          const latestDraft = workflow.versions.find((version) => version.kind === 'draft');
          const mayManage = actor.role === 'owner' || actor.role === 'admin' || (actor.role === 'developer' && workflow.ownerUserId === actor.userId && workflow.projectId !== null);
          return (
            <article key={workflow.id} className="cloud-card overflow-hidden">
              <div className="flex flex-col gap-3 border-b border-white/[0.06] px-5 py-4 lg:flex-row lg:items-start">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-sm font-semibold text-white/78">{workflow.name}</h3>
                    <Badge variant="outline" className={workflow.status === 'active' ? 'border-[#b7ff3c]/18 text-[#c8ff69]' : workflow.status === 'paused' ? 'border-amber-300/18 text-amber-300' : 'border-white/12 text-white/40'}>{workflow.status}</Badge>
                    <span className="font-mono text-[9px] text-white/22">{workflow.id}</span>
                  </div>
                  <p className="mt-2 text-[10px] leading-5 text-white/30">{workflow.description || 'No description.'}</p>
                </div>
                {mayManage && <div className="flex flex-wrap gap-2">
                  {latestDraft && <Button size="sm" variant="outline" disabled={pending !== null} onClick={() => void workflowOperation(workflow.id, 'publish', { versionId: latestDraft.id })}><CheckCircle2 /> Publish v{latestDraft.version}</Button>}
                  {workflow.status === 'active' ? <Button size="sm" variant="outline" disabled={pending !== null} onClick={() => void workflowOperation(workflow.id, 'pause')}><Pause /> Pause</Button> : workflow.activeVersionId && <Button size="sm" variant="outline" disabled={pending !== null} onClick={() => void workflowOperation(workflow.id, 'resume')}><Play /> Resume</Button>}
                  {workflow.activeVersion?.definition.trigger.type === 'manual' && workflow.status === 'active' && <Button size="sm" disabled={pending !== null} onClick={() => void workflowOperation(workflow.id, 'manual-run')}><Play /> Run now</Button>}
                  <Button size="icon-sm" variant="destructive" aria-label={`Delete ${workflow.name}`} disabled={pending !== null} onClick={() => { if (window.confirm(`Archive workflow “${workflow.name}”?`)) void request(`${workflow.id}:delete`, `/api/workflows/${workflow.id}`, { method: 'DELETE' }); }}><Trash2 /></Button>
                </div>}
              </div>
              <div className="px-5 pb-5">
                {definition && <Pipeline definition={definition} />}
                <div className="mt-4 grid gap-4 xl:grid-cols-[.72fr_1.28fr]">
                  <div className="rounded-xl border border-white/[0.06] p-4">
                    <div className="flex items-center gap-2"><History className="size-4 text-white/35" /><h4 className="text-[10px] font-semibold uppercase tracking-[0.12em] text-white/45">Version history</h4></div>
                    <div className="mt-3 space-y-2">
                      {workflow.versions.slice(0, 8).map((version) => (
                        <div key={version.id} className="flex items-center gap-2 rounded-lg bg-white/[0.018] px-3 py-2">
                          <span className="font-mono text-[10px] text-white/50">v{version.version}</span>
                          <Badge variant="outline" className="border-white/10 text-[8px] text-white/35">{version.kind}</Badge>
                          {workflow.activeVersionId === version.id && <span className="text-[8px] uppercase tracking-wide text-[#b7ff3c]/70">active</span>}
                          <span className="ml-auto text-[9px] text-white/22">{relativeTime(version.createdAt, now)}</span>
                          {mayManage && version.kind !== 'draft' && workflow.activeVersionId !== version.id && <Button size="icon-xs" variant="ghost" aria-label={`Restore version ${version.version}`} disabled={pending !== null} onClick={() => void workflowOperation(workflow.id, 'rollback', { versionId: version.id })}><RotateCcw /></Button>}
                        </div>
                      ))}
                    </div>
                    {workflow.variables.length > 0 && <div className="mt-4 border-t border-white/[0.06] pt-3">
                      <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-white/35">Variable metadata</p>
                      <div className="mt-2 flex flex-wrap gap-1.5">{workflow.variables.map((item) => <Badge key={item.id} variant="outline" className="border-white/10 text-[8px] text-white/38">{item.name} · {item.kind === 'secret' ? `${item.secretName ?? 'missing'} (write-only)` : item.value}</Badge>)}</div>
                    </div>}
                  </div>
                  <div className="rounded-xl border border-white/[0.06] p-4">
                    <div className="flex items-center gap-2"><Activity className="size-4 text-white/35" /><h4 className="text-[10px] font-semibold uppercase tracking-[0.12em] text-white/45">Execution history</h4></div>
                    {workflow.executions.length === 0 ? <p className="mt-5 text-center text-[10px] text-white/25">No executions recorded.</p> : <div className="mt-3 space-y-2">{workflow.executions.slice(0, 10).map((execution) => (
                      <div key={execution.id} className="rounded-lg border border-white/[0.045] bg-white/[0.012] px-3 py-2.5">
                        <div className="flex flex-wrap items-center gap-2">
                          {execution.state === 'succeeded' ? <CheckCircle2 className="size-3.5 text-[#b7ff3c]/70" /> : ['failed', 'timed_out'].includes(execution.state) ? <XCircle className="size-3.5 text-red-300/70" /> : <Clock3 className="size-3.5 text-white/35" />}
                          <Badge variant="outline" className={executionTone[execution.state]}>{label(execution.state)}</Badge>
                          <span className="font-mono text-[9px] text-white/32">attempt {execution.attempts}/{execution.maxAttempts}</span>
                          {execution.deadLetterAt && <Badge variant="outline" className="border-red-300/15 text-[8px] text-red-300">dead letter</Badge>}
                          <span className="ml-auto text-[9px] text-white/22">{relativeTime(execution.createdAt, now)}</span>
                        </div>
                        <p className="mt-2 break-all font-mono text-[8px] text-white/20">correlation {execution.correlationId}</p>
                        {execution.event?.sourceId && <p className="mt-1 break-all font-mono text-[8px] text-sky-300/35">source {execution.event.sourceId} · event {execution.event.externalEventType ?? 'external.event'} · id {execution.event.externalEventId ?? 'not retained'}{execution.event.subject ? ` · ${execution.event.subject}` : ''}</p>}
                        {execution.lastError && <p className="mt-2 text-[9px] leading-4 text-red-300/75">{execution.lastError}</p>}
                        <div className="mt-2 flex flex-wrap gap-1.5">
                          {execution.actions.map((item) => <Badge key={item.id} variant="outline" className="border-white/8 text-[8px] text-white/32">{label(item.actionType)} · {item.state}</Badge>)}
                          {canRetry && ['failed', 'timed_out', 'cancelled'].includes(execution.state) && <Button size="xs" variant="ghost" disabled={pending !== null} onClick={() => void request(`retry:${execution.id}`, `/api/workflows/executions/${execution.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ operation: 'retry' }) })}><RefreshCcw /> Retry</Button>}
                          {['queued', 'waiting', 'running'].includes(execution.state) && <Button size="xs" variant="ghost" disabled={pending !== null} onClick={() => void request(`cancel:${execution.id}`, `/api/workflows/executions/${execution.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ operation: 'cancel' }) })}><XCircle /> Cancel</Button>}
                        </div>
                      </div>
                    ))}</div>}
                  </div>
                </div>
              </div>
            </article>
          );
        })}
      </section>

      {canCreate && state.workflows.length > 0 && (
        <section className="cloud-card overflow-hidden">
          <div className="border-b border-white/[0.06] px-5 py-4"><div className="flex items-center gap-2"><Variable className="size-4 text-[#b7ff3c]/60" /><h2 className="text-sm font-semibold text-white/75">Variables and write-only secret references</h2></div><p className="mt-1 text-[10px] text-white/28">Variables are bounded metadata. Secret values stay encrypted in the existing Secrets store and never enter definitions, executions, or logs.</p></div>
          <div className="grid gap-3 p-5 md:grid-cols-2 xl:grid-cols-5">
            <NativeSelect value={variableWorkflow} onChange={(event) => setVariableWorkflow(event.target.value)} className="w-full text-xs" aria-label="Variable workflow">{state.workflows.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</NativeSelect>
            <Input value={variableName} onChange={(event) => setVariableName(event.target.value.toUpperCase())} aria-label="Variable name" className="text-xs" />
            <NativeSelect value={variableKind} onChange={(event) => setVariableKind(event.target.value as typeof variableKind)} className="w-full text-xs" aria-label="Variable type"><option value="text">text</option><option value="number">number</option><option value="boolean">boolean</option><option value="secret">secret reference</option></NativeSelect>
            {variableKind === 'secret' ? <NativeSelect value={variableSecret} onChange={(event) => setVariableSecret(event.target.value)} className="w-full text-xs" aria-label="Secret reference">{secrets.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.environment} · {item.scope}</option>)}</NativeSelect> : <Input value={variableValue} onChange={(event) => setVariableValue(event.target.value)} aria-label="Variable value" className="text-xs" />}
            <Button disabled={pending !== null || !variableWorkflow || (variableKind === 'secret' && !variableSecret)} onClick={() => void setVariable()}><ShieldCheck /> Save safely</Button>
          </div>
        </section>
      )}

      <section className="cloud-card overflow-hidden">
        <div className="border-b border-white/[0.06] px-5 py-4"><div className="flex items-center gap-2"><Bell className="size-4 text-[#b7ff3c]/60" /><h2 className="text-sm font-semibold text-white/75">Internal notifications</h2></div><p className="mt-1 text-[10px] text-white/28">D1 only. No email, push provider, domain, or external billing dependency.</p></div>
        {state.notifications.length === 0 ? <p className="px-5 py-10 text-center text-[10px] text-white/25">No internal notifications.</p> : <div className="divide-y divide-white/[0.05]">{state.notifications.map((item) => (
          <div key={item.id} className="flex items-start gap-3 px-5 py-4">
            <span className={item.readAt ? 'mt-1 size-2 rounded-full bg-white/12' : 'mt-1 size-2 rounded-full bg-[#b7ff3c]'} />
            <div className="min-w-0 flex-1"><p className="text-xs font-medium text-white/65">{item.title}</p><p className="mt-1 text-[10px] leading-4 text-white/30">{item.message}</p><p className="mt-1 text-[9px] text-white/20">{relativeTime(item.createdAt, now)}</p></div>
            {!item.readAt && <Button size="xs" variant="ghost" disabled={pending !== null} onClick={() => void request(`notification:${item.id}`, `/api/notifications/${item.id}`, { method: 'PATCH' })}>Mark read</Button>}
          </div>
        ))}</div>}
      </section>
    </div>
  );
}
