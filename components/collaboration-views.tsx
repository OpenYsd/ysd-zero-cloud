'use client';

import { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { Check, Copy, Info, KeyRound, Loader2, ShieldBan, Trash2, UserRoundCog } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NativeSelect } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState } from '@/components/ui-bits';
import { NavLink } from '@/components/nav-link';
import type {
  AuditEvent,
  Organization,
  OrganizationInvitation,
  OrganizationMember,
  Project,
  ServiceAccount,
} from '@/lib/domain';
import { relativeTime } from '@/lib/format';
import {
  canChangeRole,
  canSuspend,
  can,
  PROJECT_SERVICE_TOKEN_SCOPES,
  SERVICE_TOKEN_SCOPES,
  type Actor,
  type Role,
} from '@/lib/roles';
import type { DeviceSession } from '@/lib/server/devices';

async function jsonRequest<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  const body = (await response.json()) as T & { error?: string };
  if (!response.ok) throw new Error(body.error ?? 'The request could not be completed.');
  return body;
}

function ErrorLine({ value }: { value: string | null }) {
  return value ? <p role="alert" className="rounded-lg border border-red-400/20 bg-red-400/[0.05] px-3 py-2 text-[11px] text-red-300">{value}</p> : null;
}

export function MembersView({
  organization,
  workspaceId,
  actor,
  initialMembers,
  projects,
  now,
}: {
  organization: Organization;
  workspaceId: string;
  actor: Actor;
  initialMembers: OrganizationMember[];
  projects: Project[];
  now: number;
}) {
  const [members, setMembers] = useState(initialMembers);
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ownerCount = members.filter((member) => member.role === 'owner' && member.status === 'active').length;
  const canManageMembers = can(actor, 'member.manage');

  async function mutate(userId: string, body: Record<string, unknown>) {
    setPending(userId);
    setError(null);
    try {
      await jsonRequest('/api/members', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, workspaceId, ...body }),
      });
      const refreshed = await jsonRequest<{ members: OrganizationMember[] }>('/api/members');
      setMembers(refreshed.members);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The member could not be changed.');
    } finally {
      setPending(null);
    }
  }

  function transfer(member: OrganizationMember) {
    const confirmation = window.prompt(`Type "${organization.name}" to transfer ownership to ${member.email}.`);
    if (confirmation !== null) void mutate(member.userId, { action: 'transfer-ownership', confirmation });
  }

  return (
    <div className="space-y-4">
      <ErrorLine value={error} />
      <section className="cloud-card overflow-hidden">
        <Table className="text-[11px]">
          <TableHeader><TableRow className="border-white/[0.06] hover:bg-transparent">
            {['Member', 'Role', 'Project access', 'Sessions', 'Status', 'Actions'].map((item) => <TableHead key={item} className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25">{item}</TableHead>)}
          </TableRow></TableHeader>
          <TableBody>
            {members.map((member) => {
              const target = { userId: member.userId, role: member.role };
              const roleDecision = canChangeRole(actor, target, 'viewer', ownerCount);
              const statusDecision = canSuspend(actor, target);
              const busy = pending === member.userId;
              return <TableRow key={member.id} className="border-white/[0.05]">
                <TableCell className="px-4 py-3"><span className="font-medium text-white/72">{member.name || member.email}</span><span className="mt-1 block font-mono text-[10px] text-white/30">{member.email}</span></TableCell>
                <TableCell className="px-4 py-3">{roleDecision.allowed ? <NativeSelect value={member.role} disabled={busy} onChange={(event) => void mutate(member.userId, { role: event.target.value })} className="h-7 border-white/[0.08] bg-black/20 text-[10px]">
                  {(['admin', 'developer', 'viewer'] as Role[]).map((role) => <option key={role} value={role}>{role}</option>)}
                </NativeSelect> : <Badge variant="outline" className="border-white/[0.1] text-white/55">{member.role}</Badge>}</TableCell>
                <TableCell className="px-4 py-3">{member.role === 'owner' || member.role === 'admin' ? <span className="text-white/28">all projects</span> : !canManageMembers ? <span className="text-white/28">{member.projectIds === null ? 'all projects' : `${member.projectIds.length} project${member.projectIds.length === 1 ? '' : 's'}`}</span> : <NativeSelect disabled={busy} value={member.projectIds === null ? 'all' : member.projectIds[0] ?? 'none'} onChange={(event) => {
                  const value = event.target.value;
                  void mutate(member.userId, value === 'all' ? { projectScope: 'all' } : { projectIds: value === 'none' ? [] : [value] });
                }} className="h-7 border-white/[0.08] bg-black/20 text-[10px]">
                  <option value="all">All projects</option><option value="none">No projects</option>
                  {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
                </NativeSelect>}</TableCell>
                <TableCell className="px-4 py-3 font-mono text-white/42">{member.activeSessions}</TableCell>
                <TableCell className="px-4 py-3"><Badge variant="outline" className={member.suspendedAt ? 'border-red-400/20 text-red-300' : 'border-[#b7ff3c]/15 text-[#c8ff69]'}>{member.suspendedAt ? 'suspended' : member.status}</Badge><span className="mt-1 block text-[9px] text-white/25">{member.lastActiveAt ? relativeTime(member.lastActiveAt, now) : 'never active'}</span></TableCell>
                <TableCell className="px-4 py-3"><div className="flex flex-wrap gap-1">
                  {statusDecision.allowed && <Button variant="outline" size="sm" disabled={busy} onClick={() => void mutate(member.userId, { action: member.suspendedAt ? 'reactivate' : 'suspend' })} className="border-white/[0.08] text-[9px]">{busy ? <Loader2 className="animate-spin" /> : <ShieldBan />}{member.suspendedAt ? 'Restore' : 'Suspend'}</Button>}
                  {statusDecision.allowed && <Button variant="ghost" size="sm" disabled={busy} onClick={() => void mutate(member.userId, { action: 'remove' })} className="text-[9px] text-red-300"><Trash2 />Remove</Button>}
                  {actor.role === 'owner' && member.userId !== actor.userId && member.status === 'active' && <Button variant="ghost" size="sm" disabled={busy} onClick={() => transfer(member)} className="text-[9px]"><UserRoundCog />Transfer</Button>}
                </div></TableCell>
              </TableRow>;
            })}
          </TableBody>
        </Table>
      </section>
    </div>
  );
}

export function InvitationsView({ initialInvitations }: { initialInvitations: OrganizationInvitation[] }) {
  const [invitations, setInvitations] = useState(initialInvitations);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<Exclude<Role, 'owner'>>('developer');
  const [link, setLink] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    const body = await jsonRequest<{ invitations: OrganizationInvitation[] }>('/api/invitations');
    setInvitations(body.invitations);
  }
  async function create() {
    setPending(true); setError(null); setLink(null);
    try {
      const body = await jsonRequest<{ inviteLink: string }>('/api/invitations', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, role }),
      });
      setLink(body.inviteLink); setEmail(''); await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Invitation failed.'); }
    finally { setPending(false); }
  }
  async function revoke(id: string) {
    setPending(true); setError(null);
    try { await jsonRequest(`/api/invitations/${id}`, { method: 'DELETE' }); await refresh(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Invitation could not be revoked.'); }
    finally { setPending(false); }
  }

  return <div className="space-y-4">
    <ErrorLine value={error} />
    <section className="cloud-card p-5"><div className="grid gap-3 sm:grid-cols-[1fr_160px_auto]">
      <Input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="teammate@example.com" aria-label="Invite email" />
      <NativeSelect value={role} onChange={(event) => setRole(event.target.value as Exclude<Role, 'owner'>)}><option value="admin">Admin</option><option value="developer">Developer</option><option value="viewer">Viewer</option></NativeSelect>
      <Button onClick={() => void create()} disabled={pending || !email.trim()}>{pending ? <Loader2 className="animate-spin" /> : null}Create link</Button>
    </div>{link && <div className="mt-4 rounded-lg border border-[#b7ff3c]/15 bg-[#b7ff3c]/[0.04] p-3"><p className="text-[10px] text-[#c8ff69]">Copy now — the plaintext token is not stored.</p><div className="mt-2 flex gap-2"><Input readOnly value={link} className="font-mono text-[10px]" /><Button variant="outline" onClick={() => void navigator.clipboard.writeText(link)}><Copy />Copy</Button></div></div>}</section>
    {invitations.length === 0 ? <EmptyState title="No invitations" copy="Create a single-use link for a teammate." /> : <section className="cloud-card overflow-hidden"><Table className="text-[11px]"><TableHeader><TableRow className="border-white/[0.06]"><TableHead>Email</TableHead><TableHead>Role</TableHead><TableHead>Workspace</TableHead><TableHead>Status</TableHead><TableHead /></TableRow></TableHeader><TableBody>{invitations.map((invite) => <TableRow key={invite.id} className="border-white/[0.05]"><TableCell>{invite.email}</TableCell><TableCell>{invite.role}</TableCell><TableCell>{invite.workspaceName}</TableCell><TableCell><Badge variant="outline">{invite.status}</Badge></TableCell><TableCell className="text-right">{invite.status === 'pending' && <Button variant="ghost" size="sm" disabled={pending} onClick={() => void revoke(invite.id)}><Trash2 />Revoke</Button>}</TableCell></TableRow>)}</TableBody></Table></section>}
  </div>;
}

export function ServiceAccountsView({ initialAccounts, projects }: { initialAccounts: ServiceAccount[]; projects: Project[] }) {
  const [accounts, setAccounts] = useState(initialAccounts);
  const [name, setName] = useState('');
  const [projectId, setProjectId] = useState('');
  const [scopes, setScopes] = useState<string[]>(['project.read', 'deployment.read']);
  const [expiresInDays, setExpiresInDays] = useState(30);
  const [token, setToken] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const availableScopes = projectId ? PROJECT_SERVICE_TOKEN_SCOPES : SERVICE_TOKEN_SCOPES;
  async function refresh() { setAccounts((await jsonRequest<{ accounts: ServiceAccount[] }>('/api/service-accounts')).accounts); }
  async function create() {
    setPending(true); setError(null); setToken(null);
    try {
      const body = await jsonRequest<{ token: string }>('/api/service-accounts', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, projectId: projectId || null, scopes, expiresAt: Date.now() + expiresInDays * 24 * 60 * 60 * 1000 }) });
      setToken(body.token); setName(''); await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Token could not be created.'); }
    finally { setPending(false); }
  }
  async function revoke(id: string) { setPending(true); setError(null); try { await jsonRequest(`/api/service-accounts/${id}`, { method: 'DELETE' }); await refresh(); } catch (cause) { setError(cause instanceof Error ? cause.message : 'Token could not be revoked.'); } finally { setPending(false); } }
  return <div className="space-y-4"><ErrorLine value={error} /><section className="cloud-card space-y-4 p-5"><div className="grid gap-3 sm:grid-cols-3"><Input value={name} onChange={(event) => setName(event.target.value)} placeholder="CI deployer" /><NativeSelect value={projectId} onChange={(event) => {
    const nextProjectId = event.target.value;
    setProjectId(nextProjectId);
    if (nextProjectId) {
      const allowed = new Set<string>(PROJECT_SERVICE_TOKEN_SCOPES);
      setScopes((current) => current.filter((scope) => allowed.has(scope)));
    }
  }}><option value="">Whole workspace</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</NativeSelect><NativeSelect value={String(expiresInDays)} onChange={(event) => setExpiresInDays(Number(event.target.value))} aria-label="Token lifetime"><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option><option value="180">180 days</option></NativeSelect></div><div className="flex flex-wrap gap-2">{availableScopes.map((scope) => <label key={scope} className="flex items-center gap-1.5 rounded-md border border-white/[0.07] px-2 py-1 text-[10px] text-white/48"><input type="checkbox" checked={scopes.includes(scope)} onChange={(event) => setScopes((current) => event.target.checked ? [...current, scope] : current.filter((item) => item !== scope))} />{scope}</label>)}</div><Button disabled={pending || !name.trim() || scopes.length === 0} onClick={() => void create()}>{pending ? <Loader2 className="animate-spin" /> : <KeyRound />}Create token</Button>{token && <div className="rounded-lg border border-amber-400/20 bg-amber-400/[0.04] p-3"><p className="text-[10px] text-amber-300">Shown once. Store it now.</p><div className="mt-2 flex gap-2"><Input readOnly value={token} className="font-mono text-[10px]" /><Button variant="outline" onClick={() => void navigator.clipboard.writeText(token)}><Copy />Copy</Button></div></div>}</section>{accounts.length === 0 ? <EmptyState title="No service accounts" copy="Create a scoped token for automation." /> : <section className="cloud-card overflow-hidden"><Table className="text-[11px]"><TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Project</TableHead><TableHead>Scopes</TableHead><TableHead>Expires</TableHead><TableHead>Status</TableHead><TableHead /></TableRow></TableHeader><TableBody>{accounts.map((account) => <TableRow key={account.id}><TableCell>{account.name}</TableCell><TableCell>{account.projectName ?? 'workspace'}</TableCell><TableCell className="max-w-[360px] text-[10px] text-white/40">{account.scopes.join(', ')}</TableCell><TableCell>{account.expiresAt ? new Date(account.expiresAt).toLocaleDateString() : 'unbounded'}</TableCell><TableCell><Badge variant="outline">{account.status}</Badge></TableCell><TableCell className="text-right">{account.status === 'active' && <Button variant="ghost" size="sm" disabled={pending} onClick={() => void revoke(account.id)}><Trash2 />Revoke</Button>}</TableCell></TableRow>)}</TableBody></Table></section>}</div>;
}

/**
 * Fixed, not generated.
 *
 * The header points at the explanation with `aria-describedby`, so both ends
 * must agree between the server render and the client hydration. A `useId`
 * value would not, which is the defect this release already had to fix once.
 */
const AUDIT_POSITION_HELP_ID = 'audit-position-help';

export function AuditView({ events, now }: { events: AuditEvent[]; now: number }) {
  if (events.length === 0) return <EmptyState title="No audit events" copy="Security and organization changes will appear here." />;
  return (
    <section className="cloud-card overflow-hidden">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-white/[0.06] p-3">
        {/*
          Stated in the page rather than hidden behind a hover tooltip. The
          column is a bare integer, and a number nobody can interpret is not
          evidence: hover never fires on touch, and a tooltip is invisible to
          someone scanning the table or reading it with a screen reader. The
          same element is the accessible description for the column header.
        */}
        <p
          id={AUDIT_POSITION_HELP_ID}
          className="flex max-w-xl items-start gap-2 text-[10px] leading-4 text-white/40"
        >
          <Info aria-hidden="true" className="mt-0.5 size-3.5 shrink-0 text-white/30" />
          <span>
            <span className="text-white/60">Position</span> is each record&apos;s permanent
            place in this organization&apos;s audit trail. Positions are assigned in order and
            should run unbroken — a missing position means a record is no longer present and
            should be investigated.
          </span>
        </p>
        <div className="flex shrink-0 gap-2">
          <NavLink href="/api/audit?format=csv" className="rounded-md border border-white/[0.08] px-3 py-1.5 text-[10px] text-white/55">Export CSV</NavLink>
          <NavLink href="/api/audit?format=json" className="rounded-md border border-white/[0.08] px-3 py-1.5 text-[10px] text-white/55">Export JSON</NavLink>
        </div>
      </div>
      <Table className="text-[11px]">
        <TableHeader>
          <TableRow>
            <TableHead scope="col" aria-describedby={AUDIT_POSITION_HELP_ID}>Position</TableHead>
            <TableHead scope="col">When</TableHead>
            <TableHead scope="col">Actor</TableHead>
            <TableHead scope="col">Action</TableHead>
            <TableHead scope="col">Resource</TableHead>
            <TableHead scope="col">Outcome</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {events.map((event) => (
            <TableRow key={event.id}>
              <TableCell className="font-mono text-[10px] text-white/40">{event.sequence ?? '—'}</TableCell>
              <TableCell>{relativeTime(event.createdAt, now)}</TableCell>
              <TableCell className="font-mono text-[10px]">{event.actorId}</TableCell>
              <TableCell>{event.action}</TableCell>
              <TableCell>{event.resourceType}{event.resourceId ? ` · ${event.resourceId}` : ''}</TableCell>
              <TableCell><Badge variant="outline">{event.outcome}</Badge></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </section>
  );
}

export function SessionsView({ initialSessions }: { initialSessions: DeviceSession[] }) {
  const [sessions, setSessions] = useState(initialSessions);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function revoke(id?: string) { setPending(true); setError(null); try { await jsonRequest(`/api/sessions?${id ? `id=${encodeURIComponent(id)}` : 'all=true'}`, { method: 'DELETE' }); if (!id) window.location.assign('/sign-in'); else setSessions((current) => current.filter((session) => session.id !== id)); } catch (cause) { setError(cause instanceof Error ? cause.message : 'Session could not be revoked.'); } finally { setPending(false); } }
  return <div className="space-y-4"><ErrorLine value={error} /><div className="flex justify-end"><Button variant="outline" disabled={pending || sessions.length === 0} onClick={() => void revoke()}><ShieldBan />Revoke all sessions</Button></div>{sessions.length === 0 ? <EmptyState title="No active sessions" copy="No signed-in devices were found." /> : <section className="cloud-card overflow-hidden"><Table className="text-[11px]"><TableHeader><TableRow><TableHead>Device</TableHead><TableHead>IP</TableHead><TableHead>Last used</TableHead><TableHead>Expires</TableHead><TableHead /></TableRow></TableHeader><TableBody>{sessions.map((session) => <TableRow key={session.id}><TableCell className="max-w-[420px] truncate">{session.userAgent ?? 'Unknown device'}</TableCell><TableCell className="font-mono">{session.ipAddress ?? 'unknown'}</TableCell><TableCell>{session.updatedAt}</TableCell><TableCell>{session.expiresAt}</TableCell><TableCell className="text-right"><Button variant="ghost" size="sm" disabled={pending} onClick={() => void revoke(session.id)}><Trash2 />Revoke</Button></TableCell></TableRow>)}</TableBody></Table></section>}</div>;
}

export function InvitationAcceptance() {
  const params = useSearchParams();
  const token = params.get('token') ?? '';
  const [state, setState] = useState<'idle' | 'pending' | 'done'>('idle');
  const [error, setError] = useState<string | null>(null);
  async function accept() { setState('pending'); setError(null); try { const result = await jsonRequest<{ organizationId: string; workspaceId: string }>('/api/invitations/accept', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) }); await jsonRequest('/api/context', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(result) }); setState('done'); window.location.assign('/'); } catch (cause) { setError(cause instanceof Error ? cause.message : 'Invitation could not be accepted.'); setState('idle'); } }
  return <div className="w-full max-w-md rounded-2xl border border-white/[0.08] bg-white/[0.025] p-6"><span className="mx-auto grid size-10 place-items-center rounded-full bg-[#b7ff3c]/10 text-[#c8ff69]">{state === 'done' ? <Check /> : <UserRoundCog />}</span><h1 className="mt-4 text-center text-xl font-semibold">Join the organization</h1><p className="mt-2 text-center text-[11px] leading-5 text-white/38">The link is single-use and must match the email address on your signed-in account.</p><ErrorLine value={error} /><Button className="mt-5 w-full" disabled={!token || state === 'pending'} onClick={() => void accept()}>{state === 'pending' ? <Loader2 className="animate-spin" /> : null}Accept invitation</Button></div>;
}
