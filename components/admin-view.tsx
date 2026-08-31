'use client';

import { useState } from 'react';
import { CheckCircle2, Loader2, ShieldAlert, ShieldCheck, UserCog, UserX } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { NativeSelect } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState } from '@/components/ui-bits';
import { relativeTime } from '@/lib/format';
import { canChangeRole, canSuspend, ROLES, type Actor, type Role } from '@/lib/roles';

export type AdminUser = {
  id: string;
  email: string;
  name: string;
  emailVerified: boolean;
  role: Role;
  suspendedAt: number | null;
  suspendedReason: string | null;
  lastSignInAt: number | null;
  activeSessions: number;
};

const ROLE_TONE: Record<Role, string> = {
  owner: 'border-[#b7ff3c]/20 bg-[#b7ff3c]/[0.06] text-[#c8ff69]',
  admin: 'border-[#7569ff]/25 bg-[#7569ff]/[0.06] text-[#b0aaff]',
  developer: 'border-white/[0.09] text-white/55',
  viewer: 'border-white/[0.06] text-white/35',
};

/**
 * Account administration.
 *
 * The same rules the server enforces are used here to decide which controls
 * are even offered, so an admin is not shown an action that will be refused.
 * The server still re-checks every one of them — this is affordance, not
 * authorisation.
 */
export function AdminView({
  users,
  actor,
  ownerCount,
  now,
}: {
  users: AdminUser[];
  actor: Actor;
  ownerCount: number;
  now: number;
}) {
  const [rows, setRows] = useState(users);
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function mutate(userId: string, body: Record<string, unknown>) {
    setPending(userId);
    setError(null);
    try {
      const response = await fetch('/api/admin/users', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, ...body }),
      });
      const payload = (await response.json()) as { user?: AdminUser; error?: string };
      if (!response.ok || !payload.user) {
        throw new Error(payload.error ?? 'The change could not be applied.');
      }
      const updated = payload.user;
      setRows((current) => current.map((row) => (row.id === userId ? updated : row)));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The change could not be applied.');
    } finally {
      setPending(null);
    }
  }

  if (rows.length === 0) {
    return <EmptyState title="No accounts" copy="Nobody has registered on this instance yet." />;
  }

  return (
    <>
      <div className="flex items-start gap-2.5 rounded-xl border border-[#7569ff]/12 bg-[#7569ff]/[0.035] p-4 text-[11px] leading-5 text-white/42">
        <ShieldCheck className="mt-px size-3.5 shrink-0 text-[#b0aaff]" />
        <span>
          Roles govern the instance, not workspaces. An admin manages accounts here; they still
          cannot read another operator&apos;s projects, secrets, or logs — those stay scoped to
          whoever owns them.
        </span>
      </div>

      {error && (
        <p role="alert" className="rounded-lg border border-red-400/20 bg-red-400/[0.06] px-3 py-2 text-[11px] text-red-300">
          {error}
        </p>
      )}

      <section className="cloud-card overflow-hidden">
        <Table className="text-[11px]">
          <TableHeader>
            <TableRow className="border-white/[0.06] hover:bg-transparent">
              {['Account', 'Role', 'Email', 'Sessions', 'Last sign-in', 'Status', ''].map((column, index) => (
                <TableHead key={column || `a-${index}`} className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25">
                  {column}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => {
              const target = { userId: row.id, role: row.role };
              const roleChange = canChangeRole(actor, target, 'viewer', ownerCount);
              const suspendDecision = canSuspend(actor, target);
              const busy = pending === row.id;
              const suspended = row.suspendedAt !== null;

              return (
                <TableRow key={row.id} className="border-white/[0.05] hover:bg-white/[0.02]">
                  <TableCell className="px-4 py-3">
                    <span className="flex items-center gap-2 font-medium text-white/72">
                      <UserCog className="size-3.5 text-[#b7ff3c]/65" />
                      {row.name || row.email}
                    </span>
                    <span className="mt-1 block font-mono text-[10px] text-white/30">{row.email}</span>
                  </TableCell>

                  <TableCell className="px-4 py-3">
                    {roleChange.allowed ? (
                      <NativeSelect
                        value={row.role}
                        disabled={busy}
                        aria-label={`Role for ${row.email}`}
                        onChange={(event) => void mutate(row.id, { role: event.target.value })}
                        className="h-7 border-white/[0.08] bg-black/15 text-[10px]"
                      >
                        {ROLES.filter((role) => role !== 'owner' || actor.role === 'owner').map((role) => (
                          <option key={role} value={role}>{role}</option>
                        ))}
                      </NativeSelect>
                    ) : (
                      <Badge variant="outline" className={ROLE_TONE[row.role]}>{row.role}</Badge>
                    )}
                  </TableCell>

                  <TableCell className="px-4 py-3">
                    {row.emailVerified ? (
                      <span className="flex items-center gap-1 text-[#c8ff69]">
                        <CheckCircle2 className="size-3" /> verified
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-amber-300/80">
                        <ShieldAlert className="size-3" /> unverified
                      </span>
                    )}
                  </TableCell>

                  <TableCell className="px-4 py-3 font-mono text-white/42">{row.activeSessions}</TableCell>

                  <TableCell className="px-4 py-3 text-white/42">
                    {row.lastSignInAt ? relativeTime(row.lastSignInAt, now) : 'never'}
                  </TableCell>

                  <TableCell className="px-4 py-3">
                    {suspended ? (
                      <Badge variant="outline" className="border-red-400/25 bg-red-400/[0.06] text-red-300">
                        suspended
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="border-[#b7ff3c]/12 text-[#c8ff69]">active</Badge>
                    )}
                  </TableCell>

                  <TableCell className="px-4 py-3 text-right">
                    {suspendDecision.allowed ? (
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={busy}
                        onClick={() => void mutate(row.id, { suspended: !suspended })}
                        className="border-white/[0.08] text-[10px]"
                      >
                        {busy ? <Loader2 className="animate-spin" /> : <UserX />}
                        {suspended ? 'Restore' : 'Suspend'}
                      </Button>
                    ) : (
                      <span className="text-[10px] text-white/22">{suspendDecision.message}</span>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </section>
    </>
  );
}
