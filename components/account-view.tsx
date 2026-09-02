'use client';

import { useState } from 'react';
import {
  BadgeCheck,
  Info,
  KeyRound,
  Loader2,
  MonitorSmartphone,
  ShieldAlert,
} from 'lucide-react';
import type { AccountProfile } from '@/lib/domain';
import { ACCOUNT_LIMITS } from '@/lib/account';
import { relativeTime } from '@/lib/format';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-2">
      <dt className="text-[11px] uppercase tracking-[0.12em] text-white/35">{label}</dt>
      <dd className="min-w-0 truncate text-right text-xs text-white/75">{children}</dd>
    </div>
  );
}

function Notice({
  tone,
  children,
}: {
  tone: 'error' | 'success' | 'info';
  children: React.ReactNode;
}) {
  const color =
    tone === 'error'
      ? 'text-red-300/85'
      : tone === 'success'
        ? 'text-[#c8ff69]'
        : 'text-white/50';
  return (
    <p role={tone === 'error' ? 'alert' : 'status'} className={`text-[11px] ${color}`}>
      {children}
    </p>
  );
}

export function AccountView({
  initialAccount,
  now,
}: {
  initialAccount: AccountProfile;
  now: number;
}) {
  const [account, setAccount] = useState(initialAccount);

  const [name, setName] = useState(initialAccount.name);
  const [namePending, setNamePending] = useState(false);
  const [nameError, setNameError] = useState<string | null>(null);
  const [nameSaved, setNameSaved] = useState(false);

  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [passwordPending, setPasswordPending] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordDone, setPasswordDone] = useState<string | null>(null);

  async function saveName(event: React.SyntheticEvent) {
    event.preventDefault();
    setNamePending(true);
    setNameError(null);
    setNameSaved(false);
    try {
      const response = await fetch('/api/account', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ displayName: name }),
      });
      const payload = (await response.json()) as {
        account?: AccountProfile;
        error?: string;
      };
      if (!response.ok || !payload.account) {
        throw new Error(payload.error ?? 'Your display name could not be saved.');
      }
      setAccount(payload.account);
      setName(payload.account.name);
      setNameSaved(true);
    } catch (cause) {
      setNameError(
        cause instanceof Error ? cause.message : 'Your display name could not be saved.',
      );
    } finally {
      setNamePending(false);
    }
  }

  async function changePassword(event: React.SyntheticEvent) {
    event.preventDefault();
    setPasswordPending(true);
    setPasswordError(null);
    setPasswordDone(null);
    try {
      const response = await fetch('/api/account/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          currentPassword: current,
          newPassword: next,
          confirmPassword: confirm,
        }),
      });
      const payload = (await response.json()) as {
        changed?: boolean;
        revokedOtherSessions?: boolean;
        error?: string;
      };
      if (!response.ok || !payload.changed) {
        throw new Error(payload.error ?? 'Your password could not be changed.');
      }
      // Cleared immediately: nothing keeps a credential in component state
      // longer than the request that needed it.
      setCurrent('');
      setNext('');
      setConfirm('');
      setPasswordDone(
        payload.revokedOtherSessions
          ? 'Password changed. Every other signed-in browser has been signed out; this one is still active.'
          : 'Password changed.',
      );
    } catch (cause) {
      setPasswordError(
        cause instanceof Error ? cause.message : 'Your password could not be changed.',
      );
    } finally {
      setPasswordPending(false);
    }
  }

  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <section className="cloud-card space-y-4 p-5" aria-label="Profile">
        <header className="flex items-center gap-3">
          <span className="grid size-10 place-items-center rounded-lg bg-[#7569ff] text-sm font-bold text-white">
            {account.initials}
          </span>
          <div className="min-w-0">
            <h2 className="truncate text-sm font-medium text-white">
              {account.displayName}
            </h2>
            <p className="truncate text-[11px] text-white/40">{account.email}</p>
          </div>
        </header>

        <dl className="divide-y divide-white/[0.06] border-t border-white/[0.06]">
          <Row label="Role">
            <Badge variant="outline">{account.role}</Badge>
          </Row>
          <Row label="Organization">{account.organizationName}</Row>
          <Row label="Workspace">{account.workspaceName}</Row>
          <Row label="Status">
            {account.suspended ? (
              <Badge variant="destructive">suspended</Badge>
            ) : (
              <Badge variant="outline">active</Badge>
            )}
          </Row>
          <Row label="Joined">
            {account.createdAt ? relativeTime(account.createdAt, now) : 'Unknown'}
          </Row>
        </dl>

        <form onSubmit={saveName} className="space-y-2 border-t border-white/[0.06] pt-4">
          <Label htmlFor="displayName" className="text-[11px] text-white/55">
            Display name
          </Label>
          <div className="flex gap-2">
            <Input
              id="displayName"
              value={name}
              maxLength={ACCOUNT_LIMITS.displayNameMaximum}
              disabled={namePending || account.suspended}
              onChange={(event) => {
                setName(event.target.value);
                setNameSaved(false);
              }}
              className="h-9 text-xs"
            />
            <Button
              type="submit"
              size="sm"
              disabled={namePending || account.suspended || name.trim() === account.name}
            >
              {namePending ? <Loader2 className="mr-1.5 size-3.5 animate-spin" /> : null}
              Save
            </Button>
          </div>
          <p className="text-[11px] text-white/30">
            Shown across the workspace instead of your email address.
            {' '}
            {ACCOUNT_LIMITS.displayNameMinimum}–{ACCOUNT_LIMITS.displayNameMaximum} characters.
          </p>
          {nameError ? <Notice tone="error">{nameError}</Notice> : null}
          {nameSaved ? <Notice tone="success">Display name updated.</Notice> : null}
        </form>
      </section>

      <div className="space-y-5">
        <section className="cloud-card space-y-4 p-5" aria-label="Sign-in address">
          <header className="flex items-center gap-2">
            <BadgeCheck className="size-4 text-white/45" />
            <h2 className="text-sm font-medium text-white">Sign-in address</h2>
            <Badge variant={account.emailVerified ? 'secondary' : 'outline'}>
              {account.emailVerified ? 'verified' : 'unverified'}
            </Badge>
          </header>
          <p className="break-all text-xs text-white/70">{account.email}</p>
          {!account.emailChange.available ? (
            <p className="flex items-start gap-2 rounded-md border border-white/[0.07] bg-white/[0.02] p-3 text-[11px] leading-5 text-white/45">
              <Info className="mt-0.5 size-3.5 shrink-0" />
              {account.emailChange.reason}
            </p>
          ) : null}
        </section>

        <section className="cloud-card space-y-4 p-5" aria-label="Password">
          <header className="flex items-center gap-2">
            <KeyRound className="size-4 text-white/45" />
            <h2 className="text-sm font-medium text-white">Password</h2>
          </header>
          <p className="text-[11px] text-white/40">
            Last changed{' '}
            {account.passwordChangedAt
              ? relativeTime(account.passwordChangedAt, now)
              : 'not since this was recorded'}
            .
          </p>

          <form onSubmit={changePassword} className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="currentPassword" className="text-[11px] text-white/55">
                Current password
              </Label>
              <Input
                id="currentPassword"
                type="password"
                autoComplete="current-password"
                value={current}
                disabled={passwordPending || account.suspended}
                onChange={(event) => setCurrent(event.target.value)}
                className="h-9 text-xs"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="newPassword" className="text-[11px] text-white/55">
                New password
              </Label>
              <Input
                id="newPassword"
                type="password"
                autoComplete="new-password"
                value={next}
                disabled={passwordPending || account.suspended}
                onChange={(event) => setNext(event.target.value)}
                className="h-9 text-xs"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="confirmPassword" className="text-[11px] text-white/55">
                Confirm new password
              </Label>
              <Input
                id="confirmPassword"
                type="password"
                autoComplete="new-password"
                value={confirm}
                disabled={passwordPending || account.suspended}
                onChange={(event) => setConfirm(event.target.value)}
                className="h-9 text-xs"
              />
            </div>
            <p className="text-[11px] text-white/30">
              At least {ACCOUNT_LIMITS.passwordMinimum} characters. Changing it signs
              out your other browsers and keeps this one.
            </p>
            {passwordError ? <Notice tone="error">{passwordError}</Notice> : null}
            {passwordDone ? <Notice tone="success">{passwordDone}</Notice> : null}
            <Button
              type="submit"
              size="sm"
              disabled={passwordPending || account.suspended || !current || !next || !confirm}
            >
              {passwordPending ? <Loader2 className="mr-1.5 size-3.5 animate-spin" /> : null}
              Change password
            </Button>
          </form>
        </section>

        <section className="cloud-card space-y-3 p-5" aria-label="Active sessions">
          <header className="flex items-center gap-2">
            <MonitorSmartphone className="size-4 text-white/45" />
            <h2 className="text-sm font-medium text-white">Active sessions</h2>
            <Badge variant="outline">{account.sessions.length}</Badge>
          </header>
          {account.sessions.length === 0 ? (
            <p className="text-[11px] text-white/35">No active sessions were found.</p>
          ) : (
            <ul className="divide-y divide-white/[0.06] border-t border-white/[0.06]">
              {account.sessions.slice(0, 8).map((item) => (
                <li key={item.id} className="space-y-0.5 py-2.5">
                  <p className="truncate text-[11px] text-white/70">
                    {item.userAgent ?? 'Unknown device'}
                  </p>
                  <p className="font-mono text-[10px] text-white/30">
                    {item.ipAddress ?? 'unknown address'} · expires {item.expiresAt}
                  </p>
                </li>
              ))}
            </ul>
          )}
          <p className="flex items-start gap-2 text-[11px] text-white/30">
            <ShieldAlert className="mt-0.5 size-3.5 shrink-0" />
            Session tokens are never shown here. Use the sign-out control in the header
            to end this session, or change your password to end every other one.
          </p>
        </section>
      </div>
    </div>
  );
}
