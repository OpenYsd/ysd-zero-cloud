'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { KeyRound, Loader2, LockKeyhole, Plus, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { NativeSelect } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState } from '@/components/ui-bits';
import { relativeTime } from '@/lib/format';
import { SECRET_ENVIRONMENTS, type Secret } from '@/lib/domain';

/**
 * Secrets are write-only.
 *
 * There is no reveal control anywhere in this view because the server has no
 * endpoint that would answer one. What an operator can do is replace a value
 * or delete it.
 */
export function SecretsView({ secrets, now }: { secrets: Secret[]; now: number }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  const [environment, setEnvironment] = useState<string>('Production');
  const [rotationDays, setRotationDays] = useState('90');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);

  async function save(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const parsed = Number(rotationDays);
      const response = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          value,
          environment,
          rotationDays: Number.isFinite(parsed) && parsed > 0 ? parsed : null,
        }),
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(body.error ?? 'The secret could not be stored.');
      setName('');
      setValue('');
      setOpen(false);
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The secret could not be stored.');
    } finally {
      setPending(false);
    }
  }

  async function remove(id: string) {
    setRemoving(id);
    try {
      await fetch(`/api/secrets/${id}`, { method: 'DELETE' });
      router.refresh();
    } finally {
      setRemoving(null);
    }
  }

  return (
    <>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-2.5 rounded-xl border border-[#4ac7ff]/12 bg-[#4ac7ff]/[0.035] p-4 text-[11px] leading-5 text-white/42">
          <LockKeyhole className="mt-px size-3.5 shrink-0 text-[#79d6ff]" />
          <span>
            Values are sealed with AES-GCM before they reach the database and there is no endpoint that
            unseals them. Replace a value to rotate it.
          </span>
        </div>
        <Button
          onClick={() => setOpen((state) => !state)}
          className="h-9 shrink-0 bg-[#b7ff3c] px-3.5 text-xs font-semibold text-[#07100c] hover:bg-[#cbff72]"
        >
          <Plus /> Add secret
        </Button>
      </div>

      {open && (
        <form onSubmit={save} className="cloud-card grid gap-4 p-5 lg:grid-cols-[1fr_1.4fr_150px_130px_auto] lg:items-end">
          <div className="space-y-1.5">
            <Label htmlFor="secret-name" className="text-[11px] text-white/45">Name</Label>
            <Input
              id="secret-name"
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="DATABASE_URL"
              className="h-9 border-white/[0.08] bg-black/15 font-mono text-xs"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="secret-value" className="text-[11px] text-white/45">Value</Label>
            <Input
              id="secret-value"
              type="password"
              required
              value={value}
              onChange={(event) => setValue(event.target.value)}
              autoComplete="off"
              placeholder="Stored encrypted, never shown again"
              className="h-9 border-white/[0.08] bg-black/15 text-xs"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="secret-environment" className="text-[11px] text-white/45">Environment</Label>
            <NativeSelect
              id="secret-environment"
              value={environment}
              onChange={(event) => setEnvironment(event.target.value)}
              className="h-9 border-white/[0.08] bg-black/15 text-xs"
            >
              {SECRET_ENVIRONMENTS.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </NativeSelect>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="secret-rotation" className="text-[11px] text-white/45">Rotate (days)</Label>
            <Input
              id="secret-rotation"
              type="number"
              min={1}
              max={3650}
              value={rotationDays}
              onChange={(event) => setRotationDays(event.target.value)}
              className="h-9 border-white/[0.08] bg-black/15 text-xs"
            />
          </div>
          <Button type="submit" disabled={pending} className="h-9 bg-[#7569ff] text-xs text-white hover:bg-[#887eff]">
            {pending ? <Loader2 className="animate-spin" /> : <LockKeyhole />} Seal
          </Button>
          {error && (
            <p role="alert" className="text-[11px] text-red-300 lg:col-span-5">{error}</p>
          )}
        </form>
      )}

      {secrets.length === 0 ? (
        <EmptyState
          title="No secrets stored"
          copy="Add the credentials your workloads need. They are encrypted at rest and never returned to a browser."
        />
      ) : (
        <section className="cloud-card overflow-hidden">
          <Table className="text-[11px]">
            <TableHeader>
              <TableRow className="border-white/[0.06] hover:bg-transparent">
                {['Secret', 'Scope', 'Environment', 'Value', 'Rotation', 'Updated', ''].map((column, index) => (
                  <TableHead key={column || `actions-${index}`} className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25">
                    {column}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {secrets.map((secret) => {
                const overdue =
                  secret.rotationDays !== null &&
                  now - secret.updatedAt > secret.rotationDays * 24 * 60 * 60 * 1000;
                return (
                  <TableRow key={secret.id} className="border-white/[0.05] hover:bg-white/[0.02]">
                    <TableCell className="px-4 py-3">
                      <span className="flex items-center gap-2 font-mono font-medium text-white/72">
                        <KeyRound className="size-3.5 text-[#b7ff3c]/65" />
                        {secret.name}
                      </span>
                    </TableCell>
                    <TableCell className="px-4 py-3 text-white/42">{secret.scope}</TableCell>
                    <TableCell className="px-4 py-3 text-white/42">{secret.environment}</TableCell>
                    <TableCell className="px-4 py-3 font-mono text-white/30">••••••••••••</TableCell>
                    <TableCell className="px-4 py-3">
                      {secret.rotationDays === null ? (
                        <span className="text-white/35">Manual</span>
                      ) : (
                        <Badge
                          variant="outline"
                          className={overdue ? 'border-amber-400/20 text-amber-300' : 'border-white/[0.08] text-white/45'}
                        >
                          {overdue ? 'Overdue' : `${secret.rotationDays} days`}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="px-4 py-3 text-white/42">{relativeTime(secret.updatedAt, now)}</TableCell>
                    <TableCell className="px-4 py-3 text-right">
                      <Button
                        variant="ghost"
                        size="icon-xs"
                        aria-label={`Delete ${secret.name}`}
                        disabled={removing === secret.id}
                        onClick={() => remove(secret.id)}
                      >
                        {removing === secret.id ? <Loader2 className="animate-spin" /> : <Trash2 />}
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </section>
      )}
    </>
  );
}
