'use client';

import { useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Download,
  FileUp,
  HardDrive,
  Loader2,
  LockKeyhole,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button, buttonVariants } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { EmptyState, MetricGrid } from '@/components/ui-bits';
import type { StorageState } from '@/lib/domain';
import { formatBytes } from '@/lib/free-tier';
import { relativeTime } from '@/lib/format';
import { cn } from '@/lib/utils';

export function StorageView({
  state,
  now,
}: {
  state: StorageState;
  now: number;
}) {
  const router = useRouter();
  const input = useRef<HTMLInputElement>(null);
  const [pending, setPending] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const usedPercent = Math.min(
    100,
    (state.usage.bytesUsed / state.limits.workspaceBytes) * 100,
  );

  async function upload(file: File | undefined) {
    if (!file) return;
    setPending(true);
    setError(null);
    try {
      const form = new FormData();
      form.set('file', file);
      const response = await fetch('/api/storage', {
        method: 'POST',
        body: form,
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(body.error ?? 'The upload failed.');
      if (input.current) input.current.value = '';
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The upload failed.');
    } finally {
      setPending(false);
    }
  }

  async function remove(id: string, name: string) {
    if (
      !window.confirm(
        `Delete ${name}? This removes the private R2 object permanently.`,
      )
    )
      return;
    setRemoving(id);
    setError(null);
    try {
      const response = await fetch(`/api/storage/${id}`, { method: 'DELETE' });
      const body = (await response.json()) as { error?: string };
      if (!response.ok)
        throw new Error(body.error ?? 'The object could not be deleted.');
      router.refresh();
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : 'The object could not be deleted.',
      );
    } finally {
      setRemoving(null);
    }
  }

  return (
    <>
      {!state.available ? (
        <div className="flex items-start gap-3 rounded-xl border border-amber-400/15 bg-amber-400/[0.045] p-4 text-[11px] leading-5 text-white/45">
          <HardDrive className="mt-0.5 size-4 shrink-0 text-amber-300" />
          <div>
            <p className="font-semibold text-amber-200">
              R2 account activation is still unavailable
            </p>
            <p className="mt-1">
              The private storage API, D1 quota ledger, and interface are ready.
              Cloudflare currently refuses bucket access until R2 is enabled in
              the account dashboard, so uploads stay disabled and no billable
              resource is created.
            </p>
          </div>
        </div>
      ) : null}

      <MetricGrid
        items={[
          {
            icon: HardDrive,
            label: 'Workspace storage',
            value: formatBytes(state.usage.bytesUsed),
            detail: `of ${formatBytes(state.limits.workspaceBytes)}`,
          },
          {
            icon: FileUp,
            label: 'Objects',
            value: state.usage.objectCount.toLocaleString('en-US'),
            detail: `of ${state.limits.workspaceObjects}`,
          },
          {
            icon: LockKeyhole,
            label: 'Access',
            value: 'Private',
            detail: 'session-scoped',
          },
          {
            icon: ShieldCheck,
            label: 'Projected cost',
            value: '$0.00',
            detail: 'hard stopped',
          },
        ]}
      />

      <section className="cloud-card p-5">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-white/80">
                Private R2 bucket
              </h2>
              <Badge
                variant="outline"
                className="border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]"
              >
                Standard only
              </Badge>
            </div>
            <p className="mt-1 text-[10px] text-white/30">
              {state.bucket ?? 'ysd-zero-cloud-storage'} · no r2.dev URL · no
              custom domain
            </p>
          </div>
          <div>
            <input
              ref={input}
              type="file"
              className="hidden"
              aria-label="Choose an object to upload"
              disabled={!state.available || pending}
              onChange={(event) => void upload(event.target.files?.[0])}
            />
            <Button
              type="button"
              disabled={!state.available || pending}
              onClick={() => input.current?.click()}
              className="h-9 bg-[#b7ff3c] px-3.5 text-xs font-semibold text-[#07100c] hover:bg-[#cbff72]"
            >
              {pending ? <Loader2 className="animate-spin" /> : <FileUp />}{' '}
              Upload object
            </Button>
          </div>
        </div>
        <div className="mt-5">
          <div className="mb-2 flex justify-between text-[10px] text-white/35">
            <span>Workspace guard</span>
            <span className="font-mono">
              {formatBytes(state.usage.bytesUsed)} /{' '}
              {formatBytes(state.limits.workspaceBytes)}
            </span>
          </div>
          <Progress value={usedPercent} />
          <p className="mt-3 text-[10px] leading-4 text-white/25">
            Each object is capped at {formatBytes(state.limits.objectBytes)}.
            The shared account guard stops at{' '}
            {formatBytes(state.limits.accountBytes)}, one tenth of R2
            Standard&apos;s published free storage allowance. Writes and reads
            also stop far below their monthly allowances.
          </p>
        </div>
        {error ? (
          <p role="alert" className="mt-4 text-[11px] text-red-300">
            {error}
          </p>
        ) : null}
      </section>

      {state.objects.length === 0 ? (
        <EmptyState
          title={
            state.available
              ? 'No objects yet'
              : 'Storage is safely waiting for R2'
          }
          copy={
            state.available
              ? 'Upload a file to the private bucket. Every read and write is scoped to this workspace.'
              : 'No mock objects are shown and no bucket has been created while account activation is unavailable.'
          }
        />
      ) : (
        <section className="cloud-card overflow-hidden">
          <Table className="text-[11px]">
            <TableHeader>
              <TableRow className="border-white/[0.06] hover:bg-transparent">
                {['Object', 'Type', 'Size', 'Uploaded', 'ETag', ''].map(
                  (column, index) => (
                    <TableHead
                      key={column || `actions-${index}`}
                      className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25"
                    >
                      {column}
                    </TableHead>
                  ),
                )}
              </TableRow>
            </TableHeader>
            <TableBody>
              {state.objects.map((object) => (
                <TableRow
                  key={object.id}
                  className="border-white/[0.05] hover:bg-white/[0.02]"
                >
                  <TableCell className="max-w-[280px] truncate px-4 py-3 font-medium text-white/72">
                    {object.name}
                  </TableCell>
                  <TableCell className="px-4 py-3 text-white/38">
                    {object.contentType}
                  </TableCell>
                  <TableCell className="px-4 py-3 font-mono text-white/42">
                    {formatBytes(object.size)}
                  </TableCell>
                  <TableCell className="px-4 py-3 text-white/42">
                    {relativeTime(object.createdAt, now)}
                  </TableCell>
                  <TableCell className="max-w-[160px] truncate px-4 py-3 font-mono text-[10px] text-white/28">
                    {object.etag}
                  </TableCell>
                  <TableCell className="px-4 py-3">
                    <div className="flex justify-end gap-1">
                      <a
                        href={`/api/storage/${object.id}`}
                        aria-label={`Download ${object.name}`}
                        className={cn(
                          buttonVariants({ variant: 'ghost', size: 'icon-xs' }),
                        )}
                      >
                        <Download />
                      </a>
                      <Button
                        variant="ghost"
                        size="icon-xs"
                        aria-label={`Delete ${object.name}`}
                        disabled={removing === object.id}
                        onClick={() => void remove(object.id, object.name)}
                      >
                        {removing === object.id ? (
                          <Loader2 className="animate-spin" />
                        ) : (
                          <Trash2 />
                        )}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </section>
      )}
    </>
  );
}
