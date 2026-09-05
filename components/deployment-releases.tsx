'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import type { Deployment } from '@/lib/domain';
import type { ReleaseSummary } from '@/lib/server/releases';

type Preview = {
  deploymentId: string;
  current: ReleaseSummary | null;
  target: ReleaseSummary | null;
  eligible: boolean;
  reasons: string[];
  messages: string[];
  node: { id: string; name: string | null; status: string } | null;
  expectedCurrentArtifactId: string | null;
  impact: string;
};

type History = {
  deploymentId: string;
  currentArtifactId: string | null;
  node: { id: string; name: string | null; status: string } | null;
  releases: ReleaseSummary[];
  nextCursor: string | null;
};

const STATUS_TONE: Record<string, string> = {
  current: 'border-[#b7ff3c]/20 bg-[#b7ff3c]/8 text-[#c8ff69]',
  superseded: 'border-white/12 bg-white/5 text-white/55',
  building: 'border-sky-400/20 bg-sky-400/5 text-sky-300',
  failed: 'border-amber-400/20 bg-amber-400/5 text-amber-300',
  corrupted: 'border-red-400/25 bg-red-400/6 text-red-300',
  unavailable: 'border-white/10 bg-white/[0.03] text-white/35',
};

function when(value: number | null): string {
  return value ? new Date(value).toISOString().replace('T', ' ').slice(0, 16) : '—';
}

/**
 * Release history for one deployment, and the only path to a rollback.
 *
 * The previous control was a single `rollback` button that silently picked
 * the highest-numbered verified artifact that was not current. Nobody could
 * tell what it was about to start. Here the person chooses a release, reads a
 * server-computed preview of what switching to it would do, and confirms a
 * button that names the release by number.
 */
export function DeploymentReleases({ deployment }: { deployment: Deployment }) {
  const router = useRouter();
  const dialog = useRef<HTMLDialogElement>(null);
  const [open, setOpen] = useState(false);
  const [history, setHistory] = useState<History | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [ref, setRef] = useState('');

  const load = useCallback(async () => {
    setError(null);
    try {
      const response = await fetch(`/api/deployments/${deployment.id}/releases`);
      const body = (await response.json()) as { history?: History; error?: string };
      if (!response.ok || !body.history) throw new Error(body.error ?? 'The release history could not be read.');
      setHistory(body.history);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The release history could not be read.');
    }
  }, [deployment.id]);

  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    if (open && !element.open) element.showModal();
    if (!open && element.open) element.close();
  }, [open]);

  function close() {
    setOpen(false);
    setPreview(null);
    setNotice(null);
    setError(null);
  }

  async function openPreview(release: ReleaseSummary) {
    setBusy(release.artifactId);
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(
        `/api/deployments/${deployment.id}/rollback?targetArtifactId=${encodeURIComponent(release.artifactId)}`,
      );
      const body = (await response.json()) as { preview?: Preview; error?: string };
      if (!response.ok || !body.preview) throw new Error(body.error ?? 'The preview could not be built.');
      setPreview(body.preview);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The preview could not be built.');
    } finally {
      setBusy(null);
    }
  }

  async function confirmRollback() {
    if (!preview?.target) return;
    setBusy('rollback');
    setError(null);
    try {
      const response = await fetch(`/api/deployments/${deployment.id}/rollback`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          // Same key for the same decision, so a second click of the same
          // confirmation resolves to the action already queued.
          'Idempotency-Key': `ui:rollback:${deployment.id}:${preview.target.artifactId}:${preview.expectedCurrentArtifactId ?? 'none'}`,
        },
        body: JSON.stringify({
          targetArtifactId: preview.target.artifactId,
          expectedCurrentArtifactId: preview.expectedCurrentArtifactId,
        }),
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(body.error ?? 'The rollback was refused.');
      setPreview(null);
      setNotice('Rollback queued. The node verifies the release, activates it, then health-checks it.');
      await load();
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The rollback was refused.');
    } finally {
      setBusy(null);
    }
  }

  async function deployRelease() {
    setBusy('release');
    setError(null);
    setNotice(null);
    try {
      const trimmed = ref.trim();
      const body: Record<string, string> = {};
      if (/^[a-f0-9]{40}$/i.test(trimmed)) body.commit = trimmed;
      else if (trimmed) body.branch = trimmed;
      const response = await fetch(`/api/deployments/${deployment.id}/releases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const result = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(result.error ?? 'The release was refused.');
      setNotice('Release queued. The node builds the commit, then activates it if it passes health checks.');
      setRef('');
      await load();
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The release was refused.');
    } finally {
      setBusy(null);
    }
  }

  if (deployment.target !== 'user-node' || deployment.state === 'blocked') return null;

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        className="h-6 px-2 text-[9px]"
        onClick={() => {
          setOpen(true);
          void load();
        }}
      >
        releases
      </Button>
      <dialog
        ref={dialog}
        onClose={close}
        className="w-[min(46rem,92vw)] rounded-xl border border-white/10 bg-[#0b0d10] p-0 text-white/70 backdrop:bg-black/70"
      >
        <div className="max-h-[80vh] overflow-y-auto p-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-[13px] font-medium text-white/85">Releases</h2>
              <p className="mt-1 font-mono text-[10px] text-white/35">{deployment.id}</p>
            </div>
            <Button variant="outline" size="sm" className="h-6 px-2 text-[9px]" onClick={close}>
              close
            </Button>
          </div>

          {history?.node && (
            <p className="mt-3 text-[10px] text-white/40">
              Node {history.node.name ?? history.node.id} · {history.node.status}
            </p>
          )}

          <section className="mt-4 rounded-lg border border-white/[0.07] p-3">
            <h3 className="text-[10px] uppercase tracking-[0.1em] text-white/30">Deploy a new release</h3>
            <p className="mt-1 text-[10px] text-white/40">
              Builds another commit of this repository onto the same service and port. The running release keeps
              serving until the new one passes its health check.
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <label className="sr-only" htmlFor={`ref-${deployment.id}`}>
                Branch or commit
              </label>
              <input
                id={`ref-${deployment.id}`}
                value={ref}
                onChange={(event) => setRef(event.target.value)}
                placeholder={deployment.branch}
                className="h-7 flex-1 rounded border border-white/10 bg-black/40 px-2 font-mono text-[10px] text-white/70"
              />
              <Button
                variant="outline"
                size="sm"
                className="h-7 px-2 text-[9px]"
                disabled={busy !== null}
                onClick={() => void deployRelease()}
              >
                {busy === 'release' ? 'queueing…' : 'deploy release'}
              </Button>
            </div>
          </section>

          {notice && <output className="mt-3 block text-[10px] text-[#c8ff69]">{notice}</output>}
          {error && <p className="mt-3 text-[10px] text-red-300">{error}</p>}

          {preview && (
            <section className="mt-4 rounded-lg border border-[#b7ff3c]/20 bg-[#b7ff3c]/[0.04] p-3">
              <h3 className="text-[11px] font-medium text-white/85">
                Restore release {preview.target?.label ?? '—'}?
              </h3>
              <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-[10px]">
                <dt className="text-white/35">Running now</dt>
                <dd className="text-white/65">
                  {preview.current ? `${preview.current.label} · ${preview.current.commitSha.slice(0, 12)}` : '—'}
                </dd>
                <dt className="text-white/35">Restore to</dt>
                <dd className="text-white/65">
                  {preview.target ? `${preview.target.label} · ${preview.target.commitSha.slice(0, 12)}` : '—'}
                </dd>
                <dt className="text-white/35">Artifact</dt>
                <dd className="text-white/65">{preview.target?.statusLabel ?? '—'}</dd>
                <dt className="text-white/35">Node</dt>
                <dd className="text-white/65">{preview.node ? preview.node.status : 'unknown'}</dd>
              </dl>
              <p className="mt-2 text-[10px] text-white/45">{preview.impact}</p>
              {!preview.eligible && (
                <ul className="mt-2 space-y-0.5">
                  {preview.messages.map((message) => (
                    <li key={message} className="text-[10px] text-amber-300">
                      {message}
                    </li>
                  ))}
                </ul>
              )}
              <div className="mt-3 flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 px-2 text-[9px]"
                  disabled={!preview.eligible || busy !== null}
                  onClick={() => void confirmRollback()}
                >
                  {busy === 'rollback' ? 'queueing…' : `rollback to release ${preview.target?.label ?? ''}`}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 px-2 text-[9px]"
                  onClick={() => setPreview(null)}
                >
                  cancel
                </Button>
              </div>
            </section>
          )}

          <ul className="mt-4 space-y-2">
            {(history?.releases ?? []).map((release) => (
              <li
                key={release.artifactId}
                className="rounded-lg border border-white/[0.07] p-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="flex items-center gap-2">
                    <span className="font-mono text-[11px] text-white/80">Release {release.label}</span>
                    <Badge variant="outline" className={STATUS_TONE[release.status] ?? STATUS_TONE.superseded}>
                      {release.statusLabel}
                    </Badge>
                  </span>
                  {release.canRollback ? (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-6 px-2 text-[9px]"
                      disabled={busy !== null}
                      onClick={() => void openPreview(release)}
                    >
                      {busy === release.artifactId ? '…' : 'restore'}
                    </Button>
                  ) : (
                    <span className="text-[9px] text-white/28">
                      {release.isCurrent ? 'running' : 'not restorable'}
                    </span>
                  )}
                </div>
                <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-0.5 text-[10px] sm:grid-cols-4">
                  <dt className="text-white/30">Commit</dt>
                  <dd className="font-mono text-white/50">{release.commitSha.slice(0, 12)}</dd>
                  <dt className="text-white/30">Built</dt>
                  <dd className="text-white/50">{when(release.createdAt)}</dd>
                  <dt className="text-white/30">Verified</dt>
                  <dd className="text-white/50">{when(release.verifiedAt)}</dd>
                  <dt className="text-white/30">Fingerprint</dt>
                  <dd className="font-mono text-white/50">{release.checksumPrefix ?? '—'}</dd>
                </dl>
              </li>
            ))}
          </ul>

          {history && history.releases.length === 0 && (
            <p className="mt-4 text-[10px] text-white/40">
              No releases recorded yet for this deployment.
            </p>
          )}
          {history && history.releases.length === 1 && (
            <p className="mt-3 text-[10px] text-white/40">
              Rollback needs an earlier release to return to. Deploy another release first.
            </p>
          )}
        </div>
      </dialog>
    </>
  );
}
