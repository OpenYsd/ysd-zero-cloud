'use client';

import { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Bot,
  Clock3,
  Cpu,
  Download,
  HardDrive,
  Loader2,
  MemoryStick,
  Play,
  ShieldCheck,
  Square,
  Timer,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { EmptyState, MetricGrid } from '@/components/ui-bits';
import type { AiModel, AiRun, AiState } from '@/lib/domain';
import { formatBytes } from '@/lib/free-tier';
import { relativeTime } from '@/lib/format';
import { cn } from '@/lib/utils';

const SELECT_CLASS =
  'h-9 rounded-md border border-white/[0.08] bg-[#0a0f0d] px-3 text-xs text-white/60 outline-none focus:border-[#b7ff3c]/35';

function stateStyle(state: AiRun['state']): string {
  if (state === 'succeeded') return 'text-[#c8ff69]';
  if (state === 'failed' || state === 'timed_out') return 'text-red-300';
  if (state === 'leased' || state === 'cancelling') return 'text-violet-300';
  if (state === 'cancelled') return 'text-amber-200';
  return 'text-white/45';
}

function modelBadge(model: AiModel): string {
  if (model.state === 'ready') {
    return 'border-[#b7ff3c]/20 bg-[#b7ff3c]/[0.06] text-[#c8ff69]';
  }
  if (model.state === 'error') {
    return 'border-red-300/20 bg-red-300/[0.06] text-red-200';
  }
  return 'border-white/10 bg-white/[0.035] text-white/45';
}

function resultText(run: AiRun): string | null {
  return run.result && typeof run.result.text === 'string'
    ? run.result.text
    : null;
}

export function AiCenter({ state, now }: { state: AiState; now: number }) {
  const router = useRouter();
  const defaultModel = state.models.find((model) => model.enabled)?.id ?? '';
  const [modelId, setModelId] = useState(defaultModel);
  const [targetNodeId, setTargetNodeId] = useState('');
  const [cacheNodeId, setCacheNodeId] = useState(
    state.nodes.find((node) => node.status === 'online')?.id ?? '',
  );
  const [prompt, setPrompt] = useState('Explain why outbound-only compute reduces attack surface.');
  const [systemPrompt, setSystemPrompt] = useState(
    'Answer concisely and do not include external links.',
  );
  const [maxTokens, setMaxTokens] = useState('512');
  const [temperature, setTemperature] = useState('0.7');
  const [responseFormat, setResponseFormat] = useState<'text' | 'json'>('text');
  const [downloadApproved, setDownloadApproved] = useState(false);
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const onlineNodes = useMemo(
    () => state.nodes.filter((node) => node.status === 'online'),
    [state.nodes],
  );

  async function runInference() {
    setPending('run');
    setError(null);
    try {
      const response = await fetch('/api/ai/jobs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': crypto.randomUUID(),
        },
        body: JSON.stringify({
          modelId,
          targetNodeId: targetNodeId || null,
          prompt,
          systemPrompt: systemPrompt || null,
          maxTokens: Number(maxTokens),
          temperature: Number(temperature),
          responseFormat,
          timeoutMs: 120_000,
          provider: 'local-node',
          zeroMode: true,
        }),
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) {
        throw new Error(body.error ?? 'Local inference could not be queued.');
      }
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Inference failed.');
    } finally {
      setPending(null);
    }
  }

  async function cacheModel(model: AiModel) {
    if (!downloadApproved || !cacheNodeId) return;
    setPending(`cache:${model.id}`);
    setError(null);
    try {
      const response = await fetch(`/api/ai/models/${model.id}/cache`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': crypto.randomUUID(),
        },
        body: JSON.stringify({ nodeId: cacheNodeId, approved: true }),
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) {
        throw new Error(body.error ?? 'Model acquisition could not be queued.');
      }
      setDownloadApproved(false);
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Model acquisition failed.');
    } finally {
      setPending(null);
    }
  }

  async function cancel(run: AiRun) {
    setPending(`cancel:${run.jobId}`);
    setError(null);
    try {
      const response = await fetch(`/api/ai/jobs/${run.jobId}`, {
        method: 'DELETE',
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) {
        throw new Error(body.error ?? 'Inference could not be cancelled.');
      }
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Cancellation failed.');
    } finally {
      setPending(null);
    }
  }

  return (
    <>
      <div className="flex items-start gap-3 rounded-xl border border-[#b7ff3c]/15 bg-[#b7ff3c]/[0.04] p-4 text-[11px] leading-5 text-white/45">
        <ShieldCheck className="mt-0.5 size-4 shrink-0 text-[#b7ff3c]" />
        <div>
          <p className="font-semibold text-[#d9ffa1]">Local AI, enforced</p>
          <p className="mt-1">
            Every inference runs through an allowlisted Ollama or llama.cpp API
            on a machine you own. The Worker is only the signed control plane:
            no paid AI binding, provider fallback, public node port, or arbitrary
            command is available.
          </p>
        </div>
      </div>

      <MetricGrid
        items={[
          {
            icon: Cpu,
            label: 'AI nodes',
            value: state.summary.onlineNodes.toLocaleString('en-US'),
            detail: `${state.summary.aiCapableNodes} detected`,
          },
          {
            icon: Bot,
            label: 'Ready models',
            value: state.summary.readyModels.toLocaleString('en-US'),
            detail: `${state.models.length} approved`,
          },
          {
            icon: Timer,
            label: 'Active jobs',
            value: (state.summary.queued + state.summary.running).toLocaleString('en-US'),
            detail: `${state.summary.completed} completed`,
          },
          {
            icon: HardDrive,
            label: 'Platform compute',
            value: '$0.00',
            detail: 'Zero Mode · local only',
          },
        ]}
      />

      <section className="cloud-card p-5">
        <div className="flex items-center gap-2">
          <Play className="size-4 text-violet-300" />
          <h2 className="text-sm font-semibold text-white/80">Run inference</h2>
        </div>
        <p className="mt-2 text-[10px] leading-4 text-white/30">
          The scheduler selects an online node with the exact runtime, cached
          model, memory, and concurrency capacity. Prompts cannot add URLs,
          commands, paths, providers, or execution fields.
        </p>
        <div className="mt-4 grid gap-3 lg:grid-cols-2">
          <label className="space-y-1 text-[10px] text-white/35">
            Approved model
            <select
              aria-label="Approved AI model"
              value={modelId}
              onChange={(event) => setModelId(event.target.value)}
              className={cn(SELECT_CLASS, 'w-full')}
            >
              {state.models.map((model) => (
                <option key={model.id} value={model.id}>
                  {model.displayName} · {model.runtime} · {model.state}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1 text-[10px] text-white/35">
            Target node
            <select
              aria-label="AI target node"
              value={targetNodeId}
              onChange={(event) => setTargetNodeId(event.target.value)}
              className={cn(SELECT_CLASS, 'w-full')}
            >
              <option value="">Automatic safe placement</option>
              {onlineNodes.map((node) => (
                <option key={node.id} value={node.id}>
                  {node.name}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1 text-[10px] text-white/35 lg:col-span-2">
            Prompt
            <textarea
              aria-label="Inference prompt"
              value={prompt}
              maxLength={16_384}
              rows={5}
              onChange={(event) => setPrompt(event.target.value)}
              className="w-full resize-y rounded-md border border-white/[0.08] bg-[#0a0f0d] p-3 text-xs leading-5 text-white/65 outline-none focus:border-[#b7ff3c]/35"
            />
          </label>
          <label htmlFor="ai-system-prompt" className="space-y-1 text-[10px] text-white/35 lg:col-span-2">
            System instruction
            <Input
              id="ai-system-prompt"
              value={systemPrompt}
              maxLength={4096}
              onChange={(event) => setSystemPrompt(event.target.value)}
            />
          </label>
          <div className="grid grid-cols-3 gap-2 lg:col-span-2">
            <Input
              aria-label="Maximum tokens"
              type="number"
              min={1}
              max={4096}
              value={maxTokens}
              onChange={(event) => setMaxTokens(event.target.value)}
            />
            <Input
              aria-label="Temperature"
              type="number"
              min={0}
              max={2}
              step={0.1}
              value={temperature}
              onChange={(event) => setTemperature(event.target.value)}
            />
            <select
              aria-label="Response format"
              value={responseFormat}
              onChange={(event) =>
                setResponseFormat(event.target.value === 'json' ? 'json' : 'text')
              }
              className={SELECT_CLASS}
            >
              <option value="text">Text</option>
              <option value="json">JSON</option>
            </select>
          </div>
        </div>
        <div className="mt-4 flex items-center justify-between gap-3">
          <p className="text-[10px] text-white/25">
            Lease timeout 120s · signed claim · replay protected
          </p>
          <Button
            disabled={!modelId || !prompt.trim() || Boolean(pending)}
            onClick={() => void runInference()}
            className="bg-[#b7ff3c] text-[#07100c] hover:bg-[#cbff72]"
          >
            {pending === 'run' ? <Loader2 className="animate-spin" /> : <Play />}
            Run locally
          </Button>
        </div>
        {error ? (
          <p role="alert" className="mt-4 text-[11px] text-red-300">
            {error}
          </p>
        ) : null}
      </section>

      <section className="cloud-card p-5">
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div>
            <div className="flex items-center gap-2">
              <Download className="size-4 text-[#b7ff3c]" />
              <h2 className="text-sm font-semibold text-white/80">Approved model catalog</h2>
            </div>
            <p className="mt-2 max-w-2xl text-[10px] leading-4 text-white/30">
              Downloads require a separate explicit approval and work only for
              fixed Ollama library identifiers. llama.cpp uses its already loaded
              local model; the agent never receives a URL or filesystem path.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <select
              aria-label="Model cache node"
              value={cacheNodeId}
              onChange={(event) => setCacheNodeId(event.target.value)}
              className={SELECT_CLASS}
            >
              <option value="">Select online node</option>
              {onlineNodes.map((node) => (
                <option key={node.id} value={node.id}>
                  {node.name}
                </option>
              ))}
            </select>
            <label className="flex items-center gap-2 text-[10px] text-white/45">
              <input
                type="checkbox"
                checked={downloadApproved}
                onChange={(event) => setDownloadApproved(event.target.checked)}
                className="accent-[#b7ff3c]"
              />
              I approve this local download
            </label>
          </div>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {state.models.map((model) => (
            <article key={model.id} className="rounded-xl border border-white/[0.07] bg-black/20 p-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-xs font-semibold text-white/70">{model.displayName}</p>
                  <p className="mt-1 font-mono text-[9px] text-white/25">{model.runtimeModel}</p>
                </div>
                <Badge variant="outline" className={modelBadge(model)}>{model.state}</Badge>
              </div>
              <div className="mt-4 space-y-1 text-[10px] text-white/35">
                <p>{model.runtime} · {model.family}</p>
                <p>Model {model.sizeBytes ? formatBytes(model.sizeBytes) : 'runtime-managed'}</p>
                <p>RAM floor {formatBytes(model.expectedMemoryBytes)}</p>
                <p>{model.caches.length} node cache record{model.caches.length === 1 ? '' : 's'}</p>
              </div>
              {model.downloadable ? (
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-4 w-full"
                  disabled={!downloadApproved || !cacheNodeId || Boolean(pending)}
                  onClick={() => void cacheModel(model)}
                >
                  {pending === `cache:${model.id}` ? <Loader2 className="animate-spin" /> : <Download />}
                  Cache on node
                </Button>
              ) : (
                <p className="mt-4 text-[9px] text-white/25">Existing local runtime model only</p>
              )}
            </article>
          ))}
        </div>
      </section>

      {state.runs.length === 0 ? (
        <EmptyState
          title="No local inference jobs yet"
          copy="Connect an AI runtime, cache an approved model, then submit an inference above."
        />
      ) : (
        <section className="cloud-card overflow-hidden">
          <Table className="text-[11px]">
            <TableHeader>
              <TableRow className="border-white/[0.06] hover:bg-transparent">
                {['Inference', 'State', 'Node', 'Tokens / latency', 'Result', ''].map((column, index) => (
                  <TableHead key={column || `ai-action-${index}`} className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25">
                    {column}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {state.runs.map((run) => {
                const text = resultText(run);
                const cancellable = run.state === 'queued' || run.state === 'leased';
                return (
                  <TableRow key={run.jobId} className="border-white/[0.05] hover:bg-white/[0.02]">
                    <TableCell className="px-4 py-3">
                      <p className="font-medium text-white/65">{run.modelName}</p>
                      <p className="mt-1 font-mono text-[9px] text-white/20">{run.jobId}</p>
                    </TableCell>
                    <TableCell className={cn('px-4 py-3 capitalize', stateStyle(run.state))}>
                      {run.state.replace('_', ' ')}
                    </TableCell>
                    <TableCell className="px-4 py-3 text-white/38">
                      {run.selectedNodeName ?? 'awaiting placement'}
                      <p className="mt-1 text-[9px] text-white/22">{run.runtime} · attempt {run.attempts}</p>
                    </TableCell>
                    <TableCell className="px-4 py-3 text-white/38">
                      {run.outputTokensEstimate ?? 0} output
                      <p className="mt-1 flex items-center gap-1 text-[9px] text-white/22">
                        <Clock3 className="size-3" /> {run.latencyMs === null ? relativeTime(run.createdAt, now) : `${run.latencyMs} ms`}
                      </p>
                    </TableCell>
                    <TableCell className="max-w-md px-4 py-3">
                      {text ? (
                        <p className="line-clamp-3 whitespace-pre-wrap text-white/48">{text}</p>
                      ) : run.lastError ? (
                        <p className="line-clamp-2 text-red-300/75">{run.lastError}</p>
                      ) : (
                        <span className="text-white/22">Waiting for local node</span>
                      )}
                    </TableCell>
                    <TableCell className="px-4 py-3 text-right">
                      {cancellable ? (
                        <Button
                          variant="ghost"
                          size="icon-xs"
                          aria-label={`Cancel ${run.jobId}`}
                          disabled={Boolean(pending)}
                          onClick={() => void cancel(run)}
                        >
                          {pending === `cancel:${run.jobId}` ? <Loader2 className="animate-spin" /> : <Square />}
                        </Button>
                      ) : null}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </section>
      )}

      <section className="grid gap-3 md:grid-cols-3">
        {state.nodes.map((node) => (
          <article key={node.id} className="cloud-card p-4">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-semibold text-white/70">{node.name}</p>
              <Badge variant="outline">{node.status}</Badge>
            </div>
            <div className="mt-3 space-y-1 text-[10px] text-white/35">
              <p className="flex items-center gap-1"><Cpu className="size-3" /> {node.capabilities.cpu.cores} cores</p>
              <p className="flex items-center gap-1"><MemoryStick className="size-3" /> {formatBytes(node.capabilities.memory.freeBytes)} free RAM</p>
              <p className="flex items-center gap-1"><HardDrive className="size-3" /> {formatBytes(node.capabilities.disk.freeBytes)} free disk</p>
              <p>{node.capabilities.ai.runtimes.filter((runtime) => runtime.available).map((runtime) => runtime.runtime).join(', ') || 'No local AI runtime detected'}</p>
            </div>
          </article>
        ))}
      </section>
    </>
  );
}
