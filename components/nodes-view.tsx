'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Activity,
  Boxes,
  Check,
  Clock3,
  Copy,
  Cpu,
  HardDrive,
  KeyRound,
  Loader2,
  MemoryStick,
  Network,
  Play,
  Plus,
  ShieldCheck,
  Unplug,
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
import type { ComputeNode, NodeJob, NodesState } from '@/lib/domain';
import { formatBytes } from '@/lib/free-tier';
import { relativeTime } from '@/lib/format';
import { agentVersionSupported } from '@/lib/nodes';
import { cn } from '@/lib/utils';

type Pairing = {
  id: string;
  name: string;
  code: string;
  expiresAt: number;
  minimumAgentVersion: string;
};

const STATUS_STYLE: Record<ComputeNode['status'], string> = {
  online: 'border-[#b7ff3c]/20 bg-[#b7ff3c]/[0.06] text-[#c8ff69]',
  stale: 'border-amber-300/20 bg-amber-300/[0.06] text-amber-200',
  offline: 'border-white/10 bg-white/[0.035] text-white/45',
  revoked: 'border-red-300/20 bg-red-300/[0.06] text-red-200',
};

function jobStyle(state: NodeJob['state']): string {
  if (state === 'succeeded') return 'text-[#c8ff69]';
  if (state === 'failed' || state === 'timed_out') return 'text-red-300';
  if (state === 'leased') return 'text-violet-300';
  return 'text-white/45';
}

export function NodesView({ state, now }: { state: NodesState; now: number }) {
  const router = useRouter();
  const [name, setName] = useState('My compute node');
  const [message, setMessage] = useState('YSD secure node check');
  const [targetNodeId, setTargetNodeId] = useState('');
  const [pairing, setPairing] = useState<Pairing | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function connectNode() {
    setPending('pair');
    setError(null);
    try {
      const response = await fetch('/api/nodes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      });
      const body = (await response.json()) as {
        pairing?: Pairing;
        error?: string;
      };
      if (!response.ok || !body.pairing) {
        throw new Error(body.error ?? 'Pairing could not be created.');
      }
      setPairing(body.pairing);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Pairing failed.');
    } finally {
      setPending(null);
    }
  }

  async function enqueue(type: 'diagnostic.ping' | 'diagnostic.snapshot') {
    setPending(type);
    setError(null);
    try {
      const response = await fetch('/api/nodes/jobs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': crypto.randomUUID(),
        },
        body: JSON.stringify({
          type,
          targetNodeId: targetNodeId || null,
          payload: type === 'diagnostic.ping' ? { message } : {},
        }),
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok)
        throw new Error(body.error ?? 'Job could not be queued.');
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Job failed.');
    } finally {
      setPending(null);
    }
  }

  async function revoke(node: ComputeNode) {
    if (
      !window.confirm(
        `Revoke ${node.name}? Its token will stop working immediately.`,
      )
    ) {
      return;
    }
    setPending(node.id);
    setError(null);
    try {
      const response = await fetch(`/api/nodes/${node.id}`, {
        method: 'DELETE',
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok)
        throw new Error(body.error ?? 'Node could not be revoked.');
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Revocation failed.');
    } finally {
      setPending(null);
    }
  }

  const activeNodes = state.nodes.filter((node) => node.status !== 'revoked');
  const origin = typeof window === 'undefined' ? '' : window.location.origin;
  const command = pairing
    ? `$env:YSD_NODE_URL = '${origin}'\n$env:YSD_NODE_PAIRING_CODE = '${pairing.code}'\n$env:YSD_NODE_AGENT_KEY = '<your local passphrase, 16+ characters>'\nnode --experimental-strip-types agent/cli.ts pair --url $env:YSD_NODE_URL`
    : '';

  return (
    <>
      <div className="flex items-start gap-3 rounded-xl border border-[#b7ff3c]/15 bg-[#b7ff3c]/[0.04] p-4 text-[11px] leading-5 text-white/45">
        <Network className="mt-0.5 size-4 shrink-0 text-[#b7ff3c]" />
        <div>
          <p className="font-semibold text-[#d9ffa1]">Outbound-only compute</p>
          <p className="mt-1">
            Nodes poll this Worker over signed HTTPS. No port, tunnel, inbound
            firewall rule, Cloudflare compute product, or paid resource is
            created. Work runs only on machines you own.
          </p>
        </div>
      </div>

      <MetricGrid
        items={[
          {
            icon: Boxes,
            label: 'Connected nodes',
            value: state.summary.total.toLocaleString('en-US'),
            detail: `${state.summary.online} online · ${state.summary.stale} stale`,
          },
          {
            icon: Activity,
            label: 'Job queue',
            value: state.summary.queuedJobs.toLocaleString('en-US'),
            detail: `${state.summary.activeLeases} active lease${state.summary.activeLeases === 1 ? '' : 's'}`,
          },
          {
            icon: ShieldCheck,
            label: 'Transport',
            value: 'Signed HTTPS',
            detail: 'nonce + replay guard',
          },
          {
            icon: HardDrive,
            label: 'Platform compute',
            value: '$0.00',
            detail: 'user-owned hardware',
          },
        ]}
      />

      <section className="cloud-card p-5">
        <div className="grid gap-5 lg:grid-cols-[1fr_1.2fr]">
          <div>
            <div className="flex items-center gap-2">
              <Plus className="size-4 text-[#b7ff3c]" />
              <h2 className="text-sm font-semibold text-white/80">
                Connect a node
              </h2>
            </div>
            <p className="mt-2 text-[10px] leading-4 text-white/32">
              The ticket expires in ten minutes and works once. The agent token
              is encrypted in D1 and encrypted again on the node with your local
              passphrase.
            </p>
            <div className="mt-4 flex gap-2">
              <Input
                value={name}
                maxLength={64}
                aria-label="Node name"
                onChange={(event) => setName(event.target.value)}
                className="h-9"
              />
              <Button
                onClick={() => void connectNode()}
                disabled={pending === 'pair'}
                className="h-9 bg-[#b7ff3c] text-[#07100c] hover:bg-[#cbff72]"
              >
                {pending === 'pair' ? (
                  <Loader2 className="animate-spin" />
                ) : (
                  <KeyRound />
                )}
                Pair
              </Button>
            </div>
          </div>

          <div className="rounded-xl border border-white/[0.07] bg-black/20 p-4">
            {pairing ? (
              <>
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold text-white/75">
                      One-time agent command
                    </p>
                    <p className="mt-1 text-[10px] text-white/30">
                      Expires {relativeTime(pairing.expiresAt, now)} · agent{' '}
                      {pairing.minimumAgentVersion}+
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label="Copy pairing command"
                    onClick={() => {
                      void navigator.clipboard.writeText(command);
                      setCopied(true);
                    }}
                  >
                    {copied ? <Check /> : <Copy />}
                  </Button>
                </div>
                <pre className="mt-3 overflow-x-auto whitespace-pre-wrap break-all rounded-lg border border-white/[0.06] bg-[#070a09] p-3 text-[10px] leading-5 text-[#c8ff69]/75">
                  {command}
                </pre>
              </>
            ) : (
              <div className="grid min-h-28 place-items-center text-center">
                <div>
                  <KeyRound className="mx-auto size-5 text-white/20" />
                  <p className="mt-2 text-[10px] text-white/28">
                    Create a ticket to reveal the one-time onboarding command.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
        {error ? (
          <p role="alert" className="mt-4 text-[11px] text-red-300">
            {error}
          </p>
        ) : null}
      </section>

      {state.nodes.length === 0 ? (
        <EmptyState
          title="No compute nodes connected"
          copy="Pair a machine you own. It will appear here only after the agent exchanges the one-time ticket."
        />
      ) : (
        <section className="cloud-card overflow-hidden">
          <Table className="text-[11px]">
            <TableHeader>
              <TableRow className="border-white/[0.06] hover:bg-transparent">
                {[
                  'Node',
                  'Status',
                  'Capacity',
                  'Capabilities',
                  'Agent',
                  'Heartbeat',
                  '',
                ].map((column, index) => (
                  <TableHead
                    key={column || `node-action-${index}`}
                    className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25"
                  >
                    {column}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {state.nodes.map((node) => (
                <TableRow
                  key={node.id}
                  className="border-white/[0.05] hover:bg-white/[0.02]"
                >
                  <TableCell className="px-4 py-3">
                    <p className="font-medium text-white/75">{node.name}</p>
                    <p className="mt-1 font-mono text-[9px] text-white/22">
                      {node.platform}/{node.architecture}
                    </p>
                  </TableCell>
                  <TableCell className="px-4 py-3">
                    <Badge
                      variant="outline"
                      className={cn('capitalize', STATUS_STYLE[node.status])}
                    >
                      {node.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="px-4 py-3 text-white/38">
                    <span className="flex items-center gap-1">
                      <Cpu className="size-3" /> {node.capabilities.cpu.cores}{' '}
                      cores
                    </span>
                    <span className="mt-1 flex items-center gap-1">
                      <MemoryStick className="size-3" />{' '}
                      {formatBytes(node.capabilities.memory.totalBytes)}
                    </span>
                  </TableCell>
                  <TableCell className="px-4 py-3 text-white/38">
                    GPU {node.capabilities.gpu.available ? 'reported' : 'off'} ·
                    Docker{' '}
                    {node.capabilities.docker.available ? 'reported' : 'off'}
                  </TableCell>
                  <TableCell className="px-4 py-3">
                    <span
                      className={
                        agentVersionSupported(node.agentVersion)
                          ? 'text-white/45'
                          : 'text-amber-300'
                      }
                    >
                      v{node.agentVersion}
                    </span>
                    <p className="mt-1 text-[9px] text-white/22">
                      protocol {node.protocolVersion}
                    </p>
                  </TableCell>
                  <TableCell className="px-4 py-3 text-white/38">
                    {node.lastHeartbeatAt
                      ? relativeTime(node.lastHeartbeatAt, now)
                      : 'Waiting'}
                    {node.metrics ? (
                      <p className="mt-1 text-[9px] text-white/22">
                        CPU {node.metrics.cpuLoadPercent.toFixed(1)}% · RAM{' '}
                        {formatBytes(node.metrics.memoryUsedBytes)}
                      </p>
                    ) : null}
                  </TableCell>
                  <TableCell className="px-4 py-3 text-right">
                    {node.status !== 'revoked' ? (
                      <Button
                        variant="ghost"
                        size="icon-xs"
                        aria-label={`Revoke ${node.name}`}
                        disabled={pending === node.id}
                        onClick={() => void revoke(node)}
                      >
                        {pending === node.id ? (
                          <Loader2 className="animate-spin" />
                        ) : (
                          <Unplug />
                        )}
                      </Button>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </section>
      )}

      <section className="cloud-card p-5">
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div>
            <div className="flex items-center gap-2">
              <Play className="size-4 text-violet-300" />
              <h2 className="text-sm font-semibold text-white/80">
                Allowlisted diagnostics
              </h2>
            </div>
            <p className="mt-2 max-w-xl text-[10px] leading-4 text-white/30">
              No shell text, script, image, container, AI model, or game-server
              action can be submitted. Those contracts stay disabled until a
              later security review.
            </p>
          </div>
          <div className="grid gap-2 sm:grid-cols-[180px_1fr_auto_auto]">
            <select
              aria-label="Target node"
              value={targetNodeId}
              onChange={(event) => setTargetNodeId(event.target.value)}
              className="h-9 rounded-md border border-white/[0.08] bg-[#0a0f0d] px-3 text-xs text-white/60"
            >
              <option value="">Any online node</option>
              {activeNodes.map((node) => (
                <option key={node.id} value={node.id}>
                  {node.name}
                </option>
              ))}
            </select>
            <Input
              value={message}
              maxLength={256}
              aria-label="Ping message"
              onChange={(event) => setMessage(event.target.value)}
              className="h-9"
            />
            <Button
              variant="outline"
              disabled={Boolean(pending)}
              onClick={() => void enqueue('diagnostic.ping')}
            >
              {pending === 'diagnostic.ping' ? (
                <Loader2 className="animate-spin" />
              ) : (
                <Activity />
              )}{' '}
              Ping
            </Button>
            <Button
              variant="outline"
              disabled={Boolean(pending)}
              onClick={() => void enqueue('diagnostic.snapshot')}
            >
              {pending === 'diagnostic.snapshot' ? (
                <Loader2 className="animate-spin" />
              ) : (
                <Cpu />
              )}{' '}
              Snapshot
            </Button>
          </div>
        </div>
      </section>

      {state.jobs.length > 0 ? (
        <section className="cloud-card overflow-hidden">
          <Table className="text-[11px]">
            <TableHeader>
              <TableRow className="border-white/[0.06] hover:bg-transparent">
                {['Job', 'State', 'Node', 'Attempts', 'Lease / completed'].map(
                  (column) => (
                    <TableHead
                      key={column}
                      className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25"
                    >
                      {column}
                    </TableHead>
                  ),
                )}
              </TableRow>
            </TableHeader>
            <TableBody>
              {state.jobs.map((job) => (
                <TableRow
                  key={job.id}
                  className="border-white/[0.05] hover:bg-white/[0.02]"
                >
                  <TableCell className="px-4 py-3">
                    <p className="font-medium text-white/65">{job.type}</p>
                    <p className="mt-1 font-mono text-[9px] text-white/20">
                      {job.id}
                    </p>
                  </TableCell>
                  <TableCell
                    className={cn('px-4 py-3 capitalize', jobStyle(job.state))}
                  >
                    {job.state.replace('_', ' ')}
                  </TableCell>
                  <TableCell className="px-4 py-3 font-mono text-[9px] text-white/28">
                    {job.assignedNodeId ?? job.targetNodeId ?? 'any'}
                  </TableCell>
                  <TableCell className="px-4 py-3 text-white/38">
                    {job.attempts} / {job.maxAttempts}
                  </TableCell>
                  <TableCell className="px-4 py-3 text-white/38">
                    <span className="flex items-center gap-1">
                      <Clock3 className="size-3" />{' '}
                      {job.completedAt
                        ? relativeTime(job.completedAt, now)
                        : job.leaseExpiresAt
                          ? `expires ${relativeTime(job.leaseExpiresAt, now)}`
                          : relativeTime(job.createdAt, now)}
                    </span>
                    {job.lastError ? (
                      <p className="mt-1 max-w-sm truncate text-[9px] text-red-300/70">
                        {job.lastError}
                      </p>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </section>
      ) : null}
    </>
  );
}
