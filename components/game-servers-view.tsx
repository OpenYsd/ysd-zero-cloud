'use client';

import { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Archive,
  CircleStop,
  Cpu,
  Gamepad2,
  HardDrive,
  Loader2,
  Play,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Users,
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
import {
  DEFAULT_MINECRAFT_PROPERTIES,
  MINECRAFT_VERSIONS,
  type MinecraftProperties,
} from '@/lib/game-servers';
import type {
  GameServer,
  GameServerAction,
  GameServersState,
} from '@/lib/domain';
import { formatBytes } from '@/lib/free-tier';
import { duration, relativeTime } from '@/lib/format';
import { cn } from '@/lib/utils';

const SELECT_CLASS =
  'h-9 rounded-md border border-white/[0.08] bg-[#0a0f0d] px-3 text-xs text-white/60 outline-none focus:border-[#b7ff3c]/35';

function statusClass(status: GameServer['status']): string {
  if (status === 'running') return 'border-[#b7ff3c]/20 text-[#c8ff69]';
  if (status === 'stopped') return 'border-white/10 text-white/45';
  if (
    status === 'error' ||
    status === 'crashed' ||
    status === 'crash_loop' ||
    status === 'node_revoked'
  ) {
    return 'border-red-300/20 text-red-200';
  }
  return 'border-amber-300/20 text-amber-200';
}

function actionClass(state: GameServerAction['state']): string {
  if (state === 'succeeded') return 'text-[#c8ff69]';
  if (state === 'failed' || state === 'timed_out') return 'text-red-300';
  if (state === 'cancelled') return 'text-amber-200';
  return 'text-violet-300';
}

export function GameServersView({
  state,
  now,
}: {
  state: GameServersState;
  now: number;
}) {
  const router = useRouter();
  const availableNodes = state.nodes.filter(
    (node) =>
      node.status === 'online' &&
      node.capabilities.gameServers.minecraftJavaAvailable,
  );
  const [selectedId, setSelectedId] = useState(state.servers[0]?.id ?? '');
  const selected = state.servers.find((server) => server.id === selectedId) ?? null;
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('YSD Vanilla');
  const [nodeId, setNodeId] = useState(availableNodes[0]?.id ?? '');
  const [version, setVersion] = useState<string>(
    MINECRAFT_VERSIONS.find((entry) => entry.current)?.id ?? MINECRAFT_VERSIONS[0].id,
  );
  const [ramMb, setRamMb] = useState('2048');
  const [cpuCores, setCpuCores] = useState('2');
  const [diskGiB, setDiskGiB] = useState('8');
  const [port, setPort] = useState('25565');
  const [eulaAccepted, setEulaAccepted] = useState(false);
  const [properties, setProperties] = useState<MinecraftProperties>(
    state.servers[0]
      ? { ...state.servers[0].config }
      : { ...DEFAULT_MINECRAFT_PROPERTIES },
  );
  const [configPort, setConfigPort] = useState(
    String(state.servers[0]?.port ?? 25565),
  );
  const [player, setPlayer] = useState('');
  const [backupName, setBackupName] = useState('Before maintenance');

  const selectedActions = useMemo(
    () => state.actions.filter((action) => action.serverId === selectedId),
    [selectedId, state.actions],
  );
  const selectedBackups = useMemo(
    () => state.backups.filter((backup) => backup.serverId === selectedId),
    [selectedId, state.backups],
  );
  const selectedLogs = useMemo(
    () => state.logs.filter((log) => log.serverId === selectedId),
    [selectedId, state.logs],
  );

  async function post(url: string, body: Record<string, unknown>, key: string) {
    setPending(key);
    setError(null);
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': crypto.randomUUID(),
        },
        body: JSON.stringify(body),
      });
      const value = (await response.json()) as { error?: string; serverId?: string };
      if (!response.ok) throw new Error(value.error ?? 'The Game Server action was refused.');
      if (value.serverId) setSelectedId(value.serverId);
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The Game Server action failed.');
    } finally {
      setPending(null);
    }
  }

  function createServer() {
    void post(
      '/api/game-servers',
      {
        action: 'create',
        nodeId: nodeId || null,
        name,
        version,
        ramMb: Number(ramMb),
        cpuCores: Number(cpuCores),
        diskQuotaBytes: Number(diskGiB) * 1024 ** 3,
        port: Number(port),
        properties,
        eulaAccepted,
        provider: 'local-node',
        zeroMode: true,
        exposure: 'private',
      },
      'create',
    );
  }

  function serverAction(action: string, extra: Record<string, unknown> = {}) {
    if (!selected) return;
    void post(
      `/api/game-servers/${selected.id}/actions`,
      { action, provider: 'local-node', zeroMode: true, ...extra },
      `${action}:${selected.id}`,
    );
  }

  return (
    <>
      <div className="flex items-start gap-3 rounded-xl border border-[#b7ff3c]/15 bg-[#b7ff3c]/[0.04] p-4 text-[11px] leading-5 text-white/45">
        <ShieldCheck className="mt-0.5 size-4 shrink-0 text-[#b7ff3c]" />
        <div>
          <p className="font-semibold text-[#d9ffa1]">Private local execution, enforced</p>
          <p className="mt-1">
            Vanilla Minecraft runs only on a user-owned outbound-only node. The
            agent uses a fixed Java invocation, verified Mojang metadata, a
            per-server sandbox, bounded actions, and localhost binding. YSD never
            opens router ports, UPnP, tunnels, RCON, or a paid fallback.
          </p>
        </div>
      </div>

      <MetricGrid
        items={[
          {
            icon: Gamepad2,
            label: 'Servers',
            value: state.summary.total.toLocaleString('en-US'),
            detail: `${state.summary.running} running · ${state.summary.attention} attention`,
          },
          {
            icon: Users,
            label: 'Players',
            value: state.summary.players.toLocaleString('en-US'),
            detail: 'workspace-scoped',
          },
          {
            icon: Cpu,
            label: 'Allocated RAM',
            value: `${state.summary.allocatedRamMb.toLocaleString('en-US')} MB`,
            detail: `${availableNodes.length} ready node${availableNodes.length === 1 ? '' : 's'}`,
          },
          {
            icon: HardDrive,
            label: 'Local backups',
            value: formatBytes(state.summary.localBackupBytes),
            detail: '$0.00 · no R2',
          },
        ]}
      />

      <section className="cloud-card p-5">
        <div className="flex items-center gap-2">
          <Gamepad2 className="size-4 text-[#b7ff3c]" />
          <h2 className="text-sm font-semibold text-white/80">Create private Vanilla server</h2>
        </div>
        <p className="mt-2 text-[10px] leading-4 text-white/30">
          Provisioning downloads only an allowlisted release through Mojang&apos;s
          signed metadata chain. It starts stopped and binds to 127.0.0.1.
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Input aria-label="Server name" value={name} maxLength={64} onChange={(event) => setName(event.target.value)} />
          <select aria-label="Game server node" value={nodeId} onChange={(event) => setNodeId(event.target.value)} className={SELECT_CLASS}>
            <option value="">Automatic safe placement</option>
            {availableNodes.map((node) => (
              <option key={node.id} value={node.id}>{node.name} · {node.capabilities.gameServers.javaVersion ?? 'Java'}</option>
            ))}
          </select>
          <select aria-label="Minecraft version" value={version} onChange={(event) => setVersion(event.target.value)} className={SELECT_CLASS}>
            {MINECRAFT_VERSIONS.map((entry) => (
              <option key={entry.id} value={entry.id}>{entry.label}{entry.current ? ' · current' : ''}</option>
            ))}
          </select>
          <Input aria-label="Private Minecraft port" type="number" min={1024} max={65535} value={port} onChange={(event) => setPort(event.target.value)} />
          <Input aria-label="RAM megabytes" type="number" min={1024} max={32768} step={256} value={ramMb} onChange={(event) => setRamMb(event.target.value)} />
          <Input aria-label="CPU cores" type="number" min={1} max={32} value={cpuCores} onChange={(event) => setCpuCores(event.target.value)} />
          <Input aria-label="Disk quota GiB" type="number" min={2} max={64} value={diskGiB} onChange={(event) => setDiskGiB(event.target.value)} />
          <label className="flex items-center gap-2 rounded-md border border-white/[0.08] px-3 text-[10px] text-white/45">
            <input type="checkbox" checked={eulaAccepted} onChange={(event) => setEulaAccepted(event.target.checked)} className="accent-[#b7ff3c]" />
            I accept the Minecraft EULA
          </label>
        </div>
        <div className="mt-4 flex items-center justify-between gap-3">
          <p className="text-[10px] text-white/25">Private exposure · online-mode on · whitelist on</p>
          <Button disabled={!name.trim() || !eulaAccepted || Boolean(pending)} onClick={createServer} className="bg-[#b7ff3c] text-[#07100c] hover:bg-[#cbff72]">
            {pending === 'create' ? <Loader2 className="animate-spin" /> : <Play />}
            Provision locally
          </Button>
        </div>
        {error ? <p role="alert" className="mt-4 text-[11px] text-red-300">{error}</p> : null}
      </section>

      {state.servers.length === 0 ? (
        <EmptyState title="No local Game Servers yet" copy="Pair a node with Java, accept the Minecraft EULA, and provision an allowlisted Vanilla release above." />
      ) : (
        <section className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
          {state.servers.map((server) => (
            <button
              type="button"
              key={server.id}
              onClick={() => {
                setSelectedId(server.id);
                setProperties({ ...server.config });
                setConfigPort(String(server.port));
              }}
              className={cn('cloud-card p-4 text-left transition-colors', selectedId === server.id && 'border-[#b7ff3c]/25 bg-[#b7ff3c]/[0.025]')}
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-xs font-semibold text-white/72">{server.name}</p>
                  <p className="mt-1 font-mono text-[9px] text-white/24">{server.id}</p>
                </div>
                <Badge variant="outline" className={statusClass(server.status)}>{server.status.replace('_', ' ')}</Badge>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-2 text-[10px] text-white/36">
                <p>{server.version} · Vanilla</p>
                <p>{server.nodeName}</p>
                <p>{server.ramMb} MB · {server.cpuCores} CPU</p>
                <p>{server.playerCount} / {server.config.maxPlayers} players</p>
                <p>127.0.0.1:{server.port}</p>
                <p>{duration(server.uptimeSeconds * 1000)} uptime</p>
              </div>
              {server.lastError ? <p className="mt-3 line-clamp-2 text-[10px] text-red-300/75">{server.lastError}</p> : null}
            </button>
          ))}
        </section>
      )}

      {selected ? (
        <>
          <section className="cloud-card p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-white/80">{selected.name} lifecycle</h2>
                <p className="mt-1 text-[10px] text-white/28">Signed jobs · one-shot leases · replay protected · no console</p>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" disabled={Boolean(pending)} onClick={() => serverAction('start')}><Play /> Start</Button>
                <Button size="sm" variant="outline" disabled={Boolean(pending)} onClick={() => serverAction('stop')}><CircleStop /> Stop</Button>
                <Button size="sm" variant="outline" disabled={Boolean(pending)} onClick={() => serverAction('restart')}><RefreshCw /> Restart</Button>
                <Button size="sm" variant="outline" disabled={Boolean(pending)} onClick={() => serverAction('status')}><RefreshCw /> Status</Button>
                <Button
                  size="sm"
                  variant="destructive"
                  disabled={Boolean(pending)}
                  onClick={() => {
                    if (window.confirm(`Delete ${selected.name} and all local worlds/backups? This cannot be undone.`)) serverAction('delete', { confirmDelete: true });
                  }}
                ><Trash2 /> Delete</Button>
              </div>
            </div>
          </section>

          <div className="grid gap-4 xl:grid-cols-2">
            <section className="cloud-card p-5">
              <h2 className="text-sm font-semibold text-white/80">Safe server.properties</h2>
              <p className="mt-1 text-[10px] text-white/28">Stop first. Only these reviewed fields are accepted.</p>
              <div className="mt-4 grid grid-cols-2 gap-3">
                <Input aria-label="Configured private port" type="number" min={1024} max={65535} value={configPort} onChange={(event) => setConfigPort(event.target.value)} />
                <Input aria-label="Maximum players" type="number" min={1} max={500} value={properties.maxPlayers} onChange={(event) => setProperties((value) => ({ ...value, maxPlayers: Number(event.target.value) }))} />
                <select aria-label="Difficulty" value={properties.difficulty} onChange={(event) => setProperties((value) => ({ ...value, difficulty: event.target.value as MinecraftProperties['difficulty'] }))} className={SELECT_CLASS}>
                  {['peaceful', 'easy', 'normal', 'hard'].map((value) => <option key={value}>{value}</option>)}
                </select>
                <select aria-label="Game mode" value={properties.gamemode} onChange={(event) => setProperties((value) => ({ ...value, gamemode: event.target.value as MinecraftProperties['gamemode'] }))} className={SELECT_CLASS}>
                  {['survival', 'creative', 'adventure', 'spectator'].map((value) => <option key={value}>{value}</option>)}
                </select>
                <Input aria-label="View distance" type="number" min={2} max={32} value={properties.viewDistance} onChange={(event) => setProperties((value) => ({ ...value, viewDistance: Number(event.target.value) }))} />
                <Input aria-label="Simulation distance" type="number" min={2} max={32} value={properties.simulationDistance} onChange={(event) => setProperties((value) => ({ ...value, simulationDistance: Number(event.target.value) }))} />
                <Input aria-label="Server MOTD" className="col-span-2" value={properties.motd} maxLength={100} onChange={(event) => setProperties((value) => ({ ...value, motd: event.target.value }))} />
                <label className="flex items-center gap-2 text-[10px] text-white/45"><input type="checkbox" checked={properties.onlineMode} onChange={(event) => setProperties((value) => ({ ...value, onlineMode: event.target.checked }))} className="accent-[#b7ff3c]" /> online-mode</label>
                <label className="flex items-center gap-2 text-[10px] text-white/45"><input type="checkbox" checked={properties.whitelist} onChange={(event) => setProperties((value) => ({ ...value, whitelist: event.target.checked, enforceWhitelist: event.target.checked }))} className="accent-[#b7ff3c]" /> whitelist enforced</label>
              </div>
              <Button className="mt-4" variant="outline" disabled={selected.status !== 'stopped' || Boolean(pending)} onClick={() => serverAction('config-update', { port: Number(configPort), properties })}>Save reviewed config</Button>
            </section>

            <section className="cloud-card p-5">
              <h2 className="text-sm font-semibold text-white/80">Players</h2>
              <p className="mt-1 text-[10px] text-white/28">Fixed list/kick/whitelist/op actions only. No generic console or RCON.</p>
              <Input aria-label="Minecraft player name" className="mt-4" value={player} maxLength={16} onChange={(event) => setPlayer(event.target.value)} />
              <div className="mt-3 flex flex-wrap gap-2">
                <Button size="sm" variant="outline" onClick={() => serverAction('player-list')}>List</Button>
                <Button size="sm" variant="outline" disabled={!player} onClick={() => serverAction('player-kick', { player })}>Kick</Button>
                <Button size="sm" variant="outline" disabled={!player} onClick={() => serverAction('whitelist-add', { player })}>Whitelist +</Button>
                <Button size="sm" variant="outline" disabled={!player} onClick={() => serverAction('whitelist-remove', { player })}>Whitelist −</Button>
                <Button size="sm" variant="outline" disabled={!player} onClick={() => serverAction('op', { player })}>Op</Button>
                <Button size="sm" variant="outline" disabled={!player} onClick={() => serverAction('deop', { player })}>Deop</Button>
              </div>
              <div className="mt-4 flex flex-wrap gap-2">
                {selected.players.length > 0 ? selected.players.map((entry) => <Badge key={entry} variant="outline">{entry}</Badge>) : <p className="text-[10px] text-white/25">No players reported.</p>}
              </div>
            </section>
          </div>

          <section className="cloud-card p-5">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-white/80">Local backups</h2>
                <p className="mt-1 text-[10px] text-white/28">Checksummed world snapshots stay on this node. Restore requires a stopped server and explicit confirmation.</p>
              </div>
              <div className="flex gap-2">
                <Input aria-label="Backup name" value={backupName} maxLength={64} onChange={(event) => setBackupName(event.target.value)} />
                <Button variant="outline" disabled={!backupName.trim() || Boolean(pending)} onClick={() => serverAction('backup-create', { name: backupName })}><Archive /> Create</Button>
              </div>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {selectedBackups.map((backup) => (
                <article key={backup.id} className="rounded-lg border border-white/[0.07] p-3 text-[10px] text-white/38">
                  <div className="flex justify-between gap-2"><p className="font-semibold text-white/65">{backup.name}</p><Badge variant="outline">{backup.state}</Badge></div>
                  <p className="mt-2">{formatBytes(backup.sizeBytes)} · {backup.fileCount} files</p>
                  <p className="mt-1 font-mono text-[9px] text-white/20">{backup.checksum ?? 'verification pending'}</p>
                  <div className="mt-3 flex gap-2">
                    <Button size="sm" variant="outline" disabled={backup.state !== 'ready' || selected.status !== 'stopped'} onClick={() => { if (window.confirm(`Restore ${backup.name}? Current worlds will be replaced after integrity verification.`)) serverAction('backup-restore', { backupId: backup.id, confirmRestore: true }); }}>Restore</Button>
                    <Button size="sm" variant="outline" disabled={backup.state !== 'ready'} onClick={() => { if (window.confirm(`Delete local backup ${backup.name}?`)) serverAction('backup-delete', { backupId: backup.id, confirmDelete: true }); }}>Delete</Button>
                  </div>
                </article>
              ))}
              {selectedBackups.length === 0 ? <p className="text-[10px] text-white/25">No local backups recorded.</p> : null}
            </div>
          </section>

          <div className="grid gap-4 xl:grid-cols-2">
            <section className="cloud-card overflow-hidden">
              <div className="border-b border-white/[0.06] px-5 py-4"><h2 className="text-sm font-semibold text-white/80">Recent actions</h2></div>
              <Table className="text-[10px]">
                <TableHeader><TableRow className="border-white/[0.06] hover:bg-transparent">{['Action', 'State', 'When'].map((column) => <TableHead key={column} className="h-9 px-4 text-[9px] uppercase text-white/25">{column}</TableHead>)}</TableRow></TableHeader>
                <TableBody>{selectedActions.slice(0, 20).map((action) => <TableRow key={action.id} className="border-white/[0.05]"><TableCell className="px-4 py-3 text-white/55">{action.kind}</TableCell><TableCell className={cn('px-4 py-3', actionClass(action.state))}>{action.state}</TableCell><TableCell className="px-4 py-3 text-white/28">{relativeTime(action.createdAt, now)}</TableCell></TableRow>)}</TableBody>
              </Table>
            </section>
            <section className="cloud-card p-5">
              <div className="flex items-center justify-between"><h2 className="text-sm font-semibold text-white/80">Redacted log tail</h2><Button size="sm" variant="outline" onClick={() => serverAction('logs-tail', { lines: 200 })}>Refresh</Button></div>
              <div className="mt-4 max-h-72 space-y-2 overflow-auto font-mono text-[9px] leading-4 text-white/38">
                {selectedLogs.slice(0, 50).map((log) => <p key={log.id}><span className={log.level === 'ERROR' ? 'text-red-300' : log.level === 'WARN' ? 'text-amber-200' : 'text-white/22'}>{log.level}</span> {log.message}</p>)}
                {selectedLogs.length === 0 ? <p className="text-white/20">No bounded log lines reported.</p> : null}
              </div>
            </section>
          </div>
        </>
      ) : null}

      <section className="grid gap-3 md:grid-cols-3">
        {state.nodes.map((node) => (
          <article key={node.id} className="cloud-card p-4">
            <div className="flex items-center justify-between gap-2"><p className="text-xs font-semibold text-white/70">{node.name}</p><Badge variant="outline">{node.status}</Badge></div>
            <div className="mt-3 space-y-1 text-[10px] text-white/35">
              <p>{node.capabilities.gameServers.javaVersion ?? 'Java not detected'}</p>
              <p>{node.capabilities.gameServers.activeServers} / {node.capabilities.gameServers.maxConcurrentServers} active servers</p>
              <p>{formatBytes(node.capabilities.memory.freeBytes)} free RAM</p>
              <p>{formatBytes(node.capabilities.disk.freeBytes)} free disk</p>
            </div>
          </article>
        ))}
      </section>
    </>
  );
}
