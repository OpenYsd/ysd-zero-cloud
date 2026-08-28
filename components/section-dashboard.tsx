import Link from 'next/link';
import {
  ArrowUpRight,
  Bot,
  Boxes,
  Code2,
  Database,
  Gamepad2,
  Gauge,
  Globe2,
  HardDrive,
  Network,
  Rocket,
  Server,
  Table2,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState, MetricGrid, PreviewNotice, SmallMetric } from '@/components/ui-bits';
import { isSection, SECTIONS, type Deployment, type Section, type TableSummary } from '@/lib/domain';
import { formatBytes, formatUsage, type UsageReading } from '@/lib/free-tier';
import { duration, money, relativeTime } from '@/lib/format';

/**
 * Section surfaces that only render data.
 *
 * The interactive sections live in their own client components; anything that
 * is still a design preview is rendered here behind a `PreviewNotice` so the
 * workspace never presents a mock-up as a measurement.
 */

export { isSection, SECTIONS };
export type { Section };

export const SECTION_META: Record<Section, { title: string; eyebrow: string; description: string }> = {
  projects: { title: 'Projects', eyebrow: 'Workspace', description: 'Applications, environments, and connected repositories.' },
  deployments: { title: 'Deployments', eyebrow: 'Delivery', description: 'Plans analysed and recorded against the cost guard.' },
  databases: { title: 'Databases', eyebrow: 'Data', description: 'Your Cloudflare D1 database, with Studio and SQL access.' },
  storage: { title: 'Storage', eyebrow: 'Data', description: 'Buckets and objects across zero-cost storage providers.' },
  ai: { title: 'AI', eyebrow: 'Intelligence', description: 'Models, inference endpoints, prompts, and usage controls.' },
  'game-servers': { title: 'Game Servers', eyebrow: 'Compute', description: 'Create and monitor community game infrastructure.' },
  nodes: { title: 'Nodes', eyebrow: 'Compute', description: 'Bring your own machine and share safe spare capacity.' },
  logs: { title: 'Logs', eyebrow: 'Observability', description: 'Every action this workspace has taken.' },
  networking: { title: 'Networking', eyebrow: 'Edge', description: 'Domains, routes, tunnels, and traffic health.' },
  secrets: { title: 'Secrets', eyebrow: 'Security', description: 'Encrypted configuration shared safely with workloads.' },
  usage: { title: 'Usage', eyebrow: 'Limits', description: 'Measured free-tier consumption and projected cost.' },
  shield: { title: 'YSD Shield', eyebrow: 'Security Center', description: 'One security posture across identity, data, and cost.' },
  settings: { title: 'Settings', eyebrow: 'Workspace', description: 'Workspace defaults and integration configuration.' },
};

export function DeploymentsList({ deployments, now }: { deployments: Deployment[]; now: number }) {
  if (deployments.length === 0) {
    return (
      <EmptyState
        title="No deployment plans yet"
        copy="Analyse a repository above. Both accepted and blocked plans are recorded, so the history shows what the cost guard refused as well as what it allowed."
      />
    );
  }

  return (
    <section className="cloud-card overflow-hidden">
      <Table className="text-[11px]">
        <TableHeader>
          <TableRow className="border-white/[0.06] hover:bg-transparent">
            {['Deployment', 'Repository', 'Commit', 'Target', 'State', 'Estimate', 'Took', 'Created'].map((column) => (
              <TableHead key={column} className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25">
                {column}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {deployments.map((deployment) => (
            <TableRow key={deployment.id} className="border-white/[0.05] hover:bg-white/[0.02]">
              <TableCell className="px-4 py-3">
                <span className="flex items-center gap-2 font-mono font-medium text-white/72">
                  <Rocket className="size-3.5 text-[#b7ff3c]/65" />
                  {deployment.id}
                </span>
              </TableCell>
              <TableCell className="px-4 py-3 text-white/42">{deployment.repository}</TableCell>
              <TableCell className="px-4 py-3 font-mono text-[10px] text-white/35">{deployment.commitSha}</TableCell>
              <TableCell className="px-4 py-3 text-white/42">{deployment.target}</TableCell>
              <TableCell className="px-4 py-3">
                <Badge
                  variant="outline"
                  className={
                    deployment.state === 'planned'
                      ? 'border-[#b7ff3c]/12 bg-[#b7ff3c]/5 text-[#c8ff69]'
                      : 'border-amber-400/20 bg-amber-400/5 text-amber-300'
                  }
                >
                  {deployment.state}
                </Badge>
              </TableCell>
              <TableCell className="px-4 py-3 font-mono text-white/42">
                {money(deployment.estimatedMonthlyCost)}
              </TableCell>
              <TableCell className="px-4 py-3 text-white/42">{duration(deployment.durationMs)}</TableCell>
              <TableCell className="px-4 py-3 text-white/42">{relativeTime(deployment.createdAt, now)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </section>
  );
}

export function DatabasesOverview({
  tables,
  bytes,
  limitBytes,
}: {
  tables: TableSummary[];
  /** `null` when Cloudflare has not been asked for the figure. */
  bytes: number | null;
  limitBytes: number;
}) {
  const rows = tables.reduce((total, table) => total + table.rows, 0);

  return (
    <>
      <article className="cloud-card p-5">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <span className="icon-well icon-well-violet">
              <Database />
            </span>
            <div>
              <h2 className="text-sm font-semibold text-white/82">ysd-zero-cloud</h2>
              <p className="mt-1 text-[10px] text-white/28">Cloudflare D1 · binding DB · Global</p>
            </div>
          </div>
          <Badge variant="outline" className="border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]">
            <span className="size-1 rounded-full bg-[#b7ff3c]" /> Healthy
          </Badge>
        </div>
        <div className="mt-5 grid grid-cols-2 gap-4 border-t border-white/[0.06] pt-4 text-xs sm:grid-cols-4">
          <SmallMetric label="Size" value={bytes === null ? 'not reported' : formatBytes(bytes)} />
          <SmallMetric label="Tables" value={String(tables.length)} />
          <SmallMetric label="Rows" value={rows.toLocaleString('en-US')} />
          <SmallMetric label="Free storage" value={formatBytes(limitBytes)} />
        </div>
      </article>

      <div className="grid gap-4 sm:grid-cols-2">
        <Link href="/databases/studio" className="cloud-card group flex items-center gap-4 p-5">
          <span className="icon-well icon-well-violet">
            <Table2 />
          </span>
          <span>
            <span className="text-sm font-semibold text-white/80">Open Database Studio</span>
            <span className="mt-1 block text-[11px] text-white/30">Browse live tables with credentials masked.</span>
          </span>
          <ArrowUpRight className="ml-auto size-4 text-white/18 group-hover:text-white/55" />
        </Link>
        <Link href="/databases/sql-editor" className="cloud-card group flex items-center gap-4 p-5">
          <span className="icon-well icon-well-lime">
            <Code2 />
          </span>
          <span>
            <span className="text-sm font-semibold text-white/80">Open SQL Editor</span>
            <span className="mt-1 block text-[11px] text-white/30">Run guarded statements against D1.</span>
          </span>
          <ArrowUpRight className="ml-auto size-4 text-white/18 group-hover:text-white/55" />
        </Link>
      </div>

      <section className="cloud-card overflow-hidden">
        <div className="border-b border-white/[0.065] px-5 py-4">
          <h2 className="text-sm font-semibold text-white/80">Tables</h2>
          <p className="mt-1 text-[10px] text-white/27">Read live from the database schema.</p>
        </div>
        <Table className="text-[11px]">
          <TableHeader>
            <TableRow className="border-white/[0.06] hover:bg-transparent">
              {['Table', 'Owner', 'Rows', 'Columns', 'Primary key', 'Redaction'].map((column) => (
                <TableHead key={column} className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25">
                  {column}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {tables.map((table) => (
              <TableRow key={table.name} className="border-white/[0.05] hover:bg-white/[0.02]">
                <TableCell className="px-4 py-3">
                  <span className="flex items-center gap-2 font-mono font-medium text-white/72">
                    <Table2 className="size-3.5 text-[#7569ff]/70" />
                    {table.name}
                  </span>
                </TableCell>
                <TableCell className="px-4 py-3 text-white/42">{table.kind}</TableCell>
                <TableCell className="px-4 py-3 font-mono text-white/42">{table.rows.toLocaleString('en-US')}</TableCell>
                <TableCell className="px-4 py-3 font-mono text-white/42">{table.columns}</TableCell>
                <TableCell className="px-4 py-3">
                  {table.hasPrimaryKey ? (
                    <span className="text-white/42">yes</span>
                  ) : (
                    <Badge variant="outline" className="border-amber-400/20 text-amber-300">missing</Badge>
                  )}
                </TableCell>
                <TableCell className="px-4 py-3 text-white/42">{table.masked ? 'masked columns' : '—'}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </section>
    </>
  );
}

export function UsageView({
  readings,
  projectedCost,
  zeroMode,
  measuredAt,
  now,
}: {
  readings: UsageReading[];
  projectedCost: number;
  zeroMode: boolean;
  measuredAt: number;
  now: number;
}) {
  return (
    <div className="grid gap-4 lg:grid-cols-[1.2fr_.8fr]">
      <article className="cloud-card p-5">
        <div className="flex justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white/80">Free-tier capacity</h2>
            <p className="mt-1 text-[10px] text-white/27">Measured {relativeTime(measuredAt, now)}</p>
          </div>
          <Badge
            variant="outline"
            className={
              zeroMode
                ? 'border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]'
                : 'border-amber-400/20 bg-amber-400/5 text-amber-300'
            }
          >
            {zeroMode ? 'Zero Mode' : 'Guard paused'}
          </Badge>
        </div>
        <div className="mt-6 space-y-5">
          {readings.map((reading) => (
            <div key={reading.id}>
              <div className="mb-2 flex justify-between text-[10px]">
                <span className="text-white/42">
                  {reading.label} <span className="text-white/22">· {reading.provider}</span>
                </span>
                <span className={reading.measured ? 'font-mono text-white/28' : 'font-mono text-white/18'}>
                  {formatUsage(reading)}
                </span>
              </div>
              <Progress
                value={reading.percent}
                className="[&_[data-slot=progress-track]]:bg-white/[0.06]"
                style={{ '--primary': reading.color } as React.CSSProperties}
              />
            </div>
          ))}
        </div>
      </article>

      <article className="cloud-card p-5">
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-white/28">Projected bill</p>
        <p className="mt-4 text-4xl font-semibold tracking-[-0.05em] text-white">{money(projectedCost)}</p>
        <p className="mt-1 text-[11px] text-[#c8ff69]">
          {Number.isFinite(projectedCost)
            ? 'Every measured resource is inside a free allowance'
            : 'A free allowance has been exceeded'}
        </p>
        <div className="my-6 border-t border-white/[0.06]" />
        <div className="space-y-3 text-[11px]">
          {[...new Set(readings.map((reading) => reading.provider))].map((provider) => (
            <div key={provider} className="flex justify-between">
              <span className="text-white/36">{provider}</span>
              <span className="font-mono text-white/60">$0.00</span>
            </div>
          ))}
        </div>
        <p className="mt-6 text-[10px] leading-4 text-white/25">
          This workspace has no billing relationship with any provider. There is nothing to upgrade and
          no plan to exceed — the guard simply stops at the free ceiling.
        </p>
      </article>
    </div>
  );
}

const PREVIEW_COPY: Partial<Record<Section, { note: string; metrics: Parameters<typeof MetricGrid>[0]['items'] }>> = {
  storage: {
    note: 'Storage is designed but not yet wired to R2. The numbers below are placeholders, not measurements — enable the R2 binding in .openai/hosting.json to bring this surface online.',
    metrics: [
      { icon: HardDrive, label: 'Stored', value: '—', detail: 'of 10 GB free' },
      { icon: Boxes, label: 'Buckets', value: '—', detail: 'not provisioned' },
      { icon: Globe2, label: 'Egress', value: '—', detail: 'free on R2' },
      { icon: Gauge, label: 'Encrypted', value: '100%', detail: 'AES-256 by default' },
    ],
  },
  ai: {
    note: 'The AI surface is designed but not yet connected to an inference provider. No model is being called and no tokens are being spent.',
    metrics: [
      { icon: Bot, label: 'Endpoints', value: '—', detail: 'none configured' },
      { icon: Gauge, label: 'Requests', value: '—', detail: 'no traffic' },
      { icon: Network, label: 'Latency', value: '—', detail: 'no samples' },
      { icon: Boxes, label: 'Models', value: '—', detail: 'awaiting adapter' },
    ],
  },
  'game-servers': {
    note: 'Game servers need a long-running host, which a Worker cannot provide. This surface is a design preview until the connected-node runtime lands.',
    metrics: [
      { icon: Gamepad2, label: 'Servers', value: '—', detail: 'none running' },
      { icon: Server, label: 'Players', value: '—', detail: 'no sessions' },
      { icon: HardDrive, label: 'Memory', value: '—', detail: 'not allocated' },
      { icon: Gauge, label: 'Idle sleep', value: 'On', detail: 'workspace default' },
    ],
  },
  nodes: {
    note: 'Bring-your-own nodes need an agent to check in. Nothing is connected, so no capacity is being shared.',
    metrics: [
      { icon: Server, label: 'Connected', value: '—', detail: 'no agents' },
      { icon: Boxes, label: 'Shared CPU', value: '—', detail: 'not pooled' },
      { icon: HardDrive, label: 'Disk pool', value: '—', detail: 'not pooled' },
      { icon: Network, label: 'Network', value: '—', detail: 'no heartbeat' },
    ],
  },
  networking: {
    note: 'Domains and routes are managed in the Cloudflare dashboard for now. Adding CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID will let this surface read them.',
    metrics: [
      { icon: Globe2, label: 'Domains', value: '—', detail: 'needs API token' },
      { icon: Network, label: 'Routes', value: '—', detail: 'needs API token' },
      { icon: Boxes, label: 'Tunnels', value: '—', detail: 'needs API token' },
      { icon: Gauge, label: 'Requests', value: '—', detail: 'needs API token' },
    ],
  },
};

/** Renders a section that is still a design preview, clearly labelled as one. */
export function PreviewSection({ section }: { section: Section }) {
  const preview = PREVIEW_COPY[section];
  if (!preview) return <PreviewNotice>This surface is not connected to live data yet.</PreviewNotice>;

  return (
    <>
      <PreviewNotice>{preview.note}</PreviewNotice>
      <MetricGrid items={preview.metrics} />
    </>
  );
}
