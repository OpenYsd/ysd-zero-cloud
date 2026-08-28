import Link from 'next/link';
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Bot,
  Box,
  BrainCircuit,
  CheckCircle2,
  Cloud,
  CloudCog,
  Code2,
  Cpu,
  Database,
  FolderClosed,
  Gamepad2,
  Gauge,
  GitBranch,
  Globe2,
  HardDrive,
  KeyRound,
  LockKeyhole,
  Network,
  Plus,
  RefreshCcw,
  Rocket,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  TriangleAlert,
  Users,
  WandSparkles,
  Waypoints,
  Wifi,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { SmartDeployPanel } from '@/components/smart-deploy-panel';
import { getIntegrationCatalog } from '@/lib/integrations';

type Section =
  | 'projects'
  | 'deployments'
  | 'databases'
  | 'storage'
  | 'ai'
  | 'game-servers'
  | 'nodes'
  | 'logs'
  | 'networking'
  | 'secrets'
  | 'usage'
  | 'shield'
  | 'settings';

const pageMeta: Record<Section, { title: string; eyebrow: string; description: string }> = {
  projects: { title: 'Projects', eyebrow: 'Workspace', description: 'Applications, environments, and connected repositories.' },
  deployments: { title: 'Deployments', eyebrow: 'Delivery', description: 'Build, verify, and ship across your connected providers.' },
  databases: { title: 'Databases', eyebrow: 'Data', description: 'Managed data surfaces with direct studio and SQL access.' },
  storage: { title: 'Storage', eyebrow: 'Data', description: 'Buckets and objects across zero-cost storage providers.' },
  ai: { title: 'AI', eyebrow: 'Intelligence', description: 'Models, inference endpoints, prompts, and usage controls.' },
  'game-servers': { title: 'Game Servers', eyebrow: 'Compute', description: 'Create and monitor community game infrastructure.' },
  nodes: { title: 'Nodes', eyebrow: 'Compute', description: 'Bring your own machine and share safe spare capacity.' },
  logs: { title: 'Logs', eyebrow: 'Observability', description: 'Search live runtime, build, audit, and security events.' },
  networking: { title: 'Networking', eyebrow: 'Edge', description: 'Domains, routes, tunnels, and traffic health.' },
  secrets: { title: 'Secrets', eyebrow: 'Security', description: 'Encrypted configuration shared safely with workloads.' },
  usage: { title: 'Usage', eyebrow: 'Limits', description: 'Free-tier consumption and projected monthly cost.' },
  shield: { title: 'YSD Shield', eyebrow: 'Security Center', description: 'One security posture across code, cloud, and connected nodes.' },
  settings: { title: 'Settings', eyebrow: 'Workspace', description: 'Workspace defaults, integrations, and team controls.' },
};

export function isSection(value: string): value is Section {
  return value in pageMeta;
}

export function SectionDashboard({ section }: { section: Section }) {
  const meta = pageMeta[section];
  return (
    <div className="mx-auto w-full max-w-[1440px] space-y-5">
      <PageHeader {...meta} section={section} />
      {section === 'projects' && <ProjectsView />}
      {section === 'deployments' && <DeploymentsView />}
      {section === 'databases' && <DatabasesView />}
      {section === 'storage' && <StorageView />}
      {section === 'ai' && <AIView />}
      {section === 'game-servers' && <GameServersView />}
      {section === 'nodes' && <NodesView />}
      {section === 'logs' && <LogsView />}
      {section === 'networking' && <NetworkingView />}
      {section === 'secrets' && <SecretsView />}
      {section === 'usage' && <UsageView />}
      {section === 'shield' && <ShieldView />}
      {section === 'settings' && <SettingsView />}
    </div>
  );
}

function PageHeader({ title, eyebrow, description, section }: { title: string; eyebrow: string; description: string; section: Section }) {
  const createLabel: Partial<Record<Section, string>> = {
    projects: 'New project', deployments: 'New deployment', databases: 'New database', storage: 'New bucket', ai: 'New endpoint', 'game-servers': 'New server', secrets: 'Add secret', nodes: 'Connect node',
  };
  return (
    <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
      <div><p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-[#b7ff3c]/55">{eyebrow}</p><h1 className="text-2xl font-semibold tracking-[-0.035em] text-white sm:text-[28px]">{title}</h1><p className="mt-1.5 text-xs text-white/34">{description}</p></div>
      {createLabel[section] && <Button className="h-9 self-start bg-[#b7ff3c] px-3.5 text-xs font-semibold text-[#07100c] hover:bg-[#cbff72] sm:self-auto"><Plus /> {createLabel[section]}</Button>}
    </header>
  );
}

const projects = [
  ['ysd-platform', 'Next.js', 'Production', 'Global Edge', 'Live', '3m ago'],
  ['shield-api', 'Node.js', 'Production', 'Riyadh', 'Live', '18m ago'],
  ['playground', 'Vite', 'Preview', 'Frankfurt', 'Building', 'now'],
  ['docs', 'Next.js', 'Production', 'Global Edge', 'Live', '2h ago'],
];

function ProjectsView() {
  return (
    <>
      <MetricGrid items={[[LayersIcon, 'Active', '4', '+1 this month'], [Rocket, 'Deployments', '12', '100% success'], [Users, 'Collaborators', '3', 'across 2 teams'], [Gauge, 'Free capacity', '92%', 'healthy margin']]} />
      <ResourceTable columns={['Project', 'Framework', 'Environment', 'Region', 'Status', 'Updated']} rows={projects} firstIcon={Box} />
    </>
  );
}

function DeploymentsView() {
  const rows = [
    ['dpl_6C44', 'ysd-platform', '8f3c4a1', 'Ready', '42s', '3m ago'],
    ['dpl_6C43', 'shield-api', '17ad31c', 'Ready', '19s', '18m ago'],
    ['dpl_6C42', 'playground', 'a009d82', 'Building', '—', 'now'],
    ['dpl_6C41', 'docs', '17d6ba2', 'Ready', '31s', '2h ago'],
  ];
  return <><SmartDeployPanel /><ResourceTable columns={['Deployment', 'Project', 'Commit', 'State', 'Duration', 'Created']} rows={rows} firstIcon={Rocket} /></>;
}

function DatabasesView() {
  return (
    <>
      <div className="grid gap-4 lg:grid-cols-2">
        <DatabaseCard name="primary-postgres" provider="Supabase" region="eu-central-1" size="82 MB" tables="14" />
        <DatabaseCard name="analytics-sqlite" provider="Cloudflare D1" region="Global" size="16 MB" tables="7" />
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Link href="/databases/studio" className="cloud-card group flex items-center gap-4 p-5"><span className="icon-well icon-well-violet"><Database /></span><span><span className="text-sm font-semibold text-white/80">Open Database Studio</span><span className="mt-1 block text-[11px] text-white/30">Browse tables and edit mock rows.</span></span><ArrowUpRight className="ml-auto size-4 text-white/18 group-hover:text-white/55" /></Link>
        <Link href="/databases/sql-editor" className="cloud-card group flex items-center gap-4 p-5"><span className="icon-well icon-well-lime"><Code2 /></span><span><span className="text-sm font-semibold text-white/80">Open SQL Editor</span><span className="mt-1 block text-[11px] text-white/30">Run queries with structured results.</span></span><ArrowUpRight className="ml-auto size-4 text-white/18 group-hover:text-white/55" /></Link>
      </div>
    </>
  );
}

function DatabaseCard({ name, provider, region, size, tables }: Record<'name' | 'provider' | 'region' | 'size' | 'tables', string>) {
  return (
    <article className="cloud-card p-5"><div className="flex items-start justify-between"><div className="flex items-center gap-3"><span className="icon-well icon-well-violet"><Database /></span><div><h2 className="text-sm font-semibold text-white/82">{name}</h2><p className="mt-1 text-[10px] text-white/28">{provider} · {region}</p></div></div><Badge variant="outline" className="border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]"><span className="size-1 rounded-full bg-[#b7ff3c]" /> Healthy</Badge></div><div className="mt-5 grid grid-cols-3 border-t border-white/[0.06] pt-4 text-xs"><SmallMetric label="Size" value={size} /><SmallMetric label="Tables" value={tables} /><SmallMetric label="Connections" value="4 / 60" /></div></article>
  );
}

function StorageView() {
  return <><MetricGrid items={[[HardDrive, 'Stored', '1.6 GB', 'of 10 GB free'], [FolderClosed, 'Buckets', '3', 'all private'], [ArrowDownRight, 'Egress', '420 MB', 'this month'], [ShieldCheck, 'Encrypted', '100%', 'AES-256']]} /><ResourceTable columns={['Bucket', 'Provider', 'Objects', 'Size', 'Access', 'Updated']} rows={[["app-assets", "Cloudflare R2", "1,842", "1.2 GB", "Public", "7m ago"], ["backups", "Supabase", "28", "386 MB", "Private", "1h ago"], ["game-worlds", "Local node", "6", "41 MB", "Private", "3h ago"]]} firstIcon={FolderClosed} /></>;
}

function AIView() {
  return <><div className="grid gap-4 lg:grid-cols-[1.2fr_.8fr]"><article className="cloud-card p-5"><div className="flex items-center justify-between"><div><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[#9f97ff]">Playground</p><h2 className="mt-1 text-sm font-semibold text-white/80">YSD Assistant</h2></div><Badge variant="outline" className="border-[#7569ff]/20 bg-[#7569ff]/5 text-[#b0aaff]">Mock inference</Badge></div><div className="my-5 rounded-xl border border-white/[0.06] bg-black/15 p-4 text-xs leading-5 text-white/45">Analyze the latest deployment logs and explain any risks before promotion.</div><div className="flex justify-between"><span className="text-[10px] text-white/25">zero-mini · 1,024 context</span><Button size="sm" className="bg-[#7569ff] text-[10px] text-white"><WandSparkles /> Run prompt</Button></div></article><article className="cloud-card p-5"><div className="flex items-center gap-3"><span className="icon-well icon-well-blue"><BrainCircuit /></span><div><h2 className="text-sm font-semibold text-white/80">Inference usage</h2><p className="text-[10px] text-white/28">Free monthly allocation</p></div></div><p className="mt-6 text-3xl font-semibold tracking-[-0.04em] text-white">18,420</p><p className="mt-1 text-[10px] text-white/28">tokens of 1,000,000</p><Progress value={2} className="mt-4 [&_[data-slot=progress-indicator]]:bg-[#4ac7ff] [&_[data-slot=progress-track]]:bg-white/[0.06]" /></article></div><ResourceTable columns={['Endpoint', 'Model', 'Provider', 'Requests', 'Latency', 'State']} rows={[["assistant-api", "zero-mini", "Mock adapter", "126", "82 ms", "Ready"], ["embeddings", "text-embed-small", "Mock adapter", "2,841", "21 ms", "Ready"]]} firstIcon={Bot} /></>;
}

function GameServersView() {
  return <><div className="grid gap-4 xl:grid-cols-3"><GameCard name="YSD Survival" game="Minecraft 1.21" players="8 / 20" memory="2.4 / 4 GB" state="Online" /><GameCard name="Weekend Arena" game="Valheim" players="0 / 10" memory="—" state="Sleeping" /><article className="cloud-card grid min-h-48 place-items-center border-dashed p-6 text-center"><div><span className="mx-auto grid size-10 place-items-center rounded-full border border-white/[0.08] bg-white/[0.025] text-white/35"><Plus /></span><p className="mt-3 text-xs font-semibold text-white/55">Create game server</p><p className="mt-1 text-[10px] text-white/25">Minecraft, Valheim, Terraria, and more.</p></div></article></div><div className="rounded-xl border border-[#b7ff3c]/12 bg-[#b7ff3c]/[0.035] p-4 text-[11px] text-white/42"><Sparkles className="mr-2 inline size-3.5 text-[#b7ff3c]" />Sleep mode pauses idle servers automatically so connected nodes stay within your zero-cost plan.</div></>;
}

function GameCard({ name, game, players, memory, state }: Record<'name' | 'game' | 'players' | 'memory' | 'state', string>) {
  return <article className="cloud-card p-5"><div className="flex items-start justify-between"><span className="icon-well icon-well-lime"><Gamepad2 /></span><Badge variant="outline" className={state === 'Online' ? 'border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]' : 'border-white/[0.08] text-white/35'}>{state}</Badge></div><h2 className="mt-4 text-sm font-semibold text-white/80">{name}</h2><p className="mt-1 text-[10px] text-white/28">{game}</p><div className="mt-5 grid grid-cols-2 border-t border-white/[0.06] pt-4"><SmallMetric label="Players" value={players} /><SmallMetric label="Memory" value={memory} /></div></article>;
}

function NodesView() {
  return <><MetricGrid items={[[Server, 'Connected', '3', '2 online'], [Cpu, 'Shared CPU', '12 cores', '38% active'], [HardDrive, 'Disk pool', '284 GB', '61% free'], [Wifi, 'Network', '42 Mbps', 'stable']]} /><ResourceTable columns={['Node', 'Type', 'Location', 'CPU', 'Memory', 'State']} rows={[["home-lab-01", "Linux · x64", "Riyadh", "4 / 8 cores", "6.2 / 16 GB", "Online"], ["gaming-pc", "Windows · x64", "Jeddah", "2 / 12 cores", "4 / 32 GB", "Online"], ["mini-node", "Linux · arm64", "Dammam", "—", "—", "Offline"]]} firstIcon={Server} /></>;
}

function LogsView() {
  const lines = [
    ['18:24:11.982', 'INFO', 'deployment', 'ysd-platform promoted to production'],
    ['18:24:09.114', 'INFO', 'shield', 'dependency scan completed · 0 critical'],
    ['18:23:58.721', 'WARN', 'database', 'connection pool reached 72% for 4s'],
    ['18:23:42.018', 'INFO', 'edge', 'cache revalidated · /api/projects'],
    ['18:22:18.612', 'INFO', 'node', 'home-lab-01 heartbeat · 41ms'],
    ['18:21:03.220', 'INFO', 'shield', 'secret exposure scan completed'],
  ];
  return <div className="cloud-card overflow-hidden"><div className="flex flex-col justify-between gap-3 border-b border-white/[0.065] p-4 sm:flex-row sm:items-center"><div className="flex gap-2"><div className="relative"><Search className="absolute left-2.5 top-1/2 size-3 -translate-y-1/2 text-white/25" /><Input placeholder="Search logs" className="h-8 w-56 border-white/[0.07] bg-black/10 pl-7 text-[10px]" /></div><Button variant="outline" size="sm" className="border-white/[0.07] text-[10px]"><TerminalSquare /> All sources</Button></div><div className="flex items-center gap-2 text-[10px] text-[#c8ff69]"><span className="size-1.5 animate-pulse rounded-full bg-[#b7ff3c]" /> Live tail</div></div><div className="min-h-[520px] bg-[#080c0a] p-4 font-mono text-[11px] leading-7">{lines.map(([time, level, source, message]) => <div key={time} className="grid grid-cols-[90px_52px_80px_minmax(0,1fr)] border-b border-white/[0.035]"><span className="text-white/18">{time}</span><span className={level === 'WARN' ? 'text-amber-300/70' : 'text-[#b7ff3c]/60'}>{level}</span><span className="text-[#9f97ff]/65">{source}</span><span className="text-white/48">{message}</span></div>)}</div></div>;
}

function NetworkingView() {
  return <><MetricGrid items={[[Globe2, 'Domains', '4', 'all secured'], [Network, 'Routes', '18', 'global edge'], [Waypoints, 'Tunnels', '2', 'healthy'], [Activity, 'Requests', '84.2K', '+12% this week']]} /><ResourceTable columns={['Domain', 'Target', 'Provider', 'TLS', 'Traffic', 'State']} rows={[["zero.ysd.dev", "ysd-platform", "Cloudflare", "Auto", "61.4K", "Active"], ["api.ysd.dev", "shield-api", "Cloudflare", "Auto", "22.8K", "Active"], ["play.ysd.dev", "game tunnel", "YSD Node", "Auto", "—", "Active"]]} firstIcon={Globe2} /></>;
}

function SecretsView() {
  return <><div className="rounded-xl border border-[#4ac7ff]/12 bg-[#4ac7ff]/[0.035] p-4 text-[11px] text-white/42"><LockKeyhole className="mr-2 inline size-3.5 text-[#79d6ff]" />Values are encrypted at rest and never shown again after creation.</div><ResourceTable columns={['Secret', 'Scope', 'Environment', 'Value', 'Updated', 'Rotation']} rows={[["DATABASE_URL", "ysd-platform", "Production", "••••••••••••", "2d ago", "Manual"], ["GITHUB_TOKEN", "Workspace", "All", "••••••••••••", "5d ago", "90 days"], ["SHIELD_SIGNING_KEY", "shield-api", "Production", "••••••••••••", "12d ago", "30 days"]]} firstIcon={KeyRound} /></>;
}

function UsageView() {
  const usage = [['Build minutes', '38 / 500 min', 8, '#b7ff3c'], ['Bandwidth', '1.2 / 100 GB', 2, '#4ac7ff'], ['Database', '82 / 500 MB', 16, '#7569ff'], ['Storage', '1.6 / 10 GB', 16, '#ffb84a'], ['AI tokens', '18.4K / 1M', 2, '#ef78ff']];
  return <><div className="grid gap-4 lg:grid-cols-[1.2fr_.8fr]"><article className="cloud-card p-5"><div className="flex justify-between"><div><h2 className="text-sm font-semibold text-white/80">Free-tier capacity</h2><p className="mt-1 text-[10px] text-white/27">August 2026 · resets in 3 days</p></div><Badge variant="outline" className="border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]">Zero Mode</Badge></div><div className="mt-6 space-y-5">{usage.map(([label, value, percent, color]) => <div key={String(label)}><div className="mb-2 flex justify-between text-[10px]"><span className="text-white/42">{label}</span><span className="font-mono text-white/28">{value}</span></div><Progress value={Number(percent)} className="[&_[data-slot=progress-track]]:bg-white/[0.06]" style={{ '--primary': color } as React.CSSProperties} /></div>)}</div></article><article className="cloud-card p-5"><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-white/28">Projected bill</p><p className="mt-4 text-4xl font-semibold tracking-[-0.05em] text-white">$0.00</p><p className="mt-1 text-[11px] text-[#c8ff69]">No paid resources detected</p><div className="my-6 border-t border-white/[0.06]" /><div className="space-y-3 text-[11px]"><CostRow label="Cloudflare" value="$0.00" /><CostRow label="Supabase" value="$0.00" /><CostRow label="Connected nodes" value="$0.00" /><CostRow label="YSD services" value="$0.00" /></div></article></div></>;
}

function ShieldView() {
  const checks = [['Secrets exposure', 'No exposed credentials', 'Passed'], ['Dependencies', '0 critical · 2 low', 'Passed'], ['Network surface', '3 public routes reviewed', 'Passed'], ['Database policies', '1 table needs RLS review', 'Review']];
  return <><div className="grid gap-4 lg:grid-cols-[.72fr_1.28fr]"><article className="cloud-card relative overflow-hidden p-6"><div className="absolute -right-16 -top-16 size-48 rounded-full bg-[#b7ff3c]/[0.055] blur-3xl" /><div className="relative"><span className="grid size-12 place-items-center rounded-full border border-[#b7ff3c]/18 bg-[#b7ff3c]/8 text-[#b7ff3c]"><ShieldCheck className="size-6" /></span><p className="mt-6 text-5xl font-semibold tracking-[-0.06em] text-white">94</p><p className="mt-1 text-sm font-semibold text-[#c8ff69]">Strong posture</p><p className="mt-3 max-w-xs text-[11px] leading-5 text-white/32">Your workspace is protected. One database policy should be reviewed before the next release.</p><Button className="mt-6 bg-[#b7ff3c] text-xs font-semibold text-[#07100c]"><RefreshCcw /> Run full scan</Button></div></article><article className="cloud-card overflow-hidden"><div className="border-b border-white/[0.065] px-5 py-4"><h2 className="text-sm font-semibold text-white/80">Security checks</h2><p className="mt-1 text-[10px] text-white/27">Last full scan 6 minutes ago</p></div><div className="divide-y divide-white/[0.055]">{checks.map(([name, detail, state]) => <div key={name} className="flex items-center gap-3 px-5 py-4"><span className={state === 'Passed' ? 'grid size-8 place-items-center rounded-lg bg-[#b7ff3c]/6 text-[#b7ff3c]' : 'grid size-8 place-items-center rounded-lg bg-amber-400/6 text-amber-300'}>{state === 'Passed' ? <CheckCircle2 className="size-4" /> : <TriangleAlert className="size-4" />}</span><div><p className="text-xs font-medium text-white/68">{name}</p><p className="mt-1 text-[10px] text-white/27">{detail}</p></div><Badge variant="outline" className={state === 'Passed' ? 'ml-auto border-[#b7ff3c]/12 text-[#c8ff69]' : 'ml-auto border-amber-300/15 text-amber-300'}>{state}</Badge></div>)}</div></article></div><ResourceTable columns={['Finding', 'Resource', 'Severity', 'Status', 'Owner', 'Detected']} rows={[["Enable RLS on profiles_archive", "primary-postgres", "Medium", "Open", "Data", "6m ago"], ["Update vite transitive package", "playground", "Low", "Tracked", "Web", "1d ago"]]} firstIcon={ShieldAlert} /></>;
}

function SettingsView() {
  const integrations = getIntegrationCatalog();
  const iconMap = { github: GitBranch, cloudflare: Cloud, supabase: Database };
  return <div className="grid gap-4 xl:grid-cols-[1fr_1.2fr]"><article className="cloud-card p-5"><h2 className="text-sm font-semibold text-white/80">Workspace defaults</h2><p className="mt-1 text-[10px] text-white/27">Applied to newly created resources.</p><div className="mt-6 space-y-5"><SettingToggle title="Zero Mode" copy="Block every deployment plan with a projected charge." checked /><SettingToggle title="Automatic security scans" copy="Run YSD Shield after deployments and dependency updates." checked /><SettingToggle title="Sleep idle game servers" copy="Pause unused workloads after 15 minutes." checked /><SettingToggle title="Preview deployments" copy="Create a temporary URL for every branch." checked={false} /></div></article><article className="cloud-card overflow-hidden"><div className="border-b border-white/[0.065] px-5 py-4"><h2 className="text-sm font-semibold text-white/80">Integrations</h2><p className="mt-1 text-[10px] text-white/27">Adapters are mock-backed until credentials are configured.</p></div><div className="divide-y divide-white/[0.055]">{integrations.map((integration) => { const Icon = iconMap[integration.id]; return <div key={integration.id} className="flex items-center gap-4 px-5 py-4"><span className="grid size-9 place-items-center rounded-lg border border-white/[0.07] bg-white/[0.03] text-white/48"><Icon className="size-4" /></span><div><p className="text-xs font-semibold text-white/70">{integration.name}</p><p className="mt-1 text-[10px] text-white/27">{integration.purpose}</p></div><Badge variant="outline" className={integration.status === 'configured' ? 'ml-auto border-[#b7ff3c]/15 text-[#c8ff69]' : 'ml-auto border-[#4ac7ff]/15 text-[#79d6ff]'}>{integration.status === 'configured' ? 'Connected' : 'Mock mode'}</Badge><Button variant="outline" size="sm" className="border-white/[0.07] text-[10px]">Configure</Button></div>})}</div></article></div>;
}

function MetricGrid({ items }: { items: [typeof Activity, string, string, string][] }) {
  return <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{items.map(([Icon, label, value, detail], index) => <article key={label} className="cloud-card p-4"><div className={index % 3 === 0 ? 'icon-well icon-well-lime' : index % 3 === 1 ? 'icon-well icon-well-violet' : 'icon-well icon-well-blue'}><Icon className="size-4" /></div><p className="mt-4 text-2xl font-semibold tracking-[-0.04em] text-white">{value}</p><div className="mt-1 flex justify-between text-xs"><span className="text-white/55">{label}</span><span className="text-white/25">{detail}</span></div></article>)}</section>;
}

function ResourceTable({ columns, rows, firstIcon: Icon }: { columns: string[]; rows: string[][]; firstIcon: typeof Activity }) {
  return <section className="cloud-card overflow-hidden"><div className="flex items-center justify-between border-b border-white/[0.065] px-4 py-3"><p className="text-xs font-semibold text-white/60">Resources</p><Button variant="ghost" size="sm" className="text-[10px] text-white/35"><RefreshCcw /> Refresh</Button></div><Table className="text-[11px]"><TableHeader><TableRow className="border-white/[0.06] hover:bg-transparent">{columns.map((column) => <TableHead key={column} className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25">{column}</TableHead>)}</TableRow></TableHeader><TableBody>{rows.map((row) => <TableRow key={row[0]} className="border-white/[0.05] hover:bg-white/[0.02]">{row.map((cell, index) => <TableCell key={`${row[0]}-${index}`} className="px-4 py-3 text-white/42">{index === 0 ? <span className="flex items-center gap-2 font-medium text-white/72"><Icon className="size-3.5 text-[#b7ff3c]/65" />{cell}</span> : index === row.length - 2 && ['Live', 'Ready', 'Active', 'Online', 'Healthy'].includes(cell) ? <Badge variant="outline" className="border-[#b7ff3c]/12 bg-[#b7ff3c]/5 text-[#c8ff69]">{cell}</Badge> : cell}</TableCell>)}</TableRow>)}</TableBody></Table></section>;
}

function SmallMetric({ label, value }: { label: string; value: string }) { return <div><p className="text-[9px] uppercase tracking-[0.1em] text-white/22">{label}</p><p className="mt-1.5 text-xs font-semibold text-white/60">{value}</p></div>; }
function CostRow({ label, value }: { label: string; value: string }) { return <div className="flex justify-between"><span className="text-white/36">{label}</span><span className="font-mono text-white/60">{value}</span></div>; }
function SettingToggle({ title, copy, checked }: { title: string; copy: string; checked: boolean }) { return <div className="flex items-start justify-between gap-4"><div><p className="text-xs font-medium text-white/65">{title}</p><p className="mt-1 max-w-sm text-[10px] leading-4 text-white/27">{copy}</p></div><Switch defaultChecked={checked} aria-label={`Toggle ${title}`} className="data-checked:bg-[#b7ff3c]" /></div>; }
const LayersIcon = CloudCog;
