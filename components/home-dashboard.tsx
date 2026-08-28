import Link from 'next/link';
import {
  ArrowUpRight,
  Box,
  Check,
  Database,
  GitBranch,
  Globe2,
  Plus,
  Rocket,
  ShieldCheck,
  Sparkles,
  Zap,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';

const stats = [
  { label: 'Active projects', value: '4', detail: 'of 10 free', icon: Box, tone: 'lime' },
  { label: 'Deployments', value: '12', detail: '3 this week', icon: Rocket, tone: 'violet' },
  { label: 'Databases', value: '2', detail: 'healthy', icon: Database, tone: 'blue' },
  { label: 'Monthly cost', value: '$0.00', detail: 'Zero Mode', icon: ShieldCheck, tone: 'lime' },
];

const projects = [
  { name: 'ysd-platform', framework: 'Next.js', status: 'Live', region: 'Global Edge', updated: '3m ago', color: '#b7ff3c' },
  { name: 'shield-api', framework: 'Node.js', status: 'Live', region: 'Riyadh', updated: '18m ago', color: '#7569ff' },
  { name: 'playground', framework: 'Vite', status: 'Building', region: 'Frankfurt', updated: 'now', color: '#4ac7ff' },
];

export function HomeDashboard() {
  return (
    <div className="mx-auto w-full max-w-[1440px] space-y-6">
      <section className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-white/30">
            <Globe2 className="size-3" /> OpenYsd workspace
          </div>
          <h1 className="text-2xl font-semibold tracking-[-0.035em] text-white sm:text-[28px]">Good evening, YSD.</h1>
          <p className="mt-1.5 text-sm text-white/38">Your cloud is calm, healthy, and still costs zero.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" className="h-9 border-white/[0.08] bg-white/[0.025] text-xs"><GitBranch /> Import repository</Button>
          <Button className="h-9 bg-[#b7ff3c] px-3.5 text-xs font-semibold text-[#08110d] hover:bg-[#cbff72]"><Plus /> New project</Button>
        </div>
      </section>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <article key={stat.label} className="cloud-card group p-4">
              <div className="flex items-start justify-between">
                <div className={stat.tone === 'lime' ? 'icon-well icon-well-lime' : stat.tone === 'violet' ? 'icon-well icon-well-violet' : 'icon-well icon-well-blue'}><Icon className="size-4" /></div>
                <ArrowUpRight className="size-3.5 text-white/15 transition-colors group-hover:text-white/45" />
              </div>
              <p className="mt-4 text-2xl font-semibold tracking-[-0.04em] text-white">{stat.value}</p>
              <div className="mt-1 flex items-center justify-between gap-3 text-xs">
                <span className="text-white/58">{stat.label}</span><span className="text-white/27">{stat.detail}</span>
              </div>
            </article>
          );
        })}
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(300px,.75fr)]">
        <div className="cloud-card overflow-hidden">
          <div className="flex items-center justify-between border-b border-white/[0.065] px-5 py-4">
            <div><h2 className="text-sm font-semibold text-white">Projects</h2><p className="mt-0.5 text-[11px] text-white/28">Recently active environments</p></div>
            <Button nativeButton={false} variant="ghost" size="sm" className="text-[11px] text-white/42" render={<Link href="/projects" />}>View all <ArrowUpRight /></Button>
          </div>
          <div className="divide-y divide-white/[0.055]">
            {projects.map((project) => (
              <Link key={project.name} href="/projects" className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 px-5 py-4 transition-colors hover:bg-white/[0.025] sm:grid-cols-[minmax(0,1fr)_120px_110px_auto]">
                <div className="flex min-w-0 items-center gap-3">
                  <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-white/[0.07] bg-white/[0.035]"><span className="size-2 rounded-full" style={{ background: project.color, boxShadow: `0 0 10px ${project.color}` }} /></span>
                  <div className="min-w-0"><p className="truncate text-xs font-semibold text-white/85">{project.name}</p><p className="mt-1 text-[10px] text-white/28">{project.framework}</p></div>
                </div>
                <div className="hidden items-center gap-1.5 text-[11px] text-white/38 sm:flex"><Globe2 className="size-3" /> {project.region}</div>
                <Badge variant="outline" className={project.status === 'Building' ? 'hidden border-[#4ac7ff]/15 bg-[#4ac7ff]/5 text-[#79d6ff] sm:inline-flex' : 'hidden border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69] sm:inline-flex'}>
                  <span className={project.status === 'Building' ? 'size-1 rounded-full bg-[#4ac7ff]' : 'size-1 rounded-full bg-[#b7ff3c]'} /> {project.status}
                </Badge>
                <span className="text-[10px] tabular-nums text-white/22">{project.updated}</span>
              </Link>
            ))}
          </div>
        </div>

        <div className="cloud-card p-5">
          <div className="flex items-start justify-between">
            <div><h2 className="text-sm font-semibold text-white">Zero Mode</h2><p className="mt-0.5 text-[11px] text-white/28">Cost protection is active</p></div>
            <div className="grid size-9 place-items-center rounded-full bg-[#b7ff3c]/10 text-[#b7ff3c]"><ShieldCheck className="size-[18px]" /></div>
          </div>
          <div className="my-5 rounded-xl border border-[#b7ff3c]/12 bg-[#b7ff3c]/[0.04] p-3.5">
            <div className="flex items-center gap-2 text-xs font-semibold text-[#d6ff92]"><Check className="size-3.5" /> Paid resources blocked</div>
            <p className="mt-1.5 text-[10px] leading-4 text-white/32">Every deployment is checked before a provider can create billable infrastructure.</p>
          </div>
          <div className="space-y-3">
            <UsageMeter label="Build minutes" value="38 / 500" progress={8} />
            <UsageMeter label="Bandwidth" value="1.2 / 100 GB" progress={2} />
            <UsageMeter label="Database" value="82 / 500 MB" progress={16} />
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <QuickAction icon={Sparkles} title="Smart Deploy" copy="Analyze a repository and create a zero-cost deployment plan." href="/deployments" accent="#b7ff3c" />
        <QuickAction icon={Database} title="Database Studio" copy="Browse tables, edit rows, and run SQL from one workspace." href="/databases/studio" accent="#7569ff" />
        <QuickAction icon={ShieldCheck} title="YSD Shield" copy="Scan secrets, dependencies, and exposed cloud surfaces." href="/shield" accent="#4ac7ff" />
      </section>
    </div>
  );
}

function UsageMeter({ label, value, progress }: { label: string; value: string; progress: number }) {
  return (
    <div>
      <div className="mb-1.5 flex justify-between text-[10px]"><span className="text-white/38">{label}</span><span className="font-mono text-white/28">{value}</span></div>
      <Progress value={progress} className="[&_[data-slot=progress-indicator]]:bg-[#b7ff3c] [&_[data-slot=progress-track]]:bg-white/[0.055]" />
    </div>
  );
}

function QuickAction({ icon: Icon, title, copy, href, accent }: { icon: typeof Zap; title: string; copy: string; href: string; accent: string }) {
  return (
    <Link href={href} className="cloud-card group flex items-start gap-4 p-4 transition-transform hover:-translate-y-0.5">
      <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-white/[0.07] bg-white/[0.03]" style={{ color: accent }}><Icon className="size-4" /></span>
      <span className="min-w-0"><span className="flex items-center gap-1.5 text-xs font-semibold text-white/78">{title} <ArrowUpRight className="size-3 text-white/20 transition-colors group-hover:text-white/55" /></span><span className="mt-1.5 block text-[10px] leading-4 text-white/28">{copy}</span></span>
    </Link>
  );
}
