import { NavLink } from '@/components/nav-link';
import {
  ArrowUpRight,
  Box,
  Check,
  Database,
  Globe2,
  Rocket,
  ShieldCheck,
  Sparkles,
  Zap,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { formatUsage, type UsageReading } from '@/lib/free-tier';
import { money, relativeTime } from '@/lib/format';
import type { Project } from '@/lib/domain';

export type HomeData = {
  operator: string;
  projects: Project[];
  projectCount: number;
  deploymentCount: number;
  tableCount: number;
  readings: UsageReading[];
  projectedMonthlyCost: number;
  shieldScore: number | null;
  zeroMode: boolean;
  now: number;
};

const STATUS_TONE: Record<Project['status'], string> = {
  live: 'border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]',
  building: 'border-[#4ac7ff]/15 bg-[#4ac7ff]/5 text-[#79d6ff]',
  idle: 'border-white/[0.08] text-white/40',
  blocked: 'border-amber-400/20 bg-amber-400/5 text-amber-300',
};

export function HomeDashboard({ data }: { data: HomeData }) {
  const headline = data.readings.slice(0, 3);

  const stats = [
    { label: 'Projects', value: String(data.projectCount), detail: 'in this workspace', icon: Box, tone: 'lime' },
    { label: 'Deployments', value: String(data.deploymentCount), detail: 'plans recorded', icon: Rocket, tone: 'violet' },
    { label: 'Database tables', value: String(data.tableCount), detail: 'on Cloudflare D1', icon: Database, tone: 'blue' },
    {
      label: 'Monthly cost',
      value: money(data.projectedMonthlyCost),
      detail: data.zeroMode ? 'Zero Mode enforced' : 'Zero Mode paused',
      icon: ShieldCheck,
      tone: 'lime',
    },
  ];

  return (
    <div className="mx-auto w-full max-w-[1440px] space-y-6">
      <section className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-white/30">
            <Globe2 className="size-3" /> {data.operator}
          </div>
          <h1 className="text-2xl font-semibold tracking-[-0.035em] text-white sm:text-[28px]">Your cloud, at a glance.</h1>
          <p className="mt-1.5 text-sm text-white/38">
            Every number below is read from your own D1 database, not a sample.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            nativeButton={false}
            variant="outline"
            className="h-9 border-white/[0.08] bg-white/[0.025] text-xs"
            render={<NavLink href="/databases/studio" />}
          >
            <Database /> Open Studio
          </Button>
          <Button
            nativeButton={false}
            className="h-9 bg-[#b7ff3c] px-3.5 text-xs font-semibold text-[#08110d] hover:bg-[#cbff72]"
            render={<NavLink href="/deployments" />}
          >
            <Sparkles /> Smart Deploy
          </Button>
        </div>
      </section>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <article key={stat.label} className="cloud-card group p-4">
              <div className="flex items-start justify-between">
                <div className={stat.tone === 'lime' ? 'icon-well icon-well-lime' : stat.tone === 'violet' ? 'icon-well icon-well-violet' : 'icon-well icon-well-blue'}>
                  <Icon className="size-4" />
                </div>
              </div>
              <p className="mt-4 text-2xl font-semibold tracking-[-0.04em] text-white">{stat.value}</p>
              <div className="mt-1 flex items-center justify-between gap-3 text-xs">
                <span className="text-white/58">{stat.label}</span>
                <span className="text-white/27">{stat.detail}</span>
              </div>
            </article>
          );
        })}
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(300px,.75fr)]">
        <div className="cloud-card overflow-hidden">
          <div className="flex items-center justify-between border-b border-white/[0.065] px-5 py-4">
            <div>
              <h2 className="text-sm font-semibold text-white">Projects</h2>
              <p className="mt-0.5 text-[11px] text-white/28">Recently active environments</p>
            </div>
            <Button nativeButton={false} variant="ghost" size="sm" className="text-[11px] text-white/42" render={<NavLink href="/projects" />}>
              View all <ArrowUpRight />
            </Button>
          </div>

          {data.projects.length === 0 ? (
            <div className="px-5 py-12 text-center">
              <p className="text-xs font-medium text-white/55">No projects yet</p>
              <p className="mx-auto mt-1.5 max-w-xs text-[11px] leading-4 text-white/28">
                Run Smart Deploy on a repository and the project is created for you.
              </p>
              <Button
                nativeButton={false}
                className="mt-4 h-8 bg-[#b7ff3c] text-[11px] font-semibold text-[#07100c]"
                render={<NavLink href="/deployments" />}
              >
                <Sparkles /> Analyze a repository
              </Button>
            </div>
          ) : (
            <div className="divide-y divide-white/[0.055]">
              {data.projects.slice(0, 5).map((project) => (
                <NavLink
                  key={project.id}
                  href="/projects"
                  className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 px-5 py-4 transition-colors hover:bg-white/[0.025] sm:grid-cols-[minmax(0,1fr)_120px_110px_auto]"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-white/[0.07] bg-white/[0.035]">
                      <span className="size-2 rounded-full bg-[#b7ff3c] shadow-[0_0_10px_#b7ff3c]" />
                    </span>
                    <div className="min-w-0">
                      <p className="truncate text-xs font-semibold text-white/85">{project.name}</p>
                      <p className="mt-1 text-[10px] text-white/28">{project.framework}</p>
                    </div>
                  </div>
                  <div className="hidden items-center gap-1.5 text-[11px] text-white/38 sm:flex">
                    <Globe2 className="size-3" /> {project.region}
                  </div>
                  <Badge variant="outline" className={`hidden sm:inline-flex ${STATUS_TONE[project.status]}`}>
                    {project.status}
                  </Badge>
                  <span className="text-[10px] tabular-nums text-white/22">
                    {relativeTime(project.updatedAt, data.now)}
                  </span>
                </NavLink>
              ))}
            </div>
          )}
        </div>

        <div className="cloud-card p-5">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-sm font-semibold text-white">Zero Mode</h2>
              <p className="mt-0.5 text-[11px] text-white/28">
                {data.zeroMode ? 'Cost protection is active' : 'Cost protection is paused'}
              </p>
            </div>
            <div className={`grid size-9 place-items-center rounded-full ${data.zeroMode ? 'bg-[#b7ff3c]/10 text-[#b7ff3c]' : 'bg-amber-400/10 text-amber-300'}`}>
              <ShieldCheck className="size-[18px]" />
            </div>
          </div>

          <div className={`my-5 rounded-xl border p-3.5 ${data.zeroMode ? 'border-[#b7ff3c]/12 bg-[#b7ff3c]/[0.04]' : 'border-amber-400/15 bg-amber-400/[0.04]'}`}>
            <div className={`flex items-center gap-2 text-xs font-semibold ${data.zeroMode ? 'text-[#d6ff92]' : 'text-amber-300'}`}>
              <Check className="size-3.5" /> {data.zeroMode ? 'Paid resources blocked' : 'Charges would be allowed'}
            </div>
            <p className="mt-1.5 text-[10px] leading-4 text-white/32">
              Every deployment plan is checked on the server before a provider can create billable infrastructure.
            </p>
          </div>

          <div className="space-y-3">
            {headline.map((reading) => (
              <div key={reading.id}>
                <div className="mb-1.5 flex justify-between text-[10px]">
                  <span className="text-white/38">{reading.label}</span>
                  <span className={reading.measured ? 'font-mono text-white/28' : 'font-mono text-white/18'}>
                    {formatUsage(reading)}
                  </span>
                </div>
                <Progress
                  value={reading.percent}
                  className="[&_[data-slot=progress-track]]:bg-white/[0.055]"
                  style={{ '--primary': reading.color } as React.CSSProperties}
                />
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <QuickAction icon={Sparkles} title="Smart Deploy" copy="Analyze a repository and record a zero-cost plan." href="/deployments" accent="#b7ff3c" />
        <QuickAction icon={Database} title="Database Studio" copy="Browse the live D1 tables and run guarded SQL." href="/databases/studio" accent="#7569ff" />
        <QuickAction
          icon={ShieldCheck}
          title="YSD Shield"
          copy={data.shieldScore === null ? 'Run the first security scan of this workspace.' : `Posture score ${data.shieldScore} of 100.`}
          href="/shield"
          accent="#4ac7ff"
        />
      </section>
    </div>
  );
}

function QuickAction({
  icon: Icon,
  title,
  copy,
  href,
  accent,
}: {
  icon: typeof Zap;
  title: string;
  copy: string;
  href: string;
  accent: string;
}) {
  return (
    <NavLink href={href} className="cloud-card group flex items-start gap-4 p-4 transition-transform hover:-translate-y-0.5">
      <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-white/[0.07] bg-white/[0.03]" style={{ color: accent }}>
        <Icon className="size-4" />
      </span>
      <span className="min-w-0">
        <span className="flex items-center gap-1.5 text-xs font-semibold text-white/78">
          {title} <ArrowUpRight className="size-3 text-white/20 transition-colors group-hover:text-white/55" />
        </span>
        <span className="mt-1.5 block text-[10px] leading-4 text-white/28">{copy}</span>
      </span>
    </NavLink>
  );
}
