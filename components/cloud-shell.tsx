'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Activity,
  Bell,
  Bot,
  Boxes,
  ChevronDown,
  CloudCog,
  Database,
  Gamepad2,
  Gauge,
  HardDrive,
  Home,
  KeyRound,
  Layers3,
  LockKeyhole,
  Network,
  Rocket,
  Search,
  Settings,
  ShieldCheck,
  TerminalSquare,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { ZeroModeProvider, useZeroMode } from '@/components/zero-mode-provider';

const navigation = [
  { label: 'Home', href: '/', icon: Home },
  { label: 'Projects', href: '/projects', icon: Layers3 },
  { label: 'Deployments', href: '/deployments', icon: Rocket },
  { label: 'Databases', href: '/databases', icon: Database },
  { label: 'Storage', href: '/storage', icon: HardDrive },
  { label: 'AI', href: '/ai', icon: Bot },
  { label: 'Game Servers', href: '/game-servers', icon: Gamepad2 },
  { label: 'Nodes', href: '/nodes', icon: Boxes },
  { label: 'Logs', href: '/logs', icon: TerminalSquare },
  { label: 'Networking', href: '/networking', icon: Network },
  { label: 'Secrets', href: '/secrets', icon: KeyRound },
  { label: 'Usage', href: '/usage', icon: Gauge },
  { label: 'YSD Shield', href: '/shield', icon: ShieldCheck },
  { label: 'Settings', href: '/settings', icon: Settings },
];

function BrandMark() {
  return (
    <div className="grid size-8 place-items-center rounded-[10px] bg-[#b7ff3c] text-[#08110d] shadow-[0_0_24px_rgba(183,255,60,.18)]">
      <CloudCog className="size-[18px]" strokeWidth={2.4} />
    </div>
  );
}

export function CloudShell({ children }: { children: React.ReactNode }) {
  return (
    <ZeroModeProvider>
      <CloudShellFrame>{children}</CloudShellFrame>
    </ZeroModeProvider>
  );
}

function CloudShellFrame({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const zeroMode = useZeroMode();

  return (
    <div className="min-h-screen bg-background text-foreground">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[244px] border-r border-white/[0.065] bg-[#090d0c] md:flex md:flex-col">
        <div className="flex h-[68px] items-center gap-3 border-b border-white/[0.065] px-5">
          <BrandMark />
          <div>
            <p className="text-sm font-semibold leading-none tracking-tight text-white">YSD Zero Cloud</p>
            <p className="mt-1 text-[10px] font-medium uppercase tracking-[0.16em] text-white/35">Cloud OS · v0.1</p>
          </div>
        </div>

        <nav aria-label="Primary navigation" className="flex-1 overflow-y-auto p-3">
          <p className="px-2 pb-2 pt-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-white/25">Workspace</p>
          <div className="space-y-0.5">
            {navigation.map((item) => {
              const active = item.href === '/' ? pathname === '/' : pathname.startsWith(item.href);
              const Icon = item.icon;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    'group flex h-9 items-center gap-3 rounded-lg px-2.5 text-[13px] font-medium transition-colors',
                    active ? 'bg-[#b7ff3c]/10 text-[#c8ff69]' : 'text-white/48 hover:bg-white/[0.045] hover:text-white/80',
                  )}
                >
                  <Icon className={cn('size-4', active ? 'text-[#b7ff3c]' : 'text-white/32 group-hover:text-white/65')} />
                  <span>{item.label}</span>
                  {item.href === '/shield' && (
                    <span className="ml-auto rounded-full bg-[#b7ff3c]/10 px-1.5 text-[9px] text-[#b7ff3c]">SAFE</span>
                  )}
                </Link>
              );
            })}
          </div>
        </nav>

        <div className="m-3 rounded-xl border border-[#b7ff3c]/15 bg-[#b7ff3c]/[0.045] p-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <LockKeyhole className="size-3.5 text-[#b7ff3c]" />
              <span className="text-xs font-semibold text-white/85">Zero Mode</span>
            </div>
            <Switch checked={zeroMode.enabled} onCheckedChange={zeroMode.setEnabled} aria-label="Toggle Zero Mode" className="data-checked:bg-[#b7ff3c]" />
          </div>
          <p className="mt-2 text-[10px] leading-4 text-white/34">
            {zeroMode.enabled ? 'Paid services are blocked automatically.' : 'Cost guard is currently paused.'}
          </p>
        </div>
      </aside>

      <div className="md:pl-[244px]">
        <header className="sticky top-0 z-30 flex h-[68px] items-center gap-3 border-b border-white/[0.065] bg-[#0d1210]/90 px-4 backdrop-blur-xl sm:px-6">
          <div className="flex min-w-0 items-center gap-2 md:hidden">
            <BrandMark />
            <span className="hidden text-sm font-semibold sm:block">YSD Zero</span>
          </div>
          <div className="relative hidden w-full max-w-[380px] sm:block">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-white/28" />
            <Input
              aria-label="Search the cloud workspace"
              placeholder="Search resources, projects, logs…"
              className="h-8 border-white/[0.07] bg-white/[0.035] pl-9 text-xs placeholder:text-white/25 focus-visible:border-[#b7ff3c]/40 focus-visible:ring-[#b7ff3c]/10"
            />
          </div>
          <div className="ml-auto flex items-center gap-1.5">
            <div className="hidden items-center gap-2 rounded-full border border-[#b7ff3c]/15 bg-[#b7ff3c]/[0.045] px-2.5 py-1.5 text-[10px] font-semibold text-[#c8ff69] lg:flex">
              <span className="size-1.5 rounded-full bg-[#b7ff3c] shadow-[0_0_8px_#b7ff3c]" /> All systems operational
            </div>
            <Tooltip>
              <TooltipTrigger render={<Button variant="ghost" size="icon" aria-label="Open activity" />}><Activity /></TooltipTrigger>
              <TooltipContent>Activity</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger render={<Button variant="ghost" size="icon" aria-label="Open notifications" />}><Bell /></TooltipTrigger>
              <TooltipContent>Notifications</TooltipContent>
            </Tooltip>
            <Button variant="ghost" className="gap-2 px-2 text-xs">
              <span className="grid size-6 place-items-center rounded-md bg-[#7569ff] text-[10px] font-bold text-white">YS</span>
              <span className="hidden sm:inline">OpenYsd</span>
              <ChevronDown className="size-3 text-white/35" />
            </Button>
          </div>
        </header>

        <div className="border-b border-white/[0.065] bg-[#0b100e] px-4 py-2 md:hidden">
          <nav className="flex gap-1 overflow-x-auto" aria-label="Mobile navigation">
            {navigation.slice(0, 8).map((item) => {
              const active = item.href === '/' ? pathname === '/' : pathname.startsWith(item.href);
              return (
                <Link key={item.href} href={item.href} className={cn('shrink-0 rounded-md px-3 py-1.5 text-[11px] font-medium', active ? 'bg-[#b7ff3c]/10 text-[#c8ff69]' : 'text-white/40')}>
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>

        <main className="min-h-[calc(100vh-68px)] bg-[radial-gradient(circle_at_58%_-10%,rgba(82,255,143,.055),transparent_32rem)] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          {children}
        </main>
      </div>
    </div>
  );
}
