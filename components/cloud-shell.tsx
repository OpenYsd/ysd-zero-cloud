'use client';

import { NavLink } from '@/components/nav-link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import {
  Bot,
  Boxes,
  CloudCog,
  Database,
  Gamepad2,
  Gauge,
  HardDrive,
  Home,
  KeyRound,
  Layers3,
  Loader2,
  LockKeyhole,
  LogOut,
  Network,
  Rocket,
  Settings,
  ShieldCheck,
  ShieldOff,
  TerminalSquare,
  UserCog,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { authClient, signOut } from '@/lib/auth-client';
import { isLiveSection, isSection } from '@/lib/domain';
import type { Role } from '@/lib/roles';
import { cn } from '@/lib/utils';
import { ZeroModeProvider, useZeroMode } from '@/components/zero-mode-provider';

export type ShellUser = { name: string; email: string; role: Role; canAdminister: boolean };

/**
 * The sidebar. `live` is derived from the shared section catalog rather than
 * restated here, so the "Preview" badge always matches what the page renders.
 */
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
  { label: 'Accounts', href: '/admin', icon: UserCog, adminOnly: true },
  { label: 'Settings', href: '/settings', icon: Settings },
].map((item) => {
  const slug = item.href.slice(1);
  return {
    ...item,
    adminOnly: 'adminOnly' in item ? Boolean(item.adminOnly) : false,
    live: slug === '' || (isSection(slug) && isLiveSection(slug)),
  };
});

function BrandMark() {
  return (
    <div className="grid size-8 place-items-center rounded-[10px] bg-[#b7ff3c] text-[#08110d] shadow-[0_0_24px_rgba(183,255,60,.18)]">
      <CloudCog className="size-[18px]" strokeWidth={2.4} />
    </div>
  );
}

/**
 * The workspace frame.
 *
 * Anonymous visits render the bare centred layout the sign-in screens use, so
 * the navigation never advertises surfaces the visitor cannot open.
 */
export function CloudShell({
  children,
  user,
  zeroMode,
}: {
  children: React.ReactNode;
  user: ShellUser | null;
  zeroMode: boolean;
}) {
  if (!user) {
    return (
      <ZeroModeProvider initialEnabled={zeroMode} persist={false}>
        <div className="grid min-h-screen place-items-center bg-background px-4 py-10 text-foreground">
          {children}
        </div>
      </ZeroModeProvider>
    );
  }

  return (
    <ZeroModeProvider initialEnabled={zeroMode}>
      <CloudShellFrame user={user}>{children}</CloudShellFrame>
    </ZeroModeProvider>
  );
}

function CloudShellFrame({ children, user }: { children: React.ReactNode; user: ShellUser }) {
  const pathname = usePathname();
  const zeroMode = useZeroMode();

  return (
    <div className="min-h-screen bg-background text-foreground">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[244px] border-r border-white/[0.065] bg-[#090d0c] md:flex md:flex-col">
        <div className="flex h-[68px] items-center gap-3 border-b border-white/[0.065] px-5">
          <BrandMark />
          <div>
            <p className="text-sm font-semibold leading-none tracking-tight text-white">YSD Zero Cloud</p>
            <p className="mt-1 text-[10px] font-medium uppercase tracking-[0.16em] text-white/35">Cloud OS · v0.2</p>
          </div>
        </div>

        <nav aria-label="Primary navigation" className="flex-1 overflow-y-auto p-3">
          <p className="px-2 pb-2 pt-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-white/25">Workspace</p>
          <div className="space-y-0.5">
            {navigation
              .filter((item) => !item.adminOnly || user.canAdminister)
              .map((item) => {
              const active = item.href === '/' ? pathname === '/' : pathname.startsWith(item.href);
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.href}
                  href={item.href}
                  className={cn(
                    'group flex h-9 items-center gap-3 rounded-lg px-2.5 text-[13px] font-medium transition-colors',
                    active ? 'bg-[#b7ff3c]/10 text-[#c8ff69]' : 'text-white/48 hover:bg-white/[0.045] hover:text-white/80',
                  )}
                >
                  <Icon className={cn('size-4', active ? 'text-[#b7ff3c]' : 'text-white/32 group-hover:text-white/65')} />
                  <span>{item.label}</span>
                  {!item.live && (
                    <span className="ml-auto rounded-full border border-white/[0.08] px-1.5 text-[9px] text-white/30">
                      Preview
                    </span>
                  )}
                </NavLink>
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
            <Switch
              checked={zeroMode.enabled}
              onCheckedChange={zeroMode.setEnabled}
              disabled={zeroMode.pending}
              aria-label="Toggle Zero Mode"
              className="data-checked:bg-[#b7ff3c]"
            />
          </div>
          <p className="mt-2 text-[10px] leading-4 text-white/34">
            {zeroMode.error ??
              (zeroMode.enabled
                ? 'Paid resources are blocked before a plan runs.'
                : 'Cost guard is paused. Plans with a charge will be accepted.')}
          </p>
        </div>
      </aside>

      <div className="md:pl-[244px]">
        <header className="sticky top-0 z-30 flex h-[68px] items-center gap-3 border-b border-white/[0.065] bg-[#0d1210]/90 px-4 backdrop-blur-xl sm:px-6">
          <div className="flex min-w-0 items-center gap-2 md:hidden">
            <BrandMark />
            <span className="hidden text-sm font-semibold sm:block">YSD Zero</span>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <div
              className={cn(
                'hidden items-center gap-2 rounded-full border px-2.5 py-1.5 text-[10px] font-semibold lg:flex',
                zeroMode.enabled
                  ? 'border-[#b7ff3c]/15 bg-[#b7ff3c]/[0.045] text-[#c8ff69]'
                  : 'border-amber-400/20 bg-amber-400/[0.05] text-amber-300',
              )}
            >
              <span
                className={cn(
                  'size-1.5 rounded-full',
                  zeroMode.enabled ? 'bg-[#b7ff3c] shadow-[0_0_8px_#b7ff3c]' : 'bg-amber-300',
                )}
              />
              {zeroMode.enabled ? 'Zero Mode enforced' : 'Zero Mode paused'}
            </div>
            <UserMenu user={user} />
          </div>
        </header>

        <div className="border-b border-white/[0.065] bg-[#0b100e] px-4 py-2 md:hidden">
          <nav className="flex gap-1 overflow-x-auto" aria-label="Mobile navigation">
            {navigation
              .filter((item) => !item.adminOnly || user.canAdminister)
              .map((item) => {
              const active = item.href === '/' ? pathname === '/' : pathname.startsWith(item.href);
              return (
                <NavLink key={item.href} href={item.href} className={cn('shrink-0 rounded-md px-3 py-1.5 text-[11px] font-medium', active ? 'bg-[#b7ff3c]/10 text-[#c8ff69]' : 'text-white/40')}>
                  {item.label}
                </NavLink>
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

function initials(name: string, email: string): string {
  const source = name.trim() || email;
  const parts = source.split(/[\s@._-]+/).filter(Boolean);
  return `${parts[0]?.[0] ?? 'Y'}${parts[1]?.[0] ?? ''}`.toUpperCase();
}

function UserMenu({ user }: { user: ShellUser }) {
  const [pending, setPending] = useState(false);

  async function handleSignOut() {
    setPending(true);
    try {
      await signOut();
      // Full document load for the same reason the sign-in redirect uses one:
      // the root layout must re-render without a session.
      window.location.assign('/sign-in');
    } finally {
      setPending(false);
    }
  }

  /**
   * Revokes every session this account holds, not just the one in this browser.
   * The control an operator reaches for after losing a laptop.
   */
  async function handleSignOutEverywhere() {
    setPending(true);
    try {
      await authClient.revokeSessions();
      window.location.assign('/sign-in');
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <div className="flex items-center gap-2 rounded-lg border border-white/[0.07] bg-white/[0.025] px-2 py-1.5">
        <span className="grid size-6 place-items-center rounded-md bg-[#7569ff] text-[10px] font-bold text-white">
          {initials(user.name, user.email)}
        </span>
        <span className="hidden max-w-[160px] truncate text-xs text-white/70 sm:inline">{user.email}</span>
      </div>
      <Button
        variant="ghost"
        size="icon"
        aria-label="Sign out"
        title="Sign out of this browser"
        onClick={handleSignOut}
        disabled={pending}
      >
        {pending ? <Loader2 className="animate-spin" /> : <LogOut />}
      </Button>
      <Button
        variant="ghost"
        size="icon"
        aria-label="Sign out everywhere"
        title="Sign out of every device"
        onClick={handleSignOutEverywhere}
        disabled={pending}
      >
        <ShieldOff />
      </Button>
    </div>
  );
}
