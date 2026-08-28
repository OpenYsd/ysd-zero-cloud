'use client';

import { useState } from 'react';
import {
  Cloud,
  Database,
  GitBranch,
  KeyRound,
  Loader2,
  MailCheck,
  ShieldCheck,
  UserRoundCheck,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { useZeroMode } from '@/components/zero-mode-provider';
import type {
  IntegrationDescriptor,
  IntegrationProvider,
} from '@/lib/integrations';
import type { Workspace, WorkspaceSetting } from '@/lib/domain';

const ICONS: Record<IntegrationProvider, typeof Cloud> = {
  github: GitBranch,
  'github-oauth': GitBranch,
  cloudflare: Cloud,
  'cloudflare-d1': Database,
  'better-auth': UserRoundCheck,
  turnstile: ShieldCheck,
  email: MailCheck,
};

const STATUS_LABEL = {
  bound: 'Bound',
  configured: 'Connected',
  mock: 'Not configured',
} as const;

type Toggle = {
  setting: WorkspaceSetting;
  title: string;
  copy: string;
};

const TOGGLES: Toggle[] = [
  {
    setting: 'zeroMode',
    title: 'Zero Mode',
    copy: 'Reject any deployment plan that carries a projected charge.',
  },
  {
    setting: 'autoScan',
    title: 'Automatic security scans',
    copy: 'Run YSD Shield after a deployment plan is recorded.',
  },
  {
    setting: 'sleepIdleServers',
    title: 'Sleep idle game servers',
    copy: 'Pause unused workloads after 15 minutes. Applies once game servers are live.',
  },
  {
    setting: 'previewDeployments',
    title: 'Preview deployments',
    copy: 'Record a separate plan for every branch.',
  },
];

export function SettingsView({
  workspace,
  integrations,
}: {
  workspace: Workspace;
  integrations: IntegrationDescriptor[];
}) {
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_1.2fr]">
      <article className="cloud-card p-5">
        <h2 className="text-sm font-semibold text-white/80">
          Workspace defaults
        </h2>
        <p className="mt-1 text-[10px] text-white/27">
          Stored on the workspace row and applied on the server.
        </p>
        <div className="mt-6 space-y-5">
          {TOGGLES.map((toggle) => (
            <SettingToggle
              key={toggle.setting}
              toggle={toggle}
              initial={workspace[toggle.setting]}
            />
          ))}
        </div>
      </article>

      <article className="cloud-card overflow-hidden">
        <div className="border-b border-white/[0.065] px-5 py-4">
          <h2 className="text-sm font-semibold text-white/80">Integrations</h2>
          <p className="mt-1 text-[10px] text-white/27">
            Configure these as Worker secrets. Only the key names are ever shown
            here.
          </p>
        </div>
        <div className="divide-y divide-white/[0.055]">
          {integrations.map((integration) => {
            const Icon = ICONS[integration.id];
            return (
              <div
                key={integration.id}
                className="flex items-center gap-4 px-5 py-4"
              >
                <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-white/[0.07] bg-white/[0.03] text-white/48">
                  <Icon className="size-4" />
                </span>
                <div className="min-w-0">
                  <p className="text-xs font-semibold text-white/70">
                    {integration.name}
                  </p>
                  <p className="mt-1 text-[10px] text-white/27">
                    {integration.purpose}
                  </p>
                  {integration.envKeys.length > 0 && (
                    <p className="mt-1 flex flex-wrap items-center gap-1 font-mono text-[9px] text-white/22">
                      <KeyRound className="size-2.5" />
                      {integration.envKeys.join(' · ')}
                    </p>
                  )}
                  {integration.binding && (
                    <p className="mt-1 font-mono text-[9px] text-white/22">
                      binding: {integration.binding}
                    </p>
                  )}
                </div>
                <Badge
                  variant="outline"
                  className={
                    integration.status === 'mock'
                      ? 'ml-auto shrink-0 border-white/[0.09] text-white/35'
                      : 'ml-auto shrink-0 border-[#b7ff3c]/15 text-[#c8ff69]'
                  }
                >
                  {STATUS_LABEL[integration.status]}
                </Badge>
              </div>
            );
          })}
        </div>
      </article>
    </div>
  );
}

function SettingToggle({
  toggle,
  initial,
}: {
  toggle: Toggle;
  initial: boolean;
}) {
  const zeroMode = useZeroMode();
  const [checked, setChecked] = useState(initial);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Zero Mode is already owned by the shell provider, so this row mirrors it
  // rather than keeping a second copy that could drift.
  const isZeroMode = toggle.setting === 'zeroMode';
  const value = isZeroMode ? zeroMode.enabled : checked;
  const busy = isZeroMode ? zeroMode.pending : pending;
  const message = isZeroMode ? zeroMode.error : error;

  async function change(next: boolean) {
    if (isZeroMode) {
      zeroMode.setEnabled(next);
      return;
    }

    const previous = checked;
    setChecked(next);
    setPending(true);
    setError(null);
    try {
      const response = await fetch('/api/settings', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ setting: toggle.setting, value: next }),
      });
      if (!response.ok) {
        const body = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        throw new Error(body.error ?? 'The setting could not be saved.');
      }
    } catch (cause) {
      setChecked(previous);
      setError(
        cause instanceof Error
          ? cause.message
          : 'The setting could not be saved.',
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <p className="flex items-center gap-2 text-xs font-medium text-white/65">
          {toggle.title}
          {busy && <Loader2 className="size-3 animate-spin text-white/30" />}
        </p>
        <p className="mt-1 max-w-sm text-[10px] leading-4 text-white/27">
          {message ?? toggle.copy}
        </p>
      </div>
      <Switch
        checked={value}
        onCheckedChange={change}
        disabled={busy}
        aria-label={`Toggle ${toggle.title}`}
        className="data-checked:bg-[#b7ff3c]"
      />
    </div>
  );
}
