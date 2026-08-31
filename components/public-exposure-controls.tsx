'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type { NetworkState, PrivateAppService } from '@/lib/networking';
import type { ExposureAccessPolicy, ExposureMode, PublicExposure } from '@/lib/public-exposure';

async function jsonRequest(url: string, init: RequestInit): Promise<Record<string, unknown>> {
  const headers = new Headers(init.headers);
  headers.set('content-type', 'application/json');
  const response = await fetch(url, {
    ...init,
    headers,
  });
  const decoded: unknown = response.status === 204
    ? {}
    : await response.json().catch(() => ({ error: 'The server returned an invalid response.' }));
  const body = typeof decoded === 'object' && decoded !== null
    ? decoded as Record<string, unknown>
    : {};
  if (!response.ok) throw new Error(typeof body.error === 'string' ? body.error : 'The request failed.');
  return body;
}

function ServiceControl({
  service,
  exposure,
  state,
}: {
  service: PrivateAppService;
  exposure: PublicExposure | undefined;
  state: NetworkState;
}) {
  const router = useRouter();
  const [mode, setMode] = useState<ExposureMode>(exposure?.mode ?? 'private');
  const [access, setAccess] = useState<ExposureAccessPolicy>(exposure?.accessPolicy ?? 'authenticated');
  const [rate, setRate] = useState(String(exposure?.rateLimitPerMinute ?? 60));
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const preview = service.environment === 'Preview';
  const canManage = state.permissions.manageExposure || (preview && state.permissions.createPreview);

  async function save() {
    setBusy(true);
    setMessage(null);
    try {
      const result = await jsonRequest('/api/exposures', {
        method: 'POST',
        body: JSON.stringify({
          deploymentId: service.deploymentId,
          mode,
          accessPolicy: access,
          fallbackPolicy: 'none',
          rateLimitEnabled: true,
          rateLimitPerMinute: Number(rate),
          ipAllowlist: [],
          preview,
        }),
      });
      const saved = result.exposure as PublicExposure | undefined;
      setMessage(saved?.status === 'unavailable_zero_mode'
        ? 'Saved, but public transport remains unavailable under Zero Mode.'
        : 'Exposure policy saved.');
      router.refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The request failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-xl border border-white/[0.07] bg-black/10 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium text-white/72">{service.repository}</p>
          <p className="mt-1 text-[10px] text-white/30">
            {service.environment} · {service.nodeName} · origin hidden
          </p>
        </div>
        <span className="rounded-full border border-white/10 px-2 py-1 text-[9px] uppercase text-white/38">
          {exposure?.status ?? 'private'}
        </span>
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_1fr_100px_auto]">
        <label className="text-[10px] text-white/34">
          Mode
          <select
            value={mode}
            onChange={(event) => setMode(event.target.value as ExposureMode)}
            disabled={!canManage || busy}
            className="mt-1 h-8 w-full rounded-lg border border-white/10 bg-[#10131a] px-2 text-[11px] text-white/65"
          >
            <option value="private">Private</option>
            <option value="public">Public (gated)</option>
            <option value="custom-domain" disabled={!state.availability.available}>Custom domain</option>
          </select>
        </label>
        <label className="text-[10px] text-white/34">
          Access
          <select
            value={access}
            onChange={(event) => setAccess(event.target.value as ExposureAccessPolicy)}
            disabled={!canManage || busy}
            className="mt-1 h-8 w-full rounded-lg border border-white/10 bg-[#10131a] px-2 text-[11px] text-white/65"
          >
            <option value="authenticated">YSD authenticated</option>
            <option value="public">Public</option>
          </select>
        </label>
        <label htmlFor={`exposure-rate-${service.deploymentId}`} className="text-[10px] text-white/34">
          Requests/min
          <Input
            id={`exposure-rate-${service.deploymentId}`}
            type="number"
            min={5}
            max={600}
            value={rate}
            onChange={(event) => setRate(event.target.value)}
            disabled={!canManage || busy}
            className="mt-1 text-[11px]"
          />
        </label>
        <Button className="self-end" size="sm" onClick={save} disabled={!canManage || busy}>
          {busy ? 'Saving…' : 'Save policy'}
        </Button>
      </div>
      {exposure ? (
        <div className="mt-3 grid gap-2 text-[10px] text-white/35 sm:grid-cols-3">
          <span>Route: <span className="font-mono text-white/50">/apps/{exposure.routeId}/</span></span>
          <span>TLS: <span className="text-white/50">{exposure.tls}</span></span>
          <span>Health: <span className="text-white/50">{exposure.health}</span></span>
          <span>URL: <span className="text-white/50">{exposure.publicUrl ?? 'not assigned'}</span></span>
          <span>Last request: <span className="text-white/50">{exposure.lastRequestAt ? new Date(exposure.lastRequestAt).toLocaleString() : 'never'}</span></span>
          <span>Error: <span className="text-white/50">{exposure.lastError ?? 'none'}</span></span>
        </div>
      ) : null}
      {!canManage ? <p className="mt-3 text-[10px] text-white/28">Read-only for your organization role.</p> : null}
      {message ? <p className="mt-3 text-[10px] text-[#79d6ff]">{message}</p> : null}
    </div>
  );
}

export function PublicExposureControls({ state }: { state: NetworkState }) {
  const router = useRouter();
  const [hostname, setHostname] = useState('');
  const [verification, setVerification] = useState<{ name: string; value: string } | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function addDomain() {
    setBusy(true);
    setMessage(null);
    try {
      const result = await jsonRequest('/api/domains', {
        method: 'POST',
        body: JSON.stringify({ hostname }),
      });
      const record = result.verificationRecord as { name?: string; value?: string } | undefined;
      if (record?.name && record.value) setVerification({ name: record.name, value: record.value });
      setHostname('');
      setMessage('Domain inventoried. Save this one-time TXT value before leaving.');
      router.refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The request failed.');
    } finally {
      setBusy(false);
    }
  }

  async function domainAction(id: string, action: 'verify' | 'remove') {
    setBusy(true);
    setMessage(null);
    try {
      await jsonRequest(action === 'verify' ? `/api/domains/${id}/verify` : `/api/domains/${id}`, {
        method: action === 'verify' ? 'POST' : 'DELETE',
      });
      setMessage(action === 'verify' ? 'Ownership verification completed.' : 'Domain removed.');
      router.refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'The request failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      {state.services.map((service) => (
        <ServiceControl
          key={service.deploymentId}
          service={service}
          exposure={state.exposures.find((item) =>
            item.deploymentId === service.deploymentId && item.preview === (service.environment === 'Preview'))}
          state={state}
        />
      ))}
      {state.services.length === 0 ? (
        <p className="rounded-xl border border-white/[0.06] p-4 text-[11px] text-white/32">
          No healthy App Runtime deployment is available. No public route has been created.
        </p>
      ) : null}

      <div className="rounded-xl border border-white/[0.07] p-4">
        <p className="text-xs font-medium text-white/70">Owned domain inventory</p>
        <p className="mt-1 text-[10px] leading-4 text-white/30">
          Ownership can be proven with DNS TXT. Attachment and Cloudflare TLS stay disabled until an owned Zone exists on a verified $0 path.
        </p>
        {state.permissions.manageDomains ? (
          <div className="mt-3 flex gap-2">
            <Input value={hostname} onChange={(event) => setHostname(event.target.value)} placeholder="app.your-owned-domain.com" disabled={busy} />
            <Button size="sm" onClick={addDomain} disabled={busy || !hostname.trim()}>Add</Button>
          </div>
        ) : null}
        {verification ? (
          <div className="mt-3 rounded-lg border border-[#79d6ff]/15 bg-[#79d6ff]/5 p-3 text-[10px] text-white/55">
            <p>TXT name: <span className="font-mono">{verification.name}</span></p>
            <p className="mt-1 break-all">TXT value: <span className="font-mono">{verification.value}</span></p>
          </div>
        ) : null}
        <div className="mt-3 space-y-2">
          {state.domains.map((domain) => (
            <div key={domain.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-white/[0.025] px-3 py-2 text-[10px]">
              <span className="text-white/58">{domain.hostname}</span>
              <span className="text-white/30">ownership {domain.ownershipState} · attach {domain.attachState} · TLS {domain.tls}</span>
              {state.permissions.manageDomains ? (
                <span className="flex gap-1">
                  <Button size="xs" variant="outline" disabled={busy} onClick={() => domainAction(domain.id, 'verify')}>Verify</Button>
                  <Button size="xs" variant="ghost" disabled={busy || domain.attachState === 'attached'} onClick={() => domainAction(domain.id, 'remove')}>Remove</Button>
                </span>
              ) : null}
            </div>
          ))}
        </div>
        {message ? <p className="mt-3 text-[10px] text-[#79d6ff]">{message}</p> : null}
      </div>
    </div>
  );
}
