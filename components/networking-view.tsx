import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { MetricGrid } from '@/components/ui-bits';
import type { NetworkState } from '@/lib/networking';
import {
  Globe2,
  Link2,
  LockKeyhole,
  Network,
  Route,
  ShieldCheck,
} from 'lucide-react';

const EXPOSURE_TONE: Record<
  NetworkState['routes'][number]['exposure'],
  string
> = {
  public: 'border-[#4ac7ff]/15 bg-[#4ac7ff]/5 text-[#79d6ff]',
  session: 'border-[#7569ff]/20 bg-[#7569ff]/7 text-[#aaa4ff]',
  internal: 'border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]',
};

export function NetworkingView({ state }: { state: NetworkState }) {
  return (
    <>
      <MetricGrid
        items={[
          {
            icon: Globe2,
            label: 'Edge origin',
            value: state.workerDomain ? 'Workers' : 'Custom',
            detail: state.tls ? 'TLS enforced' : 'local HTTP',
          },
          {
            icon: Link2,
            label: 'Custom domains',
            value: String(state.customDomains),
            detail: state.customDomains === 0 ? 'no owned zone' : 'configured',
          },
          {
            icon: Route,
            label: 'Tunnels',
            value: String(state.tunnels),
            detail: 'none provisioned',
          },
          {
            icon: LockKeyhole,
            label: 'Public R2 URLs',
            value: String(state.publicStorageEndpoints),
            detail: 'private binding only',
          },
        ]}
      />

      <section className="cloud-card p-5">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
          <div className="flex items-start gap-3">
            <span className="icon-well icon-well-blue">
              <Network />
            </span>
            <div>
              <h2 className="text-sm font-semibold text-white/82">
                {state.hostname}
              </h2>
              <p className="mt-1 text-[10px] text-white/30">{state.origin}</p>
            </div>
          </div>
          <Badge
            variant="outline"
            className="border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]"
          >
            <ShieldCheck className="size-3" /> Zero-cost edge
          </Badge>
        </div>
        <div className="mt-5 grid gap-3 border-t border-white/[0.06] pt-4 text-[11px] sm:grid-cols-3">
          <div>
            <p className="text-white/25">Mode</p>
            <p className="mt-1 font-mono text-white/58">{state.mode}</p>
          </div>
          <div>
            <p className="text-white/25">TLS</p>
            <p className="mt-1 text-white/58">
              {state.tls ? 'Cloudflare managed' : 'development only'}
            </p>
          </div>
          <div>
            <p className="text-white/25">Paid routing</p>
            <p className="mt-1 text-[#c8ff69]">None</p>
          </div>
        </div>
      </section>

      <section className="cloud-card overflow-hidden">
        <div className="border-b border-white/[0.065] px-5 py-4">
          <h2 className="text-sm font-semibold text-white/80">
            Route inventory
          </h2>
          <p className="mt-1 text-[10px] text-white/27">
            Derived from the deployed Worker bindings and route policy; no mock
            traffic.
          </p>
        </div>
        <Table className="text-[11px]">
          <TableHeader>
            <TableRow className="border-white/[0.06] hover:bg-transparent">
              {['Surface', 'Address', 'Exposure', 'Protection'].map(
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
            {state.routes.map((route) => (
              <TableRow
                key={route.id}
                className="border-white/[0.05] hover:bg-white/[0.02]"
              >
                <TableCell className="px-4 py-3 font-medium text-white/70">
                  {route.label}
                </TableCell>
                <TableCell className="max-w-[360px] truncate px-4 py-3 font-mono text-[10px] text-white/36">
                  {route.address}
                </TableCell>
                <TableCell className="px-4 py-3">
                  <Badge
                    variant="outline"
                    className={EXPOSURE_TONE[route.exposure]}
                  >
                    {route.exposure}
                  </Badge>
                </TableCell>
                <TableCell className="px-4 py-3 text-white/42">
                  {route.protection}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </section>

      <div className="flex items-start gap-2.5 rounded-xl border border-[#b7ff3c]/12 bg-[#b7ff3c]/[0.035] p-4 text-[11px] leading-5 text-white/42">
        <ShieldCheck className="mt-px size-3.5 shrink-0 text-[#b7ff3c]" />
        <span>
          No domain purchase, nameserver change, Tunnel, Spectrum, Argo, load
          balancer, or public bucket endpoint is configured. Networking remains
          on the free workers.dev origin until an owned domain is deliberately
          added later.
        </span>
      </div>
    </>
  );
}
