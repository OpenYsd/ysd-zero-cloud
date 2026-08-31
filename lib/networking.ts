import type {
  ExposureDomain,
  PublicExposure,
  PublicExposureAvailability,
} from './public-exposure';

export type NetworkRoute = {
  id: string;
  label: string;
  address: string;
  exposure: 'public' | 'session' | 'internal';
  protection: string;
};

export type PrivateAppService = {
  deploymentId: string;
  repository: string;
  environment: string;
  nodeName: string;
  localPort: number | null;
};

export type NetworkState = {
  mode: 'workers-dev-only' | 'custom';
  origin: string;
  hostname: string;
  tls: boolean;
  workerDomain: boolean;
  customDomains: number;
  tunnels: number;
  publicStorageEndpoints: number;
  privateAppServices: number;
  routes: NetworkRoute[];
  services: PrivateAppService[];
  exposures: PublicExposure[];
  domains: ExposureDomain[];
  availability: PublicExposureAvailability;
  permissions: {
    manageExposure: boolean;
    createPreview: boolean;
    manageDomains: boolean;
  };
};

export function buildNetworkState(input: {
  origin: string;
  mode?: string;
  storageAvailable: boolean;
  localServices?: PrivateAppService[];
  exposures?: PublicExposure[];
  domains?: ExposureDomain[];
  availability?: PublicExposureAvailability;
  permissions?: NetworkState['permissions'];
}): NetworkState {
  let url: URL;
  try {
    url = new URL(input.origin);
  } catch {
    url = new URL('http://localhost:3000');
  }

  const workerDomain = url.hostname.endsWith('.workers.dev');
  const mode = input.mode === 'workers-dev-only' ? 'workers-dev-only' : 'custom';
  const localServices = input.localServices ?? [];
  const availability = input.availability ?? {
    available: false,
    state: 'unavailable-zero-mode' as const,
    reason: 'Unavailable under Zero Mode.',
    accountPlan: 'workers-free' as const,
    billingState: 'no-payment-method' as const,
    ownedZones: 0,
    tunnels: 0,
    workersDevHostname: url.hostname,
    gatewayStyle: 'path' as const,
    projectedMonthlyCost: 0 as const,
  };
  return {
    mode,
    origin: url.origin,
    hostname: url.hostname,
    tls: url.protocol === 'https:',
    workerDomain,
    customDomains: input.domains?.length ?? 0,
    tunnels: availability.tunnels,
    publicStorageEndpoints: 0,
    privateAppServices: localServices.length,
    routes: [
      {
        id: 'app',
        label: 'Cloud OS',
        address: url.origin,
        exposure: 'public',
        protection: 'TLS · security headers',
      },
      {
        id: 'auth',
        label: 'Authentication',
        address: `${url.origin}/api/auth/*`,
        exposure: 'public',
        protection: 'Turnstile · D1 rate limits · lockout',
      },
      {
        id: 'gateway',
        label: 'YSD Gateway',
        address: `${url.origin}/apps/<route-id>/*`,
        exposure: 'public',
        protection: 'Exact deployment route · fail closed · no arbitrary origin',
      },
      {
        id: 'workspace-api',
        label: 'Workspace API',
        address: `${url.origin}/api/*`,
        exposure: 'session',
        protection: 'HttpOnly session · organization/workspace/project scope',
      },
      {
        id: 'r2',
        label: 'R2 object binding',
        address: input.storageAvailable ? 'Private Worker binding' : 'binding unavailable',
        exposure: 'internal',
        protection: 'No public bucket endpoint',
      },
      {
        id: 'd1',
        label: 'D1 database binding',
        address: 'Private Worker binding',
        exposure: 'internal',
        protection: 'Tenant predicates · integrity triggers',
      },
      ...localServices.map((service) => ({
        id: `app-runtime:${service.deploymentId}`,
        label: `${service.repository} · ${service.nodeName}`,
        address: service.localPort ? `Private node service · port ${service.localPort}` : 'Private node service',
        exposure: 'internal' as const,
        protection: 'Origin address redacted · no automatic router or firewall changes',
      })),
    ],
    services: localServices,
    exposures: input.exposures ?? [],
    domains: input.domains ?? [],
    availability,
    permissions: input.permissions ?? {
      manageExposure: false,
      createPreview: false,
      manageDomains: false,
    },
  };
}
