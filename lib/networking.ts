export type NetworkRoute = {
  id: string;
  label: string;
  address: string;
  exposure: 'public' | 'session' | 'internal';
  protection: string;
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
  routes: NetworkRoute[];
};

export function buildNetworkState(input: {
  origin: string;
  mode?: string;
  storageAvailable: boolean;
}): NetworkState {
  let url: URL;
  try {
    url = new URL(input.origin);
  } catch {
    url = new URL('http://localhost:3000');
  }

  const workerDomain = url.hostname.endsWith('.workers.dev');
  const mode =
    input.mode === 'workers-dev-only' ? 'workers-dev-only' : 'custom';

  return {
    mode,
    origin: url.origin,
    hostname: url.hostname,
    tls: url.protocol === 'https:',
    workerDomain,
    customDomains: mode === 'workers-dev-only' ? 0 : workerDomain ? 0 : 1,
    tunnels: 0,
    // R2 is intentionally reachable only through the session-scoped Worker
    // route. Neither r2.dev nor a bucket custom domain is enabled.
    publicStorageEndpoints: 0,
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
        id: 'workspace-api',
        label: 'Workspace API',
        address: `${url.origin}/api/*`,
        exposure: 'session',
        protection: 'HttpOnly session · workspace scope',
      },
      {
        id: 'r2',
        label: 'R2 object binding',
        address: input.storageAvailable ? 'env.STORAGE' : 'binding unavailable',
        exposure: 'internal',
        protection: 'Private bucket · D1 authorization index',
      },
      {
        id: 'd1',
        label: 'D1 database binding',
        address: 'env.DB',
        exposure: 'internal',
        protection: 'Worker binding · tenant predicates',
      },
    ],
  };
}
