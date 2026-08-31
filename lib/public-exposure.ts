/** Pure Phase 8 policy shared by API handlers, the Gateway, UI, and tests. */

export const EXPOSURE_MODES = ['private', 'public', 'custom-domain'] as const;
export type ExposureMode = (typeof EXPOSURE_MODES)[number];

export const EXPOSURE_ACCESS_POLICIES = ['public', 'authenticated'] as const;
export type ExposureAccessPolicy = (typeof EXPOSURE_ACCESS_POLICIES)[number];

export const EXPOSURE_FALLBACK_POLICIES = ['none', 'previous_healthy'] as const;
export type ExposureFallbackPolicy = (typeof EXPOSURE_FALLBACK_POLICIES)[number];

export type ExposureStatus =
  | 'disabled'
  | 'pending'
  | 'unavailable_zero_mode'
  | 'active'
  | 'degraded'
  | 'expired'
  | 'revoked'
  | 'failed'
  | 'deleted';

export type ExposureHealth = 'unknown' | 'healthy' | 'stale' | 'offline' | 'revoked' | 'failed';
export type ExposureTlsState = 'unavailable' | 'pending' | 'cloudflare';

export type PublicExposure = {
  id: string;
  deploymentId: string;
  projectId: string;
  repository: string;
  environment: 'Production' | 'Preview' | 'Development';
  nodeName: string;
  routeId: string;
  gatewayRoute: string;
  publicUrl: string | null;
  assignedHostname: string | null;
  mode: ExposureMode;
  status: ExposureStatus;
  accessPolicy: ExposureAccessPolicy;
  health: ExposureHealth;
  tls: ExposureTlsState;
  verification: 'not_required' | 'pending' | 'verified' | 'failed';
  fallbackPolicy: ExposureFallbackPolicy;
  rateLimitEnabled: boolean;
  rateLimitPerMinute: number;
  ipAllowlist: string[];
  preview: boolean;
  expiresAt: number | null;
  lastRequestAt: number | null;
  lastError: string | null;
  updatedAt: number;
  canManage: boolean;
};

export type ExposureDomain = {
  id: string;
  hostname: string;
  dnsRecordName: string;
  tokenPrefix: string;
  ownershipState: 'pending' | 'verified' | 'failed';
  providerState: 'no_owned_zone' | 'ready' | 'unavailable_zero_mode';
  attachState: 'detached' | 'pending' | 'attached';
  tls: ExposureTlsState;
  exposureId: string | null;
  verifiedAt: number | null;
  lastError: string | null;
  updatedAt: number;
};

export type PublicExposureAvailability = {
  available: boolean;
  state: 'unavailable-zero-mode' | 'available-reviewed';
  reason: string;
  accountPlan: 'workers-free';
  billingState: 'no-payment-method';
  ownedZones: number;
  tunnels: number;
  workersDevHostname: string;
  gatewayStyle: 'path';
  projectedMonthlyCost: 0;
};

const FORBIDDEN_INPUT_KEY =
  /(?:url|uri|upstream|origin|endpoint|address|host|ip|port|provider|tunnel|argo|spectrum|load.?balancer|command|shell|executable|args|billing|paid|zero.?mode)/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export type ExposureMutation = {
  deploymentId: string;
  mode: ExposureMode;
  accessPolicy: ExposureAccessPolicy;
  fallbackPolicy: ExposureFallbackPolicy;
  rateLimitEnabled: true;
  rateLimitPerMinute: number;
  ipAllowlist: string[];
  preview: boolean;
  expiresAt: number | null;
};

export type ExposureMutationResult =
  | { ok: true; value: ExposureMutation }
  | { ok: false; status: 400; error: string; securityEvent?: string };

/**
 * Parses only policy and deployment identity. There is deliberately no field
 * through which a caller can provide an upstream URL, IP, connector target,
 * executable, provider, or Zero Mode override.
 */
export function parseExposureMutation(body: unknown, now = Date.now()): ExposureMutationResult {
  if (!isRecord(body)) return { ok: false, status: 400, error: 'A JSON object is required.' };
  const allowed = new Set([
    'deploymentId', 'mode', 'accessPolicy', 'fallbackPolicy',
    'rateLimitEnabled', 'rateLimitPerMinute', 'ipAllowlist', 'preview', 'expiresAt',
  ]);
  const unexpected = Object.keys(body).filter((key) => !allowed.has(key));
  if (unexpected.length > 0) {
    const hostile = unexpected.some((key) => FORBIDDEN_INPUT_KEY.test(key));
    return {
      ok: false,
      status: 400,
      error: hostile
        ? 'Upstream URLs, IPs, ports, providers, tunnels, commands, billing fields, and Zero Mode overrides are forbidden.'
        : 'The exposure request contains an unexpected field.',
      securityEvent: hostile ? 'gateway-upstream-rejected' : undefined,
    };
  }
  const deploymentId = typeof body.deploymentId === 'string' ? body.deploymentId : '';
  if (!/^dpl_[a-f0-9]{24}$/.test(deploymentId)) {
    return { ok: false, status: 400, error: 'A valid deployment identity is required.' };
  }
  const mode = typeof body.mode === 'string' && (EXPOSURE_MODES as readonly string[]).includes(body.mode)
    ? (body.mode as ExposureMode)
    : null;
  if (!mode) return { ok: false, status: 400, error: 'Choose private, public, or custom-domain mode.' };
  const accessPolicy = typeof body.accessPolicy === 'string' &&
    (EXPOSURE_ACCESS_POLICIES as readonly string[]).includes(body.accessPolicy)
    ? (body.accessPolicy as ExposureAccessPolicy)
    : null;
  if (!accessPolicy) return { ok: false, status: 400, error: 'Choose public or authenticated access.' };
  const fallbackPolicy = body.fallbackPolicy === undefined
    ? 'none'
    : typeof body.fallbackPolicy === 'string' &&
        (EXPOSURE_FALLBACK_POLICIES as readonly string[]).includes(body.fallbackPolicy)
      ? (body.fallbackPolicy as ExposureFallbackPolicy)
      : null;
  if (!fallbackPolicy) return { ok: false, status: 400, error: 'Choose a supported health fallback policy.' };
  if (body.rateLimitEnabled === false && mode !== 'private') {
    return { ok: false, status: 400, error: 'Rate limiting is mandatory for every public route.' };
  }
  const rateLimitPerMinute = body.rateLimitPerMinute === undefined ? 60 : body.rateLimitPerMinute;
  if (!Number.isSafeInteger(rateLimitPerMinute) || Number(rateLimitPerMinute) < 5 || Number(rateLimitPerMinute) > 600) {
    return { ok: false, status: 400, error: 'Rate limit must be an integer from 5 to 600 requests per minute.' };
  }
  const list = body.ipAllowlist === undefined ? [] : body.ipAllowlist;
  if (!Array.isArray(list) || list.length > 32 || list.some((value) => typeof value !== 'string')) {
    return { ok: false, status: 400, error: 'IP allowlist must contain at most 32 IPv4 addresses or CIDRs.' };
  }
  const ipAllowlist: string[] = [];
  for (const entry of list as string[]) {
    const normalized = normalizeIpv4Cidr(entry);
    if (!normalized) return { ok: false, status: 400, error: 'Only canonical IPv4 addresses and CIDRs are accepted.' };
    if (!ipAllowlist.includes(normalized)) ipAllowlist.push(normalized);
  }
  const preview = body.preview === true;
  let expiresAt: number | null = null;
  if (body.expiresAt !== undefined && body.expiresAt !== null) {
    if (!preview || !Number.isSafeInteger(body.expiresAt) || Number(body.expiresAt) < now + 5 * 60_000 || Number(body.expiresAt) > now + 7 * 24 * 60 * 60_000) {
      return { ok: false, status: 400, error: 'Preview expiry must be between five minutes and seven days from now.' };
    }
    expiresAt = Number(body.expiresAt);
  } else if (preview) {
    expiresAt = now + 24 * 60 * 60_000;
  }
  return {
    ok: true,
    value: {
      deploymentId,
      mode,
      accessPolicy,
      fallbackPolicy,
      rateLimitEnabled: true,
      rateLimitPerMinute: Number(rateLimitPerMinute),
      ipAllowlist,
      preview,
      expiresAt,
    },
  };
}

function ipv4Number(value: string): number | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    result = (result * 256 + octet) >>> 0;
  }
  return result;
}

export function normalizeIpv4Cidr(value: string): string | null {
  const trimmed = value.trim();
  const [address, prefixText, extra] = trimmed.split('/');
  if (extra !== undefined || !address) return null;
  const number = ipv4Number(address);
  if (number === null) return null;
  const prefix = prefixText === undefined ? 32 : Number(prefixText);
  if (!Number.isSafeInteger(prefix) || prefix < 0 || prefix > 32 || String(prefix) !== (prefixText ?? '32')) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  if ((number & mask) >>> 0 !== number) return null;
  return `${address}/${prefix}`;
}

export function ipAllowed(address: string, allowlist: readonly string[]): boolean {
  if (allowlist.length === 0) return true;
  const candidate = ipv4Number(address);
  if (candidate === null) return false;
  return allowlist.some((entry) => {
    const normalized = normalizeIpv4Cidr(entry);
    if (!normalized) return false;
    const [networkText, prefixText] = normalized.split('/');
    const network = ipv4Number(networkText);
    const prefix = Number(prefixText);
    if (network === null) return false;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return ((candidate & mask) >>> 0) === network;
  });
}

export function normalizeCustomHostname(value: string): string | null {
  const hostname = value.trim().toLowerCase().replace(/\.$/, '');
  if (hostname.length < 4 || hostname.length > 253 || hostname.includes('/') || hostname.includes(':')) return null;
  if (/^(?:localhost|.*\.(?:localhost|local|internal|invalid|test|example|workers\.dev))$/.test(hostname)) return null;
  const labels = hostname.split('.');
  if (labels.length < 2 || /^\d+$/.test(labels.at(-1) ?? '')) return null;
  if (labels.some((label) => label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return null;
  return hostname;
}

/** Fixed Cloudflare DNS-over-HTTPS target; the user supplies only a validated name. */
export function domainVerificationQueryUrl(hostname: string): string | null {
  const normalized = normalizeCustomHostname(hostname);
  if (!normalized) return null;
  const queryName = `_ysd-verification.${normalized}`;
  return `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(queryName)}&type=TXT`;
}

export type GatewayCandidate = {
  mode: ExposureMode;
  status: ExposureStatus;
  accessPolicy: ExposureAccessPolicy;
  transportState: 'unavailable_zero_mode' | 'disconnected' | 'ready' | 'revoked' | 'failed';
  health: ExposureHealth;
  tls: ExposureTlsState;
  verification: 'not_required' | 'pending' | 'verified' | 'failed';
  expiresAt: number | null;
  rateLimitEnabled: boolean;
};

export type GatewayDecision = {
  action: 'not-found' | 'authenticate' | 'deny' | 'unavailable' | 'forward';
  status: 404 | 401 | 403 | 503 | 200;
};

/** Metadata-only routing decision. No upstream URL participates in it. */
export function gatewayDecision(input: {
  route: GatewayCandidate | null;
  now: number;
  authenticatedMember: boolean;
  ipAllowed: boolean;
}): GatewayDecision {
  const route = input.route;
  if (!route || route.mode === 'private' || ['disabled', 'expired', 'revoked', 'deleted'].includes(route.status)) {
    return { action: 'not-found', status: 404 };
  }
  if (route.expiresAt !== null && route.expiresAt <= input.now) return { action: 'not-found', status: 404 };
  if (route.accessPolicy === 'authenticated' && !input.authenticatedMember) {
    return { action: 'authenticate', status: 401 };
  }
  if (!input.ipAllowed) return { action: 'deny', status: 403 };
  if (!route.rateLimitEnabled || route.health !== 'healthy') return { action: 'unavailable', status: 503 };
  if (route.mode === 'custom-domain' && (route.verification !== 'verified' || route.tls !== 'cloudflare')) {
    return { action: 'unavailable', status: 503 };
  }
  if (route.status !== 'active' || route.transportState !== 'ready') {
    return { action: 'unavailable', status: 503 };
  }
  return { action: 'forward', status: 200 };
}

export function gatewayResponseHeaders(extra?: HeadersInit): Headers {
  const headers = new Headers(extra);
  headers.set('Cache-Control', 'no-store, max-age=0');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-YSD-Gateway', 'fail-closed');
  return headers;
}
