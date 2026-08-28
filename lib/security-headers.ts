/**
 * The security response headers this deployment serves.
 *
 * One definition, used twice: `middleware.ts` applies it to every response, and
 * YSD Shield reports against it. A header removed here disappears from
 * responses *and* is immediately reported as missing, so the check cannot drift
 * away from what is actually served.
 *
 * Delivery itself is proven from outside, in `security-acceptance.py`. A Worker
 * fetching its own origin is not routed back through middleware, so it cannot
 * observe its own headers — which is why this module, not a self-request, is
 * the scan's source of truth.
 */

/**
 * Content Security Policy.
 *
 * `script-src` keeps `'unsafe-inline'` deliberately: the RSC runtime bootstraps
 * each page from an inline `<script>` carrying the flight payload, and vinext
 * offers no nonce to attach to it. Removing it would break every page. The
 * policy still refuses script from any origin other than this one and
 * Turnstile, which is the injection case that matters, and `object-src 'none'`
 * with `base-uri 'none'` closes the usual escapes.
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: blob:",
  "connect-src 'self' https://challenges.cloudflare.com",
  "frame-src https://challenges.cloudflare.com",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "base-uri 'none'",
].join('; ');

export const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy': CSP,
  // The Worker is only reachable over HTTPS, so committing to it costs nothing
  // and removes the first plaintext request on a repeat visit.
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  // Belt and braces with frame-ancestors, for anything that predates CSP.
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
};

/** The headers YSD Shield insists on. Lower-cased for comparison. */
export const REQUIRED_SECURITY_HEADERS = [
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
] as const;

/** Which required headers this build actually configures. */
export function configuredSecurityHeaders(): { present: string[]; missing: string[] } {
  const configured = new Set(Object.keys(SECURITY_HEADERS).map((name) => name.toLowerCase()));
  const present = REQUIRED_SECURITY_HEADERS.filter((name) => configured.has(name));
  const missing = REQUIRED_SECURITY_HEADERS.filter((name) => !configured.has(name));
  return { present: [...present], missing: [...missing] };
}
