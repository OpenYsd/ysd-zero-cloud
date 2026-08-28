/**
 * Cloudflare Turnstile.
 *
 * Turnstile is free on every Cloudflare plan, which is why it is the CAPTCHA
 * this project uses. It protects the two unauthenticated endpoints that do
 * real work — sign-up and sign-in — from automated abuse.
 *
 * The protection is configuration-gated. With no keys the widget cannot render
 * and a token cannot exist, so requiring one would lock every operator out of
 * their own instance. Instead the surfaces report Turnstile as not configured
 * and YSD Shield raises it as a finding, which is visible rather than silent.
 */

const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export type TurnstileConfig = {
  siteKey: string;
  secretKey: string;
};

/** Reads the keys, treating blanks as absent. */
export function readTurnstileConfig(
  env: Record<string, unknown>,
): TurnstileConfig | null {
  const siteKey = typeof env.TURNSTILE_SITE_KEY === 'string' ? env.TURNSTILE_SITE_KEY.trim() : '';
  const secretKey =
    typeof env.TURNSTILE_SECRET_KEY === 'string' ? env.TURNSTILE_SECRET_KEY.trim() : '';
  if (!siteKey || !secretKey) return null;
  return { siteKey, secretKey };
}

export function isTurnstileConfigured(env: Record<string, unknown>): boolean {
  return readTurnstileConfig(env) !== null;
}

/** The shape Cloudflare's siteverify endpoint returns. */
export type SiteVerifyResponse = {
  success?: boolean;
  'error-codes'?: string[];
  challenge_ts?: string;
  hostname?: string;
};

export type TurnstileVerdict = {
  ok: boolean;
  /** Machine-readable reason when `ok` is false. */
  reason: string;
  /** Safe to show a person. */
  message: string;
};

export const TURNSTILE_OK: TurnstileVerdict = { ok: true, reason: '', message: '' };

/**
 * Interprets a siteverify response.
 *
 * Kept separate from the network call so every branch is testable without a
 * live endpoint.
 */
export function interpretSiteVerify(
  body: SiteVerifyResponse | null,
  status: number,
): TurnstileVerdict {
  if (body === null) {
    // A verification service that cannot be reached must fail closed. Treating
    // an outage as a pass would turn a dependency blip into an open door.
    return {
      ok: false,
      reason: 'unreachable',
      message: 'The challenge could not be verified. Try again in a moment.',
    };
  }
  if (status !== 200) {
    return {
      ok: false,
      reason: `http-${status}`,
      message: 'The challenge could not be verified. Try again in a moment.',
    };
  }
  if (body.success === true) return TURNSTILE_OK;

  const codes = body['error-codes'] ?? [];
  if (codes.includes('timeout-or-duplicate')) {
    return {
      ok: false,
      reason: 'timeout-or-duplicate',
      message: 'That challenge has expired. Please try again.',
    };
  }
  if (codes.includes('missing-input-response')) {
    return {
      ok: false,
      reason: 'missing-token',
      message: 'Please complete the challenge before continuing.',
    };
  }
  return {
    ok: false,
    reason: codes.join(',') || 'rejected',
    message: 'The challenge was rejected. Please try again.',
  };
}

/**
 * Verifies a token against Cloudflare.
 *
 * @param remoteIp Caller address, passed through so Cloudflare can weigh it.
 */
export async function verifyTurnstileToken(
  token: string,
  secretKey: string,
  remoteIp?: string,
): Promise<TurnstileVerdict> {
  if (!token.trim()) {
    return {
      ok: false,
      reason: 'missing-token',
      message: 'Please complete the challenge before continuing.',
    };
  }

  const form = new FormData();
  form.set('secret', secretKey);
  form.set('response', token);
  if (remoteIp) form.set('remoteip', remoteIp);

  try {
    const response = await fetch(VERIFY_URL, {
      method: 'POST',
      body: form,
      signal: AbortSignal.timeout(5000),
    });
    const body = (await response.json()) as SiteVerifyResponse;
    return interpretSiteVerify(body, response.status);
  } catch {
    return interpretSiteVerify(null, 0);
  }
}
