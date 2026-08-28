import { isTurnstileConfigured, readTurnstileConfig, TURNSTILE_OK, verifyTurnstileToken, type TurnstileVerdict } from '@/lib/turnstile';
import { runtimeEnv } from './env';

/**
 * Server-side Turnstile verification.
 *
 * When no keys are configured the widget cannot render, so no token can exist
 * and every request would fail a mandatory check — including the owner's own
 * sign-in. The verdict is therefore a pass, and the missing protection is
 * reported by YSD Shield and on the Settings page instead of silently
 * pretending to be on.
 */
export function turnstileConfigured(): boolean {
  return isTurnstileConfigured(runtimeEnv);
}

/** The public key the widget needs, or null when Turnstile is not set up. */
export function turnstileSiteKey(): string | null {
  return readTurnstileConfig(runtimeEnv)?.siteKey ?? null;
}

export async function verifyTurnstile(token: string, remoteIp: string): Promise<TurnstileVerdict> {
  const config = readTurnstileConfig(runtimeEnv);
  if (!config) return TURNSTILE_OK;
  return verifyTurnstileToken(token, config.secretKey, remoteIp || undefined);
}
