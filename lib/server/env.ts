import { env } from 'cloudflare:workers';

/**
 * The Cloudflare environment, widened so the provider-neutral helpers in
 * `lib/` can read it by key without importing anything Cloudflare-specific.
 *
 * The intersection keeps `runtimeEnv.DB` and the documented variables fully
 * typed while allowing `runtimeEnv[someKey]`. This is the only place the
 * widening cast is written.
 */
export const runtimeEnv: Cloudflare.Env & Record<string, unknown> = env as Cloudflare.Env &
  Record<string, unknown>;
