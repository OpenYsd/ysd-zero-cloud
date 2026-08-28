import { sites } from '@openai/sites-vite-plugin';
import tailwindcss from '@tailwindcss/postcss';
import vinext from 'vinext';
import { defineConfig } from 'vite';
import hostingConfig from './.openai/hosting.json';

// macOS Seatbelt blocks FSEvents, so Codex previews need polling for HMR.
const isCodexSeatbeltSandbox = process.env.CODEX_SANDBOX === 'seatbelt';

/**
 * Vite-only worker settings.
 *
 * Bindings, the compatibility date, and the flags all live in
 * `wrangler.jsonc`. The Cloudflare plugin concatenates this object onto the
 * file config rather than replacing it, so declaring a binding in both places
 * produces two entries with the same name and a deploy that Cloudflare
 * rejects. Only the dev entrypoint belongs here.
 *
 * `.openai/hosting.json` still declares which managed resources the project
 * wants; it is asserted against `wrangler.jsonc` below so the two cannot
 * silently disagree.
 */
const localBindingConfig = {
  main: 'vinext/server/fetch-handler',
};

if (hostingConfig.d1 && hostingConfig.d1 !== 'DB') {
  throw new Error(
    `.openai/hosting.json declares the D1 binding "${hostingConfig.d1}", but wrangler.jsonc binds "DB".`,
  );
}

/**
 * Where Miniflare keeps its local D1 and cache files.
 *
 * Miniflare writes each simulated database to
 * `<state>/v3/d1/miniflare-D1DatabaseObject/<database-id>.sqlite`. On Windows
 * that path plus a deep checkout can cross the 260-character limit, and SQLite
 * fails to open the file with a message that surfaces only as an opaque
 * internal error. Point `YSD_LOCAL_STATE_PATH` at something short (for example
 * `C:/ysd-state`) when that happens; it affects local development only.
 */
const localStatePath = process.env.YSD_LOCAL_STATE_PATH ?? '.wrangler/state';

export default defineConfig(async () => {
  // Keep Wrangler and Miniflare state project-local. These are non-secret tool
  // settings; application environment belongs in ignored `.env*` files.
  process.env.WRANGLER_WRITE_LOGS ??= 'false';
  process.env.WRANGLER_LOG_PATH ??= '.wrangler/logs';
  process.env.MINIFLARE_REGISTRY_PATH ??= '.wrangler/registry';

  // Wrangler snapshots its log path while the Cloudflare plugin is imported.
  const { cloudflare } = await import('@cloudflare/vite-plugin');

  return {
    css: { postcss: { plugins: [tailwindcss()] } },
    server: isCodexSeatbeltSandbox
      ? { watch: { useFsEvents: false, usePolling: true } }
      : undefined,
    plugins: [
      vinext(),
      sites(),
      cloudflare({
        viteEnvironment: { name: 'rsc', childEnvironments: ['ssr'] },
        config: localBindingConfig,
        persistState: { path: localStatePath },
      }),
    ],
  };
});
