/**
 * Normalises the deploy config the Vite build emits.
 *
 * `@cloudflare/vite-plugin` writes `dist/server/wrangler.json` using the
 * wrangler version it bundles, which still emits fields a newer wrangler
 * rejects outright — `legacy_env` is refused with an error rather than a
 * warning. Rather than pin the CLI back or hand-edit a build artifact, this
 * step strips the fields that are known-removed and leaves everything else
 * untouched.
 *
 * Run between `build` and `wrangler deploy`; `npm run deploy` does both.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const CONFIG = join('dist', 'server', 'wrangler.json');

/**
 * Fields removed from the Wrangler config schema. Each is dropped only when
 * present, so this stays a no-op once the plugin stops emitting them.
 */
const REMOVED_FIELDS = ['legacy_env'];

const raw = await readFile(CONFIG, 'utf8').catch(() => null);
if (raw === null) {
  console.error(`${CONFIG} not found. Run \`npm run build\` first.`);
  process.exit(1);
}

const config = JSON.parse(raw);
const dropped = REMOVED_FIELDS.filter((field) => field in config);
for (const field of dropped) delete config[field];

// The plugin concatenates its own settings onto the file config, which can
// repeat a flag. Duplicates are harmless to workerd but noisy in a diff.
if (Array.isArray(config.compatibility_flags)) {
  config.compatibility_flags = [...new Set(config.compatibility_flags)];
}

await writeFile(CONFIG, `${JSON.stringify(config, null, 2)}\n`, 'utf8');

console.log(
  dropped.length > 0
    ? `Normalised ${CONFIG}: removed ${dropped.join(', ')}`
    : `Normalised ${CONFIG}: nothing to remove`,
);
