/**
 * Builds the distributable Compute Node agent.
 *
 * One self-contained ESM file, no `node_modules`, no repository, no TypeScript
 * flag. That is possible because the agent's whole transitive graph imports
 * nothing but `node:*` built-ins; this script asserts that rather than assuming
 * it, so the day somebody adds a dependency the build fails here instead of
 * shipping an artifact that cannot run on a user's machine.
 *
 * The output is deterministic: same source in, same bytes and same digest out.
 * Nothing about the build machine -- path, user, clock, or random value -- is
 * embedded. `npm run agent:build` twice and compare; a test does exactly that.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputDirectory = path.join(root, 'public', 'agent');

const nodes = readFileSync(path.join(root, 'lib', 'nodes.ts'), 'utf8');
const version = nodes.match(/CURRENT_AGENT_VERSION = '([^']+)'/)?.[1];
const protocolVersion = Number(nodes.match(/NODE_PROTOCOL_VERSION = (\d+)/)?.[1]);
const minimumNodeVersion = readFileSync(path.join(root, 'lib', 'agent-release.ts'), 'utf8')
  .match(/MINIMUM_NODE_VERSION = '([^']+)'/)?.[1];

if (!version || !Number.isInteger(protocolVersion) || !minimumNodeVersion) {
  throw new Error('Could not read the agent release constants from source.');
}

const filename = `ysd-node-agent-${version}.mjs`;
const artifact = path.join(outputDirectory, filename);

rmSync(outputDirectory, { recursive: true, force: true });
mkdirSync(outputDirectory, { recursive: true });

// Rolldown is already a repository build dependency (it is what bundles the
// Worker), so this adds no new tooling. `--platform node` keeps `node:*`
// specifiers external instead of trying to polyfill them, and no sourcemap is
// emitted -- a map would carry absolute build-machine paths into a file we ask
// strangers to download.
execFileSync(
  process.execPath,
  [
    path.join(root, 'node_modules', 'rolldown', 'bin', 'cli.mjs'),
    path.join(root, 'agent', 'cli.ts'),
    '--file', artifact,
    '--format', 'esm',
    '--platform', 'node',
  ],
  { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] },
);

const bundle = readFileSync(artifact, 'utf8');

// --- Release gates -------------------------------------------------------

const external = [...bundle.matchAll(/from\s*["']([^"']+)["']/g)].map((match) => match[1]);
const nonBuiltin = [...new Set(external)].filter((id) => !id.startsWith('node:'));
if (nonBuiltin.length > 0) {
  throw new Error(
    `The agent bundle still imports ${nonBuiltin.join(', ')}. `
    + 'It must depend on node: built-ins only, or a downloaded artifact cannot run.',
  );
}

for (const [label, pattern] of [
  ['a require() call', /\brequire\s*\(/],
  ['an absolute Windows build path', /[A-Za-z]:\\\\?Users/],
  ['an absolute POSIX build path', /\/(?:home|Users)\/[A-Za-z0-9_.-]+\//],
  ['a sourcemap reference', /\/\/# sourceMappingURL=/],
]) {
  if (pattern.test(bundle)) {
    throw new Error(`The agent bundle contains ${label}, which must not ship.`);
  }
}

// The build machine's own paths, checked by value rather than by shape. The
// bundle legitimately contains the string "node_modules" -- the agent locates
// npm on the NODE's machine and refuses entrypoints under it -- so a blanket
// ban on the word would reject correct output. What must never appear is this
// checkout's location.
// Only the absolute forms. The directory BASENAME is not a leak: this
// repository is named after the product, so `ysd-zero-cloud` legitimately
// appears inside protocol constants like `ysd-zero-cloud/app-runtime-env-v1`.
for (const leak of [root, root.split(path.sep).join('/')]) {
  if (bundle.includes(leak)) {
    throw new Error('The agent bundle embeds the build machine path, which must not ship.');
  }
}

const digest = createHash('sha256').update(readFileSync(artifact)).digest('hex');
const size = Buffer.byteLength(readFileSync(artifact));

writeFileSync(path.join(outputDirectory, `${filename}.sha256`), `${digest}  ${filename}\n`);

// No `builtAt`. A timestamp would make two builds of identical source differ,
// which would quietly destroy the reproducibility this design depends on.
const manifest = {
  version,
  protocolVersion,
  minimumNodeVersion,
  filename,
  downloadPath: `/agent/${filename}`,
  sha256: digest,
  size,
};
writeFileSync(
  path.join(outputDirectory, 'manifest.json'),
  `${JSON.stringify(manifest, null, 2)}\n`,
);

// The artifact has to actually start. A bundle that throws on load is worse
// than no bundle, because the failure lands on the user's machine.
const reported = execFileSync(process.execPath, [artifact, '--version'], {
  cwd: outputDirectory,
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'pipe'],
}).trim();
if (!reported.includes(version) || !reported.includes(String(protocolVersion))) {
  throw new Error(`The built agent reported "${reported}", which does not match the release.`);
}

console.log(`agent ${version} -> public/agent/${filename}`);
console.log(`  sha256 ${digest}`);
console.log(`  size   ${size} bytes`);
console.log(`  ${reported.split('\n').join(' / ')}`);
