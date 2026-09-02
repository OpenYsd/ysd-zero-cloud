import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const root = new URL('../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const self = new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1').split('/').join(path.sep);

function source(relative: string): string {
  return readFileSync(path.join(root, relative), 'utf8');
}

/**
 * Source with comments removed. The assertions below are about what the code
 * does; the comments deliberately name `useId` and `suppressHydrationWarning`
 * to explain why they are absent, and must not trip their own checks.
 */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** Every .ts/.tsx file we author, excluding build output and dependencies. */
function projectFiles(): string[] {
  const found: string[] = [];
  // `.claude` holds sibling git worktrees: whole stale copies of this same
  // tree, which would be scanned as if they were the source under test.
  const skip = new Set([
    'node_modules', 'dist', '.git', '.claude', '.wrangler', '.vite', '.next',
  ]);
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      if (skip.has(entry)) continue;
      const full = path.join(dir, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (/\.tsx?$/.test(entry)) found.push(full);
    }
  };
  walk(root);
  // This file necessarily spells out the tokens it forbids, so it is the one
  // file the scan must not read as evidence against itself.
  return found.filter((file) => file !== self);
}

/**
 * The hydration mismatch this guards against.
 *
 * Base UI's `SwitchRoot` labels its root element `base-ui-${React.useId()}` and
 * gives no way to override it — the `id` prop is spent on the hidden input, and
 * with the default `nativeButton={false}` the root always takes the generated
 * value. `useId` encodes tree position, and this framework's server render and
 * client hydration do not walk the same tree, so the two sides produced
 * different ids and React reported a mismatch on every authenticated page load.
 *
 * These are structural assertions rather than a render test on purpose: the
 * suite runs under `node --experimental-strip-types`, which does not transform
 * JSX, so no component in this repository can be rendered here without adding a
 * test toolchain. The behavioural half of this proof is the browser run — 20
 * fresh authenticated loads with zero hydration errors — and these assertions
 * are what stop the source from drifting back underneath it.
 */
void test('the Switch wrapper pins both of its ids instead of generating them', () => {
  const switchSource = source('components/ui/switch.tsx');

  // The root id can only be reached through `render`; the hidden input through
  // `id`. Both must be derived from the caller's value.
  assert.match(switchSource, /render=\{<span id=\{id\} \/>\}/);
  assert.match(switchSource, /id=\{`\$\{id\}-control`\}/);

  // `id` is required, so a new Switch cannot compile without a stable one, and
  // it is removed from the inherited props so Base UI cannot reclaim it.
  assert.match(switchSource, /Omit<SwitchPrimitive\.Root\.Props, 'id' \| 'render'>/);
  assert.match(switchSource, /\n  id: string;/);

  // Nothing here may reintroduce a generated or nondeterministic value.
  assert.doesNotMatch(code(switchSource), /useId|Math\.random|Date\.now/);
});

void test('every Switch call site supplies a stable, unique id', () => {
  const callSites: { file: string; props: string }[] = [];

  for (const file of projectFiles()) {
    if (file.endsWith(path.join('components', 'ui', 'switch.tsx'))) continue;
    const text = readFileSync(file, 'utf8');
    let index = text.indexOf('<Switch');
    while (index !== -1) {
      // Everything up to the end of the opening tag is the prop list.
      const end = text.indexOf('>', index);
      callSites.push({
        file: path.relative(root, file),
        props: text.slice(index, end === -1 ? index + 400 : end),
      });
      index = text.indexOf('<Switch', index + 1);
    }
  }

  assert.ok(callSites.length >= 3, 'expected the known Switch call sites');

  for (const site of callSites) {
    assert.match(
      site.props,
      /\bid=/,
      `${site.file} renders a Switch without an id, which reintroduces the generated one`,
    );
    assert.doesNotMatch(
      site.props,
      /id=\{(Math\.random|useId|Date\.now)/,
      `${site.file} derives a Switch id from a nondeterministic value`,
    );
  }

  // Literal ids must not collide, or the page gets duplicate DOM ids.
  const literals = callSites
    .map((site) => /\bid="([^"]+)"/.exec(site.props)?.[1])
    .filter((value): value is string => Boolean(value));
  assert.equal(new Set(literals).size, literals.length, 'Switch ids must be unique');
});

void test('hydration warnings are never suppressed anywhere in the app', () => {
  // Silencing the warning would hide the next real mismatch instead of fixing
  // it, so the absence of the escape hatch is itself the invariant.
  for (const file of projectFiles()) {
    assert.doesNotMatch(
      code(readFileSync(file, 'utf8')),
      /suppressHydrationWarning/,
      `${path.relative(root, file)} suppresses hydration warnings`,
    );
  }
});

/**
 * The other defect the same browser run surfaced: `/audit` threw
 * "Invalid hook call ... more than one copy of React" and failed to render,
 * because it was the one file still importing `next/link`. That module resolves
 * to a separately pre-bundled dependency carrying its own React.
 *
 * `components/nav-link.tsx` documents why this application does not use
 * `next/link` at all; this keeps the exception from creeping back.
 */
void test('nothing imports next/link, which crashes the route that renders it', () => {
  for (const file of projectFiles()) {
    const text = readFileSync(file, 'utf8');
    assert.doesNotMatch(
      text,
      /^\s*import\s+[^;]*from\s+['"]next\/link['"]/m,
      `${path.relative(root, file)} imports next/link`,
    );
  }

  // The export controls on the audit page are plain anchors: they point at API
  // endpoints, which a client-side router transition cannot serve anyway.
  const audit = source('components/collaboration-views.tsx');
  assert.match(audit, /<NavLink href="\/api\/audit\?format=csv"/);
  assert.match(audit, /<NavLink href="\/api\/audit\?format=json"/);
  assert.match(audit, /import \{ NavLink \} from '@\/components\/nav-link';/);
});
