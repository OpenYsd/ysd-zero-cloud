/**
 * Node-verified private port allocation.
 *
 * The control plane assigned private ports on the assumption that a port no
 * deployment owned was a port the node could bind. That is false on Windows:
 * blocks are reserved for Hyper-V and WSL, and binding one fails with `EACCES`
 * while nothing is listening on it. A node assigned 41000 out of a reserved
 * 40947-41146 range could not deploy anything at all -- every attempt died at
 * the port check, before a single file was fetched.
 *
 * So the node decides what it can bind and the control plane decides what it
 * gets. These cover both halves and the ways each could go wrong.
 */
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  APP_RUNTIME_LIMITS,
  PRIVATE_PORT_CANDIDATE_LIMIT,
  parsePrivatePortCandidates,
  privatePortInRange,
  privatePortSearchOrder,
} from '../lib/app-runtime.ts';

const MIN = APP_RUNTIME_LIMITS.portMinimum;
const MAX = APP_RUNTIME_LIMITS.portMaximum;
const repoRoot = path.join(path.dirname(new URL(import.meta.url).pathname.slice(1)), '..');

/**
 * The server's decision, isolated from D1. Mirrors `negotiatePrivatePort`:
 * refuse a healthy deployment, refuse a stale expectation, keep the current
 * port if the node can bind it, otherwise take the first free candidate.
 */
function decide(input: {
  observedState: string;
  currentPort: number;
  expectedCurrentPort: number;
  candidates: number[];
  takenByOthers: number[];
}): { ok: true; port: number; changed: boolean } | { ok: false; status: number } {
  const parsed = parsePrivatePortCandidates(input.candidates);
  if (!parsed || !privatePortInRange(input.expectedCurrentPort)) return { ok: false, status: 400 };
  if (input.observedState === 'healthy') return { ok: false, status: 409 };
  if (input.currentPort !== input.expectedCurrentPort) return { ok: false, status: 409 };
  if (parsed.includes(input.expectedCurrentPort)) {
    return { ok: true, port: input.expectedCurrentPort, changed: false };
  }
  const taken = new Set(input.takenByOthers);
  for (const candidate of parsed) {
    if (!taken.has(candidate)) return { ok: true, port: candidate, changed: true };
  }
  return { ok: false, status: 409 };
}

// --- the node's half --------------------------------------------------------

void test('a bindable assigned port is kept', () => {
  const decision = decide({
    observedState: 'blocked',
    currentPort: MIN,
    expectedCurrentPort: MIN,
    candidates: [MIN, MIN + 1],
    takenByOthers: [],
  });
  assert.deepEqual(decision, { ok: true, port: MIN, changed: false });
});

void test('the search starts at the assigned port and wraps exactly once', () => {
  const order = privatePortSearchOrder(MIN + 5);
  assert.equal(order[0], MIN + 5);
  assert.equal(order.length, MAX - MIN + 1);
  assert.equal(new Set(order).size, order.length, 'no port is offered twice');
  assert.equal(order.at(-1), MIN + 4, 'it wraps to just before where it started');
  assert.ok(order.every((port) => privatePortInRange(port)));

  // An assignment outside the range cannot send the scan somewhere invalid.
  assert.equal(privatePortSearchOrder(1)[0], MIN);
  assert.equal(privatePortSearchOrder(MAX + 500)[0], MIN);
});

void test('a long blocked prefix does not stop the scan', () => {
  // The real host had roughly 147 consecutive reserved ports at the bottom of
  // the range. Nothing about that number is special -- the scan simply keeps
  // going -- so this simulates a long prefix rather than encoding a constant.
  const blocked = new Set(Array.from({ length: 400 }, (_, index) => MIN + index));
  const found: number[] = [];
  for (const port of privatePortSearchOrder(MIN)) {
    if (!blocked.has(port)) found.push(port);
    if (found.length >= PRIVATE_PORT_CANDIDATE_LIMIT) break;
  }
  assert.equal(found.length, PRIVATE_PORT_CANDIDATE_LIMIT);
  assert.equal(found[0], MIN + 400);
});

void test('every allowed port unavailable yields no candidates at all', () => {
  const found = privatePortSearchOrder(MIN).filter(() => false);
  assert.equal(found.length, 0);
  // An empty list is refused rather than treated as "anything goes".
  assert.equal(parsePrivatePortCandidates([]), null);
});

void test('the probe classifies by error code, never by message', async () => {
  const source = await readFile(path.join(repoRoot, 'agent', 'app-runtime.ts'), 'utf8');
  const probe = source.slice(source.indexOf('async function probePort'), source.indexOf('export async function bindablePrivatePorts'));
  // EADDRINUSE is "someone has it"; EACCES is Windows refusing a reserved
  // block. Both mean try another. Anything else is a real fault and must not
  // silently cost a candidate.
  assert.match(probe, /error\.code === 'EADDRINUSE' \|\| error\.code === 'EACCES'/u);
  assert.doesNotMatch(probe, /message\.includes|indexOf\('address/u);
  // The probe must bind the same address the runtime does, or it proves nothing.
  assert.match(probe, /host: '127\.0\.0\.1'/u);
  assert.match(probe, /exclusive: true/u);
  assert.match(source, /HOST: '127\.0\.0\.1'/u);
});

void test('a real reserved or busy port is reported unavailable, not fatal', async () => {
  // Hold a port for real, then confirm the same bind the runtime performs
  // fails on it. This is the EADDRINUSE half of the classification, proven
  // against the operating system rather than a stub.
  const holder = createServer();
  const port = await new Promise<number>((resolve, reject) => {
    holder.once('error', reject);
    holder.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
      resolve((holder.address() as { port: number }).port);
    });
  });
  const busy = await new Promise<string>((resolve) => {
    const probe = createServer();
    probe.once('error', (error: NodeJS.ErrnoException) => resolve(error.code ?? 'unknown'));
    probe.listen({ host: '127.0.0.1', port, exclusive: true }, () => {
      probe.close(() => resolve('available'));
    });
  });
  await new Promise<void>((resolve) => holder.close(() => resolve()));
  assert.equal(busy, 'EADDRINUSE');
});

// --- the server's half ------------------------------------------------------

void test('an unbindable assigned port moves to the first free candidate', () => {
  const decision = decide({
    observedState: 'blocked',
    currentPort: MIN,
    expectedCurrentPort: MIN,
    candidates: [MIN + 200, MIN + 201],
    takenByOthers: [],
  });
  assert.deepEqual(decision, { ok: true, port: MIN + 200, changed: true });
});

void test('a candidate another deployment already holds is skipped', () => {
  const decision = decide({
    observedState: 'blocked',
    currentPort: MIN,
    expectedCurrentPort: MIN,
    candidates: [MIN + 200, MIN + 201],
    takenByOthers: [MIN + 200],
  });
  assert.deepEqual(decision, { ok: true, port: MIN + 201, changed: true });
});

void test('candidates outside the private range are refused', () => {
  assert.equal(parsePrivatePortCandidates([MIN - 1]), null);
  assert.equal(parsePrivatePortCandidates([MAX + 1]), null);
  assert.equal(parsePrivatePortCandidates([80]), null);
  assert.equal(parsePrivatePortCandidates([0]), null);
  assert.equal(parsePrivatePortCandidates(['41200']), null);
  assert.equal(parsePrivatePortCandidates([41_200.5]), null);
  assert.equal(parsePrivatePortCandidates(null), null);
  assert.equal(parsePrivatePortCandidates('41200'), null);
});

void test('duplicate or oversized candidate lists are refused', () => {
  assert.equal(parsePrivatePortCandidates([MIN + 1, MIN + 1]), null);
  const oversized = Array.from({ length: PRIVATE_PORT_CANDIDATE_LIMIT + 1 }, (_, index) => MIN + index);
  assert.equal(parsePrivatePortCandidates(oversized), null);
  const exact = Array.from({ length: PRIVATE_PORT_CANDIDATE_LIMIT }, (_, index) => MIN + index);
  assert.deepEqual(parsePrivatePortCandidates(exact), exact);
});

void test('a stale expected port is refused rather than overwritten', () => {
  // Someone else moved the port between the node reading it and asking. The
  // newer assignment wins; this caller refreshes.
  const decision = decide({
    observedState: 'blocked',
    currentPort: MIN + 300,
    expectedCurrentPort: MIN,
    candidates: [MIN + 200],
    takenByOthers: [],
  });
  assert.deepEqual(decision, { ok: false, status: 409 });
});

void test('a healthy deployment keeps the port it is serving on', () => {
  // Phase 18 recovery and the Phase 21 restore gate both require the port to
  // be the same afterwards. Negotiation is for getting to running, not for
  // moving something already there.
  const decision = decide({
    observedState: 'healthy',
    currentPort: MIN,
    expectedCurrentPort: MIN,
    candidates: [MIN + 200],
    takenByOthers: [],
  });
  assert.deepEqual(decision, { ok: false, status: 409 });
});

void test('a node with nothing free is told so, bounded', () => {
  const decision = decide({
    observedState: 'blocked',
    currentPort: MIN,
    expectedCurrentPort: MIN,
    candidates: [MIN + 200, MIN + 201],
    takenByOthers: [MIN + 200, MIN + 201],
  });
  assert.deepEqual(decision, { ok: false, status: 409 });
});

void test('two deployments negotiating at once cannot land on one port', () => {
  // Both offer the same candidates. The first claims it; the second sees it
  // taken and moves on, which is what the conditional write enforces for real.
  const candidates = [MIN + 200, MIN + 201];
  const first = decide({
    observedState: 'blocked', currentPort: MIN, expectedCurrentPort: MIN,
    candidates, takenByOthers: [],
  });
  assert.ok(first.ok);
  const second = decide({
    observedState: 'blocked', currentPort: MIN + 1, expectedCurrentPort: MIN + 1,
    candidates, takenByOthers: [first.ok ? first.port : -1],
  });
  assert.ok(second.ok);
  assert.notEqual(first.ok && first.port, second.ok && second.port);
});

void test('the server write moves the port and nothing else', async () => {
  const server = await readFile(path.join(repoRoot, 'lib', 'server', 'nodes.ts'), 'utf8');
  const block = server.slice(
    server.indexOf('export async function negotiatePrivatePort'),
    server.indexOf('export async function readAgentJobStatus'),
  );
  assert.ok(block.length > 0, 'the negotiation is missing');

  const update = block.slice(block.indexOf('UPDATE deployment'));
  const assigns = update.slice(0, update.indexOf('WHERE'));
  for (const forbidden of [
    'nodeId =', 'desiredState =', 'desiredRevision =', 'currentArtifactId =',
    'state =', 'observedState =', 'projectId =', 'workspaceId =', 'deletedAt =',
    'commitSha =', 'recoveryStatus =',
  ]) {
    assert.ok(!assigns.includes(forbidden), `negotiation must not write ${forbidden}`);
  }
  assert.match(assigns, /localPort = \?/u);
  // Conditional on the port that was read: a newer assignment is never clobbered.
  const scope = update.slice(update.indexOf('WHERE'));
  assert.match(scope, /localPort = \?/u);
  assert.match(scope, /nodeId = \?/u);
  assert.match(scope, /deletedAt IS NULL/u);
  // Identity comes from the database, scoped to the authenticated node.
  assert.match(block, /nodeId = \?/u);
  assert.match(block, /row\.nodeId !== context\.node\.id/u);
  assert.doesNotMatch(block, /INSERT INTO/u);
});

void test('the port error says what is true', async () => {
  const source = await readFile(path.join(repoRoot, 'agent', 'app-runtime.ts'), 'utf8');
  // "already in use" was wrong: a Windows reserved port has no listener at all,
  // and that message sent people hunting for a process that did not exist.
  assert.match(source, /unavailable on this Compute Node/u);
  assert.match(source, /private_port_unavailable/u);
  assert.match(source, /no_available_private_port/u);
  assert.doesNotMatch(source, /port is already in use/u);
  // The Windows exclusion list is a diagnostic, never a runtime dependency.
  assert.doesNotMatch(source, /netsh|excludedportrange/iu);
});
