/**
 * The managed Agent upgrade transaction.
 *
 * Phase 19 could install a managed Agent and start it at login, but replacing
 * that Agent was a non-transactional overwrite: copy the new release, rewrite
 * the launcher, rewrite the metadata, re-register with the OS. If the new Agent
 * then failed to start, nothing on the machine remembered what had worked, and
 * `previousVersion` was a bare string with no path and no hash behind it.
 *
 * Phase 20 makes the replacement a transaction with one authority: the managed
 * install file. Everything here is pure. It decides *what the metadata should
 * say*; `autostart.ts` writes it atomically and the generated launcher applies
 * it. Keeping the decisions pure is what lets the same rules be tested directly
 * and re-derived inside the standalone launcher.
 *
 * Two properties are load-bearing and easy to lose:
 *
 *   * The top-level Phase 19 fields (`agentVersion`, `releasePath`,
 *     `releaseHash`) always name a release that is known to work. A candidate
 *     lives in `upgrade.candidate` until it proves itself, so a launcher that
 *     understands none of this still starts something good.
 *   * Rollback targets the *exact* recorded release -- version, path and hash --
 *     and nothing else. There is no search for a plausible substitute.
 */
import { createHash } from 'node:crypto';
import path from 'node:path';

import { compareStrictVersions, isStrictVersion } from '../lib/nodes.ts';

export const AUTOSTART_CRASH_LIMIT = 3;
export const AUTOSTART_CRASH_WINDOW_MS = 10 * 60_000;
export const AUTOSTART_RESTART_DELAY_MS = 2_000;
export const AUTOSTART_LOG_FILES = 4;
export const AUTOSTART_LOG_MAX_BYTES = 256 * 1024;

/**
 * How many times a candidate may be started before the trial is abandoned.
 *
 * Two: one first start, and one restart in case the first failed for a reason
 * that does not repeat. A third attempt buys nothing -- an Agent that cannot
 * complete its own startup twice in a row is not going to on the next try --
 * and every extra attempt is another minute where the node is not running any
 * Agent at all.
 */
export const UPGRADE_TRIAL_ATTEMPT_LIMIT = 2;

/**
 * How long a live candidate may go without a readiness proof before the local
 * status says so. This is a *reporting* threshold, never a kill: the Agent
 * retries the control plane in-process and does not exit when the network is
 * down, so terminating it here would turn an outage into a version downgrade.
 */
export const UPGRADE_READINESS_NOTICE_MS = 120_000;

/** Free space required before a candidate is staged, on top of its own size. */
export const UPGRADE_MINIMUM_FREE_BYTES = 64 * 1024 * 1024;

/** Failed candidates remembered by hash so they are never retried silently. */
export const UPGRADE_QUARANTINE_LIMIT = 8;

/** Releases retained with no transaction in flight: current and previous. */
export const MANAGED_RELEASE_LIMIT = 2;

/** Releases retained mid-transaction: previous, current, and the candidate. */
export const MANAGED_RELEASE_TRANSACTION_LIMIT = 3;

/**
 * The additive metadata revision. The install file's own `version` stays `1`
 * on purpose -- the Phase 19 launcher validates that exact value and would
 * refuse a file that claimed anything else, stranding a node mid-migration.
 */
export const MANAGED_INSTALL_SCHEMA = 2 as const;

export const AGENT_EXIT = {
  clean: 0,
  alreadyRunning: 20,
  authorizationRejected: 21,
  credentialInvalid: 22,
  unsupportedRuntime: 23,
  controlledShutdown: 24,
} as const;

export type AutostartManager =
  | 'windows-task-scheduler'
  | 'systemd-user'
  | 'launchagent';

export const MANAGERS = [
  'windows-task-scheduler',
  'systemd-user',
  'launchagent',
] as const;

export type AutostartState =
  | 'enabled'
  | 'disabled'
  | 'manager_missing'
  | 'agent_missing'
  | 'node_runtime_missing'
  | 'registration_invalid'
  | 'upgrade_required'
  | 'credential_key_unavailable'
  | 'restart_limited'
  | 'authorization_rejected'
  | 'already_running'
  | 'stopped'
  | 'starting';

export const STATES = [
  'enabled',
  'disabled',
  'manager_missing',
  'agent_missing',
  'node_runtime_missing',
  'registration_invalid',
  'upgrade_required',
  'credential_key_unavailable',
  'restart_limited',
  'authorization_rejected',
  'already_running',
  'stopped',
  'starting',
] as const;

/**
 * The transaction states. Deliberately five.
 *
 *   idle              no transaction; the top-level release is what runs
 *   staged            a verified candidate exists but has not been handed the
 *                     machine yet, so the known-good Agent still runs. An
 *                     interruption here is invisible.
 *   trial             the launcher starts the candidate and waits for proof.
 *                     The top-level release is still the known-good one.
 *   rollback_pending  the trial has been judged failed and the decision is
 *                     durable, but the quarantine record is not written yet.
 *   blocked           the trial ended for a reason the previous Agent shares,
 *                     so nothing starts until a person intervenes.
 */
export const UPGRADE_STATES = ['idle', 'staged', 'trial', 'rollback_pending', 'blocked'] as const;
export type UpgradeState = (typeof UPGRADE_STATES)[number];

/** Fixed reasons. No raw exception text ever reaches metadata or a log line. */
export const UPGRADE_REASONS = [
  'candidate_hash_mismatch',
  'candidate_start_failed',
  'candidate_incompatible',
  'candidate_quarantined',
  'authorization_rejected',
  'credential_invalid',
  'network_unavailable',
  'previous_missing',
  'previous_corrupted',
  'transaction_interrupted',
  'low_disk',
  'maintenance_busy',
  'node_runtime_missing',
  'ownership_conflict',
  'already_current',
  'downgrade_refused',
  'candidate_unreadable',
] as const;
export type UpgradeReason = (typeof UPGRADE_REASONS)[number];

/** The headless projection published in `status.json`. Never authoritative. */
export const UPGRADE_STATUS_STATES = [
  'upgrade_idle',
  'upgrade_staged',
  'upgrade_trial',
  'upgrade_waiting_for_network',
  'upgrade_succeeded',
  'upgrade_rolled_back',
  'upgrade_failed',
  'upgrade_blocked',
] as const;
export type UpgradeStatusState = (typeof UPGRADE_STATUS_STATES)[number];

export type ManagedRelease = {
  version: string;
  releasePath: string;
  releaseHash: string;
};

export type QuarantinedRelease = {
  version: string;
  releaseHash: string;
  reason: UpgradeReason;
};

export type ManagedUpgrade = {
  state: UpgradeState;
  transactionId: string;
  generation: number;
  candidate: ManagedRelease | null;
  attempts: number;
  reason: UpgradeReason | null;
  quarantine: QuarantinedRelease[];
  updatedAt: number;
};

export type UpgradeStatus = {
  state: UpgradeStatusState;
  reason: UpgradeReason | null;
  transactionId: string;
  candidateVersion: string | null;
};

export type ReadinessMarker = {
  version: 1;
  transactionId: string;
  generation: number;
  agentVersion: string;
  acceptedAt: number;
};

const NULL_TRANSACTION = '0'.repeat(32);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function canonicalCredentialPath(value: string): string {
  const absolute = path.resolve(value);
  return process.platform === 'win32' ? absolute.toLowerCase() : absolute;
}

/**
 * The per-node managed identity. Two nodes paired from one machine, or one node
 * re-paired into a different credential file, are different installs with
 * different releases, different transactions and different locks.
 */
export async function deriveManagedIdentity(
  credentialPath: string,
  nodeId: string,
): Promise<string> {
  return createHash('sha256')
    .update(`${canonicalCredentialPath(credentialPath)}\0${nodeId}`)
    .digest('hex')
    .slice(0, 16);
}

export function idleUpgrade(now = 0): ManagedUpgrade {
  return {
    state: 'idle',
    transactionId: NULL_TRANSACTION,
    generation: 0,
    candidate: null,
    attempts: 0,
    reason: null,
    quarantine: [],
    updatedAt: now,
  };
}

export function isManagedRelease(value: unknown): value is ManagedRelease {
  return (
    isRecord(value) &&
    isStrictVersion(value.version) &&
    typeof value.releasePath === 'string' &&
    path.isAbsolute(value.releasePath) &&
    !value.releasePath.includes(String.fromCharCode(0)) &&
    !/[\r\n]/u.test(value.releasePath) &&
    typeof value.releaseHash === 'string' &&
    /^[a-f0-9]{64}$/u.test(value.releaseHash)
  );
}

export function validateManagedUpgrade(value: unknown): ManagedUpgrade | null {
  if (!isRecord(value)) return null;
  const expected = [
    'attempts', 'candidate', 'generation', 'quarantine', 'reason', 'state', 'transactionId', 'updatedAt',
  ];
  if (Object.keys(value).sort().join('\0') !== expected.sort().join('\0')) return null;
  if (
    !UPGRADE_STATES.includes(value.state as UpgradeState) ||
    typeof value.transactionId !== 'string' || !/^[a-f0-9]{32}$/u.test(value.transactionId) ||
    !Number.isSafeInteger(value.generation) || Number(value.generation) < 0 ||
    !Number.isSafeInteger(value.attempts) || Number(value.attempts) < 0 || Number(value.attempts) > UPGRADE_TRIAL_ATTEMPT_LIMIT ||
    !Number.isSafeInteger(value.updatedAt) || Number(value.updatedAt) < 0 ||
    !(value.candidate === null || isManagedRelease(value.candidate)) ||
    !(value.reason === null || UPGRADE_REASONS.includes(value.reason as UpgradeReason)) ||
    !Array.isArray(value.quarantine) || value.quarantine.length > UPGRADE_QUARANTINE_LIMIT ||
    value.quarantine.some((entry) =>
      !isRecord(entry) ||
      Object.keys(entry).sort().join('\0') !== ['reason', 'releaseHash', 'version'].join('\0') ||
      !isStrictVersion(entry.version) ||
      typeof entry.releaseHash !== 'string' || !/^[a-f0-9]{64}$/u.test(entry.releaseHash) ||
      !UPGRADE_REASONS.includes(entry.reason as UpgradeReason))
  ) return null;
  // A trial with no candidate would tell the launcher to start something that
  // is not there. Refuse the shape rather than resolve it at start time.
  if ((value.state === 'trial' || value.state === 'staged') && value.candidate === null) return null;
  return value as ManagedUpgrade;
}

export function validateUpgradeStatus(value: unknown): UpgradeStatus | null {
  if (!isRecord(value)) return null;
  const expected = ['candidateVersion', 'reason', 'state', 'transactionId'];
  if (Object.keys(value).sort().join('\0') !== expected.sort().join('\0')) return null;
  if (
    !UPGRADE_STATUS_STATES.includes(value.state as UpgradeStatusState) ||
    !(value.reason === null || UPGRADE_REASONS.includes(value.reason as UpgradeReason)) ||
    typeof value.transactionId !== 'string' || !/^[a-f0-9]{32}$/u.test(value.transactionId) ||
    !(value.candidateVersion === null || isStrictVersion(value.candidateVersion))
  ) return null;
  return value as UpgradeStatus;
}

/** The minimum an install needs to expose for the transaction rules to apply. */
type TransactionCarrier = {
  agentVersion: string;
  releasePath: string;
  releaseHash: string;
  previousVersion: string | null;
  previousRelease?: ManagedRelease | null;
  upgrade?: ManagedUpgrade | null;
  updatedAt: number;
};

export function currentRelease<T extends TransactionCarrier>(install: T): ManagedRelease {
  return {
    version: install.agentVersion,
    releasePath: install.releasePath,
    releaseHash: install.releaseHash,
  };
}

export function upgradeOf<T extends TransactionCarrier>(install: T): ManagedUpgrade {
  return validateManagedUpgrade(install.upgrade) ?? idleUpgrade();
}

export function recordQuarantine(
  upgrade: ManagedUpgrade,
  entry: QuarantinedRelease,
): ManagedUpgrade {
  return {
    ...upgrade,
    quarantine: upgrade.quarantine
      .filter((row) => row.releaseHash !== entry.releaseHash)
      .concat(entry)
      .slice(-UPGRADE_QUARANTINE_LIMIT),
  };
}

function withUpgrade<T extends TransactionCarrier>(install: T, upgrade: ManagedUpgrade, now: number): T {
  return { ...install, upgrade, updatedAt: now };
}

function openTransaction<T extends TransactionCarrier>(
  install: T,
  candidate: ManagedRelease,
  transactionId: string,
  state: 'staged' | 'trial',
  now: number,
): T {
  const upgrade = upgradeOf(install);
  const continuing = upgrade.transactionId === transactionId && upgrade.state !== 'idle';
  return withUpgrade(install, {
    ...upgrade,
    state,
    transactionId,
    // A new transaction always gets a new generation, so a readiness proof
    // left behind by an earlier attempt can never satisfy this one.
    generation: continuing ? upgrade.generation : upgrade.generation + 1,
    candidate,
    attempts: continuing ? upgrade.attempts : 0,
    reason: null,
    updatedAt: now,
  }, now);
}

export function stageTransaction<T extends TransactionCarrier>(
  install: T,
  candidate: ManagedRelease,
  transactionId: string,
  now: number,
): T {
  return openTransaction(install, candidate, transactionId, 'staged', now);
}

export function beginTrial<T extends TransactionCarrier>(
  install: T,
  candidate: ManagedRelease,
  transactionId: string,
  now: number,
): T {
  return openTransaction(install, candidate, transactionId, 'trial', now);
}

export function markRollbackPending<T extends TransactionCarrier>(
  install: T,
  reason: UpgradeReason,
  now: number,
): T {
  return withUpgrade(install, { ...upgradeOf(install), state: 'rollback_pending', reason, updatedAt: now }, now);
}

export function blockTransaction<T extends TransactionCarrier>(
  install: T,
  reason: UpgradeReason,
  now: number,
): T {
  return withUpgrade(install, { ...upgradeOf(install), state: 'blocked', reason, updatedAt: now }, now);
}

/**
 * Moves the candidate into the authoritative top-level fields and records the
 * Agent it replaced by exact path and hash. One value in, one value out: the
 * caller writes it in a single atomic file replacement, so there is no moment
 * where the metadata names half of each release.
 */
export function promoteCandidate<T extends TransactionCarrier>(install: T, now: number): T {
  const upgrade = upgradeOf(install);
  const candidate = upgrade.candidate;
  if (!candidate) return install;
  const previous = currentRelease(install);
  return {
    ...install,
    agentVersion: candidate.version,
    releasePath: candidate.releasePath,
    releaseHash: candidate.releaseHash,
    previousVersion: previous.version,
    previousRelease: previous,
    upgrade: {
      ...upgrade,
      state: 'idle',
      candidate: null,
      attempts: 0,
      reason: null,
      updatedAt: now,
    },
    updatedAt: now,
  };
}

/**
 * Abandons the candidate. The top-level release is untouched because it was
 * never replaced -- that is the whole point of the trial shape -- so this is a
 * bookkeeping step, not a binary swap. The failed bytes are remembered by hash
 * so the next login does not walk into the same failure.
 */
export function rollbackCandidate<T extends TransactionCarrier>(
  install: T,
  reason: UpgradeReason,
  now: number,
): T {
  const upgrade = upgradeOf(install);
  const candidate = upgrade.candidate;
  const quarantined = candidate
    ? recordQuarantine(upgrade, { version: candidate.version, releaseHash: candidate.releaseHash, reason })
    : upgrade;
  return withUpgrade(install, {
    ...quarantined,
    state: 'idle',
    candidate: null,
    attempts: 0,
    reason,
    generation: upgrade.generation + 1,
    updatedAt: now,
  }, now);
}

/** Clears a transaction on an explicit operator action such as enable/repair. */
export function resetTransaction<T extends TransactionCarrier>(install: T, now: number): T {
  const upgrade = upgradeOf(install);
  return withUpgrade(install, {
    ...idleUpgrade(now),
    generation: upgrade.generation + 1,
    quarantine: upgrade.quarantine,
  }, now);
}

/**
 * Which release the launcher must start, and whether it is on trial.
 *
 * `null` means start nothing: the transaction is blocked by a condition the
 * previous Agent shares, so starting it would only produce the same failure
 * with an older binary.
 */
export function selectManagedRelease<T extends TransactionCarrier>(
  install: T,
): { release: ManagedRelease; trial: boolean } | null {
  const upgrade = upgradeOf(install);
  if (upgrade.state === 'blocked') return null;
  if (upgrade.state === 'trial' && upgrade.candidate) {
    return { release: upgrade.candidate, trial: true };
  }
  return { release: currentRelease(install), trial: false };
}

/**
 * Classifies how a trial ended.
 *
 * The split that matters is *candidate-specific* against *shared fate*. A
 * candidate that crashes on startup, or that refuses the local Node runtime,
 * has told us something about itself. A rejected authorization, an invalid
 * credential, an ownership conflict or a network outage tell us nothing about
 * the binary -- the previous Agent uses the same credential, the same lock and
 * the same network -- so treating them as candidate failures would downgrade
 * the machine for no reason and, worse, could oscillate.
 */
export function evaluateTrialOutcome(input: {
  exitCode: number | null;
  attempts: number;
  controlled: boolean;
}): { action: 'retry' | 'rollback' | 'block' | 'hold'; reason: UpgradeReason | null } {
  if (input.controlled) return { action: 'hold', reason: null };
  const code = input.exitCode;
  if (code === AGENT_EXIT.authorizationRejected) return { action: 'block', reason: 'authorization_rejected' };
  if (code === AGENT_EXIT.credentialInvalid) return { action: 'block', reason: 'credential_invalid' };
  if (code === AGENT_EXIT.alreadyRunning) return { action: 'hold', reason: 'ownership_conflict' };
  if (code === AGENT_EXIT.controlledShutdown || code === AGENT_EXIT.clean) return { action: 'hold', reason: null };
  if (code === AGENT_EXIT.unsupportedRuntime) return { action: 'rollback', reason: 'candidate_incompatible' };
  return input.attempts >= UPGRADE_TRIAL_ATTEMPT_LIMIT
    ? { action: 'rollback', reason: 'candidate_start_failed' }
    : { action: 'retry', reason: 'candidate_start_failed' };
}

export function buildReadinessMarker(
  transactionId: string,
  generation: number,
  agentVersion: string,
  acceptedAt: number,
): ReadinessMarker {
  return { version: 1, transactionId, generation, agentVersion, acceptedAt };
}

/**
 * A readiness proof is only meaningful for the transaction that asked for it.
 * Binding on the transaction id, the generation and the candidate version is
 * what stops a proof left behind by an earlier upgrade from promoting a
 * different candidate later.
 */
export function validateReadinessMarker(
  value: unknown,
  upgrade: { transactionId: string; generation: number; candidate: { version: string } | null },
): boolean {
  if (!isRecord(value) || !upgrade.candidate) return false;
  return (
    value.version === 1 &&
    value.transactionId === upgrade.transactionId &&
    value.generation === upgrade.generation &&
    value.agentVersion === upgrade.candidate.version &&
    Number.isSafeInteger(value.acceptedAt) &&
    Number(value.acceptedAt) > 0
  );
}

/**
 * The upgrade admission rule.
 *
 * Strictly newer, strictly numeric, never a prerelease. A managed node boots
 * this binary unattended at every login; "0.7.0-rc.2" is not a thing to hand
 * that job to by default, and a repository that later wants a prerelease
 * channel should add it deliberately rather than inherit it from a lenient
 * parser.
 */
export function evaluateUpgradeCandidate(input: {
  current: string;
  candidate: string;
  candidateHash?: string;
  quarantine?: readonly QuarantinedRelease[];
  retry?: boolean;
}): { allowed: boolean; reason: UpgradeReason | null } {
  const order = compareStrictVersions(input.candidate, input.current);
  if (order === null) return { allowed: false, reason: 'candidate_incompatible' };
  if (order === 0) return { allowed: false, reason: 'already_current' };
  if (order < 0) return { allowed: false, reason: 'downgrade_refused' };
  const quarantined = (input.quarantine ?? []).some(
    (entry) => input.candidateHash !== undefined && entry.releaseHash === input.candidateHash,
  );
  if (quarantined && !input.retry) return { allowed: false, reason: 'candidate_quarantined' };
  return { allowed: true, reason: null };
}

/**
 * The manual restore rule: the exact release that was recorded as previous,
 * verified by hash, and nothing else. There is deliberately no way to name an
 * arbitrary local bundle here -- a downgrade path that accepts any file is a
 * downgrade attack waiting for a writable directory.
 */
export function evaluateRestoreTarget(input: {
  current: string;
  previous: ManagedRelease | null | undefined;
  observedHash: string | null;
}): { allowed: boolean; reason: UpgradeReason | null } {
  if (!input.previous || !isManagedRelease(input.previous)) {
    return { allowed: false, reason: 'previous_missing' };
  }
  if (input.observedHash === null) return { allowed: false, reason: 'previous_missing' };
  if (input.observedHash !== input.previous.releaseHash) {
    return { allowed: false, reason: 'previous_corrupted' };
  }
  if (compareStrictVersions(input.previous.version, input.current) === null) {
    return { allowed: false, reason: 'candidate_incompatible' };
  }
  return { allowed: true, reason: null };
}

/** The headless projection for a transaction at rest. */
export function projectUpgradeStatus(upgrade: ManagedUpgrade): UpgradeStatus {
  const state: UpgradeStatusState =
    upgrade.state === 'staged' ? 'upgrade_staged'
      : upgrade.state === 'trial' ? 'upgrade_trial'
        : upgrade.state === 'blocked' ? 'upgrade_blocked'
          : upgrade.state === 'rollback_pending' ? 'upgrade_rolled_back'
            : upgrade.reason === null ? 'upgrade_idle'
              : upgrade.reason === 'already_current' ? 'upgrade_idle'
                : 'upgrade_rolled_back';
  return {
    state,
    reason: upgrade.reason,
    transactionId: upgrade.transactionId,
    candidateVersion: upgrade.candidate?.version ?? null,
  };
}
