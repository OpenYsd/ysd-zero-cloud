import type { RepositoryAnalysis } from './app-runtime.ts';
import {
  enforceZeroMode,
  ZERO_COST_RESOURCES,
  type PlannedResource,
} from './zero-mode.ts';

/**
 * Repository readiness: the stored projection, not the analyzer's own object.
 *
 * The analyzer returns everything it learned, including the full dependency
 * list and the resolved build contract. None of that belongs in D1. This module
 * narrows it to a small, versioned, attacker-proof shape and is deliberately
 * pure so the whole contract is testable under `--experimental-strip-types`.
 *
 * Everything reaching here is hostile: blocker text, entrypoint paths and
 * package names all come from a stranger's repository. So every string is length
 * capped, the field set is fixed, and the serialized result is size capped.
 */

export const READINESS_LIMITS = {
  /** Report version. Bump when the stored shape changes incompatibly. */
  version: 1,
  /** Hard ceiling for the serialized report written to `project`. */
  reportBytes: 8_192,
  /** Blockers kept in the stored report. The true count is stored separately. */
  storedBlockers: 20,
  /** Caps for individual strings copied out of a repository. */
  titleChars: 200,
  remediationChars: 240,
  entrypointChars: 240,
  branchChars: 128,
} as const;

export type ReadinessVerdict = 'ready' | 'blocked';

export type ReadinessBlocker = {
  code: string;
  title: string;
  remediation: string;
};

export type ReadinessPreview = {
  zeroMode: true;
  estimatedMonthlyCost: number;
  /** Free-tier resources a future deployment would use. */
  resources: { name: string; provider: string; kind: string; note: string | null }[];
  /** Anything the cost guard would refuse. Empty is the expected state. */
  blockedResources: string[];
  /** Stated so the UI can never imply a deployment happened. */
  deployed: false;
  requiresComputeNode: true;
  reason: string;
};

export type ReadinessReport = {
  version: number;
  verdict: ReadinessVerdict;
  framework: string | null;
  packageManager: string | null;
  nodeMajor: number | null;
  entrypoint: string | null;
  branch: string | null;
  commit: string;
  /** Total blockers found, even when `blockers` holds fewer. */
  blockedCount: number;
  blockers: ReadinessBlocker[];
  /** True when `blockers` is a bounded subset of `blockedCount`. */
  truncated: boolean;
  preview: ReadinessPreview;
};

/** What the Projects list needs. Readable without parsing the report. */
export type ReadinessSummary = {
  state: 'never' | 'ready' | 'blocked';
  analyzedAt: number | null;
  commit: string | null;
  shortCommit: string | null;
  framework: string | null;
  blockedCount: number | null;
  branch: string | null;
};

function clamp(value: string, maximum: number): string {
  // Control characters are stripped rather than escaped: they have no meaning
  // in a rendered blocker and would only serve to corrupt logs and terminals.
  // Built entirely from numeric character codes, never a backslash escape,
  // because every previous attempt at one in this file was silently rewritten
  // into the literal byte it names by an intermediate write step.
  let cleaned = '';
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    const isLowControl = code < 32;
    const isHighControl = code >= 127 && code <= 159;
    cleaned += isLowControl || isHighControl ? ' ' : character;
  }
  cleaned = cleaned.trim();
  if (cleaned.length <= maximum) return cleaned;
  return cleaned.slice(0, maximum - 1) + String.fromCharCode(8230);
}

/**
 * Blocker classification.
 *
 * The analyzer reports blockers as prose, which is right for a human but leaves
 * the UI unable to attach a fix. Each known reason is matched to a stable code
 * and a remediation. An unmatched reason is kept verbatim under
 * `unclassified` rather than dropped -- losing a blocker would make a blocked
 * repository look ready, which is the one mistake this must never make.
 */
const BLOCKER_RULES: { code: string; match: RegExp; remediation: string }[] = [
  {
    code: 'manifest-missing',
    match: /package\.json is required|bounded package\.json is required/i,
    remediation: 'Add a package.json at the repository root.',
  },
  {
    code: 'manifest-invalid',
    match: /package\.json is invalid/i,
    remediation: 'Fix the JSON syntax in package.json.',
  },
  {
    code: 'lifecycle-hooks',
    match: /lifecycle hooks are not allowed/i,
    remediation:
      'Remove install lifecycle scripts. They are never executed, so the deployment would not match the repository.',
  },
  {
    code: 'build-script',
    match: /build scripts are not executed/i,
    remediation:
      'Commit the built output, or run the build before publishing. The runtime starts your entrypoint directly.',
  },
  {
    code: 'workspaces',
    match: /workspaces are not enabled/i,
    remediation: 'Deploy a single package. Monorepo workspaces are not supported yet.',
  },
  {
    code: 'dependency-source',
    match: /does not use an approved registry version/i,
    remediation:
      'Pin every dependency to a registry version. Git, file, link and URL sources are refused.',
  },
  {
    code: 'node-version',
    match: /Node\.js must resolve to the/i,
    remediation: 'Set engines.node or .nvmrc to a supported major version.',
  },
  {
    code: 'entrypoint',
    match: /start script in the exact form|entrypoint .* is not present/i,
    remediation:
      'Use a start script of exactly "node <file>.js", and make sure that file is committed.',
  },
  {
    code: 'package-manager',
    match: /lockfile|package manager|package-manager configuration is forbidden/i,
    remediation: 'Commit exactly one supported lockfile and remove package-manager config files.',
  },
  {
    code: 'submodules',
    match: /submodules are not allowed/i,
    remediation: 'Vendor the submodule contents into the repository.',
  },
  {
    code: 'git-lfs',
    match: /LFS/i,
    remediation: 'Store the files directly in Git. LFS pointers cannot be resolved.',
  },
  {
    code: 'zero-mode',
    match: /Zero Mode/i,
    remediation: 'Keep Zero Mode enabled. Paid execution paths are not available.',
  },
];

export function classifyBlocker(reason: string): ReadinessBlocker {
  const rule = BLOCKER_RULES.find((candidate) => candidate.match.test(reason));
  return {
    code: rule?.code ?? 'unclassified',
    title: clamp(reason, READINESS_LIMITS.titleChars),
    remediation: rule
      ? clamp(rule.remediation, READINESS_LIMITS.remediationChars)
      : 'Review the repository against the App Runtime contract.',
  };
}

/**
 * The resources a future deployment would use, priced by the existing guard.
 *
 * This is the pure half of the planner: the same three free-tier entries
 * `createSmartDeployPlan` records, without a node, a port, or a health check,
 * because none of those exist until something actually runs.
 */
export function buildReadinessPreview(zeroModeEnabled = true): ReadinessPreview {
  const resources: PlannedResource[] = [
    {
      ...ZERO_COST_RESOURCES.cloudflareWorker,
      note: 'Existing control plane only; no application build or runtime executes here',
    },
    {
      ...ZERO_COST_RESOURCES.cloudflareD1,
      note: 'Existing bounded readiness metadata only; no source or artifact bytes are stored',
    },
    { ...ZERO_COST_RESOURCES.userOwnedAppCompute },
  ];
  const decision = enforceZeroMode(resources, zeroModeEnabled);
  return {
    zeroMode: true,
    estimatedMonthlyCost: decision.estimatedMonthlyCost,
    resources: resources.map((resource) => ({
      name: resource.name,
      provider: resource.provider,
      kind: resource.kind,
      note: resource.note ?? null,
    })),
    blockedResources: decision.blockedResources.map((resource) => resource.name),
    deployed: false,
    requiresComputeNode: true,
    reason: decision.reason,
  };
}

/** Builds the stored projection from an analyzer result. */
export function buildReadinessReport(input: {
  analysis: RepositoryAnalysis;
  commit: string;
  branch: string | null;
  zeroModeEnabled?: boolean;
}): ReadinessReport {
  const reasons = input.analysis.blockedReasons;
  // Ready means the analyzer found nothing to fix AND produced a build
  // contract. Either one alone is not enough to promise a deployment can start.
  const verdict: ReadinessVerdict =
    reasons.length === 0 && input.analysis.contract !== null ? 'ready' : 'blocked';
  const blockers = reasons.slice(0, READINESS_LIMITS.storedBlockers).map(classifyBlocker);
  return {
    version: READINESS_LIMITS.version,
    verdict,
    framework: input.analysis.framework ?? null,
    packageManager: input.analysis.packageManager ?? null,
    nodeMajor: input.analysis.nodeMajor ?? null,
    entrypoint: input.analysis.entrypoint
      ? clamp(input.analysis.entrypoint, READINESS_LIMITS.entrypointChars)
      : null,
    branch: input.branch ? clamp(input.branch, READINESS_LIMITS.branchChars) : null,
    commit: input.commit,
    blockedCount: reasons.length,
    blockers,
    truncated: reasons.length > blockers.length,
    preview: buildReadinessPreview(input.zeroModeEnabled ?? true),
  };
}

/**
 * Serializes within the storage cap.
 *
 * Overflow drops blockers from the end, never the verdict and never
 * `blockedCount`, so a blocked repository can never be shortened into a ready
 * one. `truncated` records that the list is partial.
 */
export function serializeReadinessReport(report: ReadinessReport): {
  json: string;
  storedBlockers: number;
} {
  let blockers = report.blockers;
  for (;;) {
    const candidate: ReadinessReport = {
      ...report,
      blockers,
      truncated: report.blockedCount > blockers.length,
    };
    const json = JSON.stringify(candidate);
    if (new TextEncoder().encode(json).length <= READINESS_LIMITS.reportBytes) {
      return { json, storedBlockers: blockers.length };
    }
    if (blockers.length === 0) {
      // Nothing left to drop: keep a valid, honest report with no blocker
      // detail rather than storing something oversized or malformed.
      return {
        json: JSON.stringify({ ...candidate, blockers: [], truncated: report.blockedCount > 0 }),
        storedBlockers: 0,
      };
    }
    blockers = blockers.slice(0, blockers.length - 1);
  }
}

/** Parses a stored report defensively. Returns null when unusable. */
export function parseReadinessReport(value: string | null): ReadinessReport | null {
  if (!value || value.length > READINESS_LIMITS.reportBytes * 2) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (typeof parsed !== 'object' || parsed === null) return null;
    const report = parsed as ReadinessReport;
    if (report.version !== READINESS_LIMITS.version) return null;
    if (report.verdict !== 'ready' && report.verdict !== 'blocked') return null;
    if (typeof report.commit !== 'string') return null;
    if (!Array.isArray(report.blockers)) return null;
    return report;
  } catch {
    return null;
  }
}

/** The list-view summary, from the denormalised columns alone. */
export function readinessSummary(row: {
  readinessAnalyzedAt?: number | null;
  readinessCommit?: string | null;
  readinessFramework?: string | null;
  readinessBlockedCount?: number | null;
  readinessSourceBranch?: string | null;
}): ReadinessSummary {
  const analyzedAt = row.readinessAnalyzedAt ?? null;
  if (!analyzedAt) {
    return {
      state: 'never',
      analyzedAt: null,
      commit: null,
      shortCommit: null,
      framework: null,
      blockedCount: null,
      branch: null,
    };
  }
  const blockedCount = row.readinessBlockedCount ?? 0;
  const commit = row.readinessCommit ?? null;
  return {
    state: blockedCount > 0 ? 'blocked' : 'ready',
    analyzedAt,
    commit,
    shortCommit: commit ? commit.slice(0, 7) : null,
    framework: row.readinessFramework ?? null,
    blockedCount,
    branch: row.readinessSourceBranch ?? null,
  };
}

/**
 * The canonical repository link, rebuilt from validated parts.
 *
 * Never echo the caller's string back into an href: it is the one place a
 * `javascript:` payload or a credential-bearing URL could reach the DOM.
 */
export function repositoryUrl(owner: string, repository: string): string | null {
  const safe = /^[A-Za-z0-9_.-]{1,100}$/;
  if (!safe.test(owner) || !safe.test(repository)) return null;
  if ([owner, repository].some((part) => part === '.' || part === '..')) return null;
  return `https://github.com/${owner}/${repository}`;
}
