/**
 * Evidence action catalog.
 *
 * The platform writes two kinds of record, and Phase 13 makes the difference
 * explicit rather than incidental:
 *
 *   EVIDENCE   -> `audit_event`. Append-only at the database, never eligible
 *                 for retention, carries actor identity, outcome, address, and
 *                 an allowlisted metadata shape. This is what proves a
 *                 privileged action happened.
 *   TELEMETRY  -> `log_event`. Operational detail for humans reading the Logs
 *                 surface. Mutable, and deliberately prunable by the Phase 12
 *                 `platform-logs` retention class.
 *
 * Before Phase 13 several high-impact operations — secret deletion, deployment
 * rollback, node revocation, raw SQL execution — existed only as telemetry, so
 * enabling a supported retention policy would erase the only record of them.
 * Every entry below is now dual-written: telemetry keeps its readable message,
 * and `audit_event` keeps the durable proof.
 *
 * Two properties make this catalog testable rather than aspirational. Action
 * names are constants here and nowhere else, so a request can never invent one.
 * And each entry names the route that must record it, which lets a test assert
 * the catalog and the routing surface have not drifted apart — the lesson from
 * the 0.12.1 Shield inventory defect, applied to audit coverage.
 */

export type EvidenceAction = {
  /** Canonical, stable action name written to `audit_event.action`. */
  action: string;
  /** The `audit_event.resourceType` this action always records. */
  resourceType: string;
  /**
   * Metadata keys this action may carry. Anything else is dropped before the
   * write, on top of the global forbidden-key filter in `lib/server/audit.ts`.
   */
  metadataKeys: readonly string[];
  /** Repository-relative route that must record this action. */
  route: string;
  /**
   * `true` when failing to write the evidence must fail the request rather
   * than be swallowed. See "Failure semantics" in the README.
   */
  critical: boolean;
  /** Short reason this action is evidence rather than telemetry. */
  why: string;
};

export const EVIDENCE_ACTIONS = [
  {
    action: 'secret.write',
    resourceType: 'secret',
    metadataKeys: ['environment', 'scope', 'rotated'],
    route: 'app/api/secrets/route.ts',
    critical: true,
    why: 'Creating or rotating a credential changes what the platform can reach.',
  },
  {
    action: 'secret.delete',
    resourceType: 'secret',
    metadataKeys: ['environment', 'scope'],
    route: 'app/api/secrets/[id]/route.ts',
    critical: true,
    why: 'Destroying a credential is irreversible and disables dependent systems.',
  },
  {
    action: 'project.create',
    resourceType: 'project',
    metadataKeys: ['framework', 'environment', 'region'],
    route: 'app/api/projects/route.ts',
    critical: false,
    why: 'Projects scope permissions, so their existence is part of the access record.',
  },
  {
    action: 'project.delete',
    resourceType: 'project',
    metadataKeys: [],
    route: 'app/api/projects/[id]/route.ts',
    critical: true,
    why: 'Deleting a project cascades to deployments, secrets, and history.',
  },
  {
    action: 'deployment.create',
    resourceType: 'deployment',
    metadataKeys: ['environment', 'branch', 'nodeId'],
    // Smart Deploy is the only path that creates a deployment; the
    // `/api/deployments` collection route is read-only.
    route: 'app/api/smart-deploy/route.ts',
    critical: false,
    why: 'A deployment changes what runs on operator-owned machines.',
  },
  {
    action: 'deployment.action',
    resourceType: 'deployment',
    metadataKeys: ['operation', 'projectId'],
    route: 'app/api/deployments/[id]/actions/route.ts',
    critical: true,
    why: 'Redeploy, rollback, and stop are the highest blast-radius runtime actions.',
  },
  {
    action: 'node.register',
    resourceType: 'compute_node',
    metadataKeys: ['label'],
    route: 'app/api/nodes/route.ts',
    critical: false,
    why: 'Admitting a machine to the control plane expands the trust boundary.',
  },
  {
    action: 'node.revoke',
    resourceType: 'compute_node',
    metadataKeys: [],
    route: 'app/api/nodes/[id]/route.ts',
    critical: true,
    why: 'Revocation removes capacity and invalidates an agent credential.',
  },
  {
    action: 'deployment.release',
    resourceType: 'deployment',
    metadataKeys: ['projectId', 'nodeId', 'artifactId', 'commitSha'],
    route: 'app/api/deployments/[id]/releases/route.ts',
    critical: true,
    why: 'A release changes which build of an application runs on an operator machine.',
  },
  {
    action: 'deployment.rollback',
    resourceType: 'deployment',
    // One action, three outcomes. A refusal is evidence too: `reasonCodes`
    // carries the fixed codes the evaluator returned, never node-supplied
    // text, and never a path, checksum, manifest or environment value.
    metadataKeys: ['projectId', 'nodeId', 'fromArtifactId', 'targetArtifactId', 'targetVersion', 'reasonCodes'],
    route: 'app/api/deployments/[id]/rollback/route.ts',
    critical: true,
    why: 'Rollback re-points a running service at an earlier build.',
  },
  {
    action: 'node.job.create',
    resourceType: 'node_job',
    metadataKeys: ['kind', 'nodeId'],
    route: 'app/api/nodes/jobs/route.ts',
    critical: false,
    why: 'A node job executes reviewed work on an operator machine.',
  },
  {
    action: 'storage.write',
    resourceType: 'storage_object',
    metadataKeys: ['scope', 'bytes'],
    route: 'app/api/storage/route.ts',
    critical: false,
    why: 'Object writes change private tenant data.',
  },
  {
    action: 'storage.delete',
    resourceType: 'storage_object',
    metadataKeys: ['scope'],
    route: 'app/api/storage/[id]/route.ts',
    critical: true,
    why: 'Object deletion is irreversible.',
  },
  {
    action: 'game-server.create',
    resourceType: 'game_server',
    metadataKeys: ['edition', 'nodeId'],
    route: 'app/api/game-servers/route.ts',
    critical: false,
    why: 'A server binds a node and a private port allocation.',
  },
  {
    action: 'game-server.action',
    resourceType: 'game_server',
    metadataKeys: ['operation'],
    route: 'app/api/game-servers/[id]/actions/route.ts',
    critical: true,
    why: 'Stop, restart, and delete affect a running workload and its data.',
  },
  {
    action: 'ai.job.run',
    resourceType: 'ai_job',
    metadataKeys: ['modelId', 'nodeId'],
    route: 'app/api/ai/jobs/route.ts',
    critical: false,
    why: 'Inference consumes operator compute under a reviewed model catalog.',
  },
  {
    action: 'ai.job.cancel',
    resourceType: 'ai_job',
    metadataKeys: [],
    route: 'app/api/ai/jobs/[id]/route.ts',
    critical: false,
    why: 'Cancellation stops work another member may be relying on.',
  },
  {
    action: 'ai.model.cache',
    resourceType: 'ai_model',
    metadataKeys: ['nodeId'],
    route: 'app/api/ai/models/[id]/cache/route.ts',
    critical: false,
    why: 'Caching a model writes a large artifact to an operator machine.',
  },
  {
    action: 'workspace.settings.update',
    resourceType: 'workspace',
    metadataKeys: ['setting', 'value'],
    route: 'app/api/settings/route.ts',
    critical: true,
    why: 'Settings include the Zero Mode switch and automatic scanning.',
  },
  {
    action: 'admin.user.update',
    resourceType: 'user',
    metadataKeys: ['operation', 'role'],
    route: 'app/api/admin/users/route.ts',
    critical: true,
    why: 'Changing a platform user record is an identity-level action.',
  },
  {
    action: 'database.query.execute',
    resourceType: 'database',
    metadataKeys: ['kind', 'verb', 'statementHash', 'rowsWritten', 'tables', 'reason'],
    route: 'app/api/database/query/route.ts',
    critical: true,
    why: 'Raw SQL cannot be tenant-scoped, so every attempt is evidence — including refusals.',
  },
  {
    action: 'account.profile.update',
    resourceType: 'user',
    // The field that changed, never the value typed into it.
    metadataKeys: ['field'],
    route: 'lib/server/account.ts',
    critical: false,
    why: 'A change to how an account identifies itself belongs in the record.',
  },
  {
    action: 'account.password.change',
    resourceType: 'user',
    // Whether other sessions were dropped. Nothing about the credential.
    metadataKeys: ['revokedOtherSessions'],
    route: 'lib/server/account.ts',
    critical: true,
    why: 'A credential rotation is the single most security-relevant thing an account holder can do.',
  },
  {
    action: 'retention.change.conflict',
    resourceType: 'retention_policy',
    metadataKeys: ['dataClass', 'operation', 'expectedRevision', 'currentRevision'],
    // Recorded in the service, not the route: only the service can tell a
    // revision conflict apart from the other 409 the same call can return.
    route: 'lib/server/retention.ts',
    critical: false,
    why: 'A revision conflict is a concurrent-writer signal that was previously invisible.',
  },
  {
    action: 'retention.unknown-class.denied',
    resourceType: 'retention_policy',
    metadataKeys: ['classHash', 'classLength'],
    route: 'app/api/retention/[id]/route.ts',
    critical: false,
    why: 'Enumerating data-class names is a probe and was previously unrecorded.',
  },
  {
    action: 'project.readiness.analyze',
    resourceType: 'project',
    metadataKeys: ['owner', 'repository', 'commit', 'branch', 'framework', 'verdict', 'blockedCount', 'reportVersion'],
    route: 'app/api/projects/[id]/analyze/route.ts',
    critical: false,
    why: 'A readiness verdict is what a user relies on before choosing a Compute Node; the exact commit it was computed against must be provable later.',
  },
  {
    action: 'project.readiness.denied',
    resourceType: 'project',
    metadataKeys: ['reason'],
    route: 'app/api/projects/[id]/analyze/route.ts',
    critical: false,
    why: 'A refused analysis (private repository, policy) is still a privileged action against a real, tenant-scoped project and belongs in the same trail as a successful one.',
  },
  {
    action: 'shield.scan.scheduled',
    resourceType: 'shield_scan',
    metadataKeys: [
      'score', 'grade', 'findingCount', 'opened', 'resolved', 'reopened',
      'severityChanged', 'durationMs',
    ],
    // Recorded in the scheduler, not a route: nothing on the request surface
    // triggers it. `outcome` separates a completed sweep from a failed one, so
    // one action covers both rather than two that could drift apart.
    route: 'lib/server/shield-schedule.ts',
    critical: false,
    why: 'A scan the platform ran on its own is a privileged read of every table, secret name, and member role in a workspace, performed with no human in the loop. Without evidence, nobody could later show which sweeps ran, what they found, or that a failing workspace was actually being attempted.',
  },
  {
    action: 'node.pairing.cancel',
    resourceType: 'node_pairing',
    metadataKeys: ['reason'],
    // The ticket is invalidated, not deleted: the row and this record both
    // survive, so "who stopped this pairing, and when" stays answerable.
    route: 'app/api/nodes/pairing/[id]/route.ts',
    critical: false,
    why: 'Withdrawing an outstanding invitation to join the compute plane is an access decision, and the ticket row alone cannot say who made it.',
  },
  {
    action: 'node.preflight.run',
    resourceType: 'compute_node',
    metadataKeys: ['verdict', 'failedChecks', 'agentVersion', 'protocolVersion'],
    route: 'app/api/nodes/[id]/preflight/route.ts',
    critical: false,
    why: 'A readiness verdict is what an operator relies on before trusting a machine with a deployment; the check codes behind a refusal must be provable later.',
  },
] as const satisfies readonly EvidenceAction[];

export type EvidenceActionName = (typeof EVIDENCE_ACTIONS)[number]['action'];

/** The actor kinds an `audit_event` row can carry. */
export type EvidenceActorType = 'user' | 'service_account' | 'system';

/** Service-account actors arrive as a synthetic address, never a real one. */
const SERVICE_ACCOUNT_SUFFIX = '.service.ysd.invalid';

/**
 * Decides who an activity mirror is attributed to.
 *
 * `trusted` is the ONLY way to claim `system`, and it is deliberately not
 * inferred from the actor string. That string is, at most call sites, the
 * signed-in user's email address; this app applies no email format validation
 * of its own, so an address such as `system:anything@example.com` cannot be
 * ruled out. A prefix rule would therefore let a self-registered user file
 * their own activity as platform automation. Automation has to say so at the
 * call site, where the value is a literal in server code and nothing from a
 * request body, query or header can reach it.
 *
 * Pure and exported so it can be executed by tests rather than only read:
 * `lib/server/logs.ts` reaches for `cloudflare:workers` and cannot be imported
 * into the test runner.
 */
export function classifyActivityActor(input: {
  actor?: string | null;
  trusted?: EvidenceActorType;
}): { actorType: EvidenceActorType; actorId: string } {
  const serviceAccount = input.actor?.endsWith(SERVICE_ACCOUNT_SUFFIX)
    ? input.actor.slice(0, -SERVICE_ACCOUNT_SUFFIX.length)
    : null;
  if (serviceAccount) {
    return { actorType: 'service_account', actorId: serviceAccount };
  }
  if (input.trusted) {
    // The readable actor is preserved: `system:shield-scheduler` says which
    // automation did it, which is worth more than a bare "system".
    return { actorType: input.trusted, actorId: input.actor ?? 'system' };
  }
  return input.actor
    ? { actorType: 'user', actorId: input.actor }
    : { actorType: 'system', actorId: 'system' };
}

const BY_ACTION = new Map<string, EvidenceAction>(
  EVIDENCE_ACTIONS.map((entry) => [entry.action, entry]),
);

export function evidenceAction(action: string): EvidenceAction | null {
  return BY_ACTION.get(action) ?? null;
}

export function isEvidenceAction(action: string): action is EvidenceActionName {
  return BY_ACTION.has(action);
}

/**
 * Tables whose rows are evidence. Phase 12 retention must never be able to
 * select one of these, and `lib/retention.ts` is asserted against this list.
 */
export const EVIDENCE_TABLES = ['audit_event', 'audit_sequence'] as const;

/**
 * Metadata value limits. Kept here so the catalog, the writer, and the tests
 * agree on one bound rather than three.
 */
export const EVIDENCE_LIMITS = {
  metadataKeys: 12,
  stringValue: 240,
  /** A truncated SHA-256 is enough to correlate identical statements. */
  hashLength: 32,
} as const;

export type EvidenceMetadata = Record<string, string | number | boolean | null>;

/**
 * Narrows metadata to the keys an action declares.
 *
 * Pure and exported so it can be executed by tests rather than only read:
 * `lib/server/*` reaches for `cloudflare:workers` and cannot be imported into
 * the test runner, so the filtering rule lives here where it can be proven.
 * Values are bounded, and anything the action did not declare is dropped
 * rather than truncated, so a caller cannot smuggle a field through by name.
 */
export function narrowEvidenceMetadata(
  action: string,
  metadata: EvidenceMetadata | undefined,
): EvidenceMetadata {
  const entry = evidenceAction(action);
  if (!entry || !metadata) return {};
  const allowed = new Set<string>(entry.metadataKeys);
  const out: EvidenceMetadata = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (!allowed.has(key)) continue;
    if (Object.keys(out).length >= EVIDENCE_LIMITS.metadataKeys) break;
    out[key] =
      typeof value === 'string' ? value.slice(0, EVIDENCE_LIMITS.stringValue) : value;
  }
  return out;
}
