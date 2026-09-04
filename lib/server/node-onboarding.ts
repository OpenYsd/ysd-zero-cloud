import {
  deriveNodeStatus,
  parseCapabilities,
  type NodeStatus,
} from '@/lib/nodes';
import {
  evaluateCompatibility,
  evaluatePreflight,
  type CompatibilityVerdict,
  type PreflightReport,
} from '@/lib/node-preflight';
import { execute, queryOne } from './db';

/**
 * The onboarding half of the Compute Node story: watching a pairing ticket,
 * cancelling one, and answering "can this node actually take a deployment?".
 *
 * Everything here is workspace-scoped at the query, not after it. A pairing id
 * or node id belonging to another tenant returns the same `null` as one that
 * never existed, so this surface cannot be used to probe for real identifiers.
 */

/**
 * Cancellation is expiry, written as a sentinel.
 *
 * `node_pairing` has `expiresAt` and `consumedAt` and no explicit cancel
 * column, and Phase 16 adds no migration. Setting `expiresAt = 0` is not a
 * cosmetic label: `pairNode` refuses on `expiresAt <= now`, so a cancelled
 * ticket is genuinely, immediately unusable by the same code path that rejects
 * an expired one. Zero is chosen because a real ticket is always
 * `createdAt + TTL`, which can never be 0, so the state is unambiguous rather
 * than inferred from arithmetic.
 *
 * The honest limit: an observer reading the raw row sees "expired at the epoch"
 * rather than the word "cancelled". The distinction survives where it matters
 * -- the audit record says who cancelled it and when -- and the security
 * property does not depend on the label at all.
 */
const CANCELLED_EXPIRY = 0;

/** The stored report is untrusted JSON until it parses and range-checks. */
function safeCapabilities(value: string | null) {
  if (!value) return null;
  try {
    return parseCapabilities(JSON.parse(value) as unknown);
  } catch {
    return null;
  }
}

export type PairingState = 'pending' | 'paired' | 'expired' | 'cancelled';

export type PairingStatus = {
  id: string;
  state: PairingState;
  expiresAt: number;
  /** Present only once a node genuinely paired against this ticket. */
  nodeId: string | null;
  nodeStatus: NodeStatus | null;
  compatibility: CompatibilityVerdict | null;
};

type PairingRow = {
  id: string;
  expiresAt: number;
  consumedAt: number | null;
  nodeId: string | null;
};

/**
 * Reads a ticket's state.
 *
 * The response is deliberately narrow. `code` and `codeHash` are never
 * selected, so no future edit to a response shape can leak them by accident,
 * and the plaintext code exists only in the creating browser's memory -- once
 * that page is gone the ticket cannot be recovered, only replaced.
 */
export async function readPairingStatus(input: {
  workspaceId: string;
  pairingId: string;
  now?: number;
}): Promise<PairingStatus | null> {
  const now = input.now ?? Date.now();
  const row = await queryOne<PairingRow>(
    `SELECT id, expiresAt, consumedAt, nodeId
       FROM node_pairing WHERE id = ? AND workspaceId = ?`,
    input.pairingId,
    input.workspaceId,
  );
  if (!row) return null;

  let state: PairingState = 'pending';
  if (row.consumedAt !== null) state = 'paired';
  else if (row.expiresAt === CANCELLED_EXPIRY) state = 'cancelled';
  else if (row.expiresAt <= now) state = 'expired';

  let nodeStatus: NodeStatus | null = null;
  let compatibility: CompatibilityVerdict | null = null;
  if (state === 'paired' && row.nodeId) {
    const node = await queryOne<{
      agentVersion: string | null;
      protocolVersion: number | null;
      lastHeartbeatAt: number | null;
      revokedAt: number | null;
    }>(
      `SELECT agentVersion, protocolVersion, lastHeartbeatAt, revokedAt
         FROM compute_node WHERE id = ? AND workspaceId = ?`,
      row.nodeId,
      input.workspaceId,
    );
    if (node) {
      nodeStatus = deriveNodeStatus({
        revokedAt: node.revokedAt,
        lastHeartbeatAt: node.lastHeartbeatAt,
        now,
      });
      compatibility = evaluateCompatibility({
        agentVersion: node.agentVersion,
        protocolVersion: node.protocolVersion,
      });
    }
  }

  return {
    id: row.id,
    state,
    expiresAt: row.expiresAt,
    nodeId: state === 'paired' ? row.nodeId : null,
    nodeStatus,
    compatibility,
  };
}

export type CancelOutcome =
  | { ok: true; alreadyTerminal: boolean }
  | { ok: false; status: number; error: string };

/**
 * Cancels an unconsumed ticket.
 *
 * Idempotent by design: cancelling an already-cancelled or already-expired
 * ticket succeeds and reports `alreadyTerminal`, because the caller's intent
 * ("this must not be usable") is already true. A ticket that has been consumed
 * is a different matter -- the node is paired, and cancelling the ticket must
 * never look like a way to unpair it. That returns 409 and points at revoke.
 */
export async function cancelPairing(input: {
  workspaceId: string;
  pairingId: string;
  now?: number;
}): Promise<CancelOutcome> {
  const now = input.now ?? Date.now();
  const row = await queryOne<PairingRow>(
    `SELECT id, expiresAt, consumedAt, nodeId
       FROM node_pairing WHERE id = ? AND workspaceId = ?`,
    input.pairingId,
    input.workspaceId,
  );
  // Opaque: a foreign workspace's ticket is indistinguishable from a
  // non-existent one.
  if (!row) return { ok: false, status: 404, error: 'Pairing ticket not found.' };

  if (row.consumedAt !== null) {
    return {
      ok: false,
      status: 409,
      error: 'That ticket already paired a node. Revoke the node instead.',
    };
  }
  if (row.expiresAt <= now) return { ok: true, alreadyTerminal: true };

  await execute(
    `UPDATE node_pairing SET expiresAt = ?
      WHERE id = ? AND workspaceId = ? AND consumedAt IS NULL`,
    CANCELLED_EXPIRY,
    input.pairingId,
    input.workspaceId,
  );
  return { ok: true, alreadyTerminal: false };
}

export type NodePreflight = PreflightReport & {
  nodeId: string;
  agentVersion: string | null;
  protocolVersion: number | null;
  status: NodeStatus;
  compatibility: CompatibilityVerdict;
};

/**
 * Evaluates a node's readiness from stored state. Nothing is executed on the
 * node, and no capability string is echoed back -- only the report the pure
 * evaluator builds from its own fixed remediation table.
 */
export async function readNodePreflight(input: {
  workspaceId: string;
  nodeId: string;
  now?: number;
}): Promise<NodePreflight | null> {
  const now = input.now ?? Date.now();
  const node = await queryOne<{
    id: string;
    agentVersion: string | null;
    protocolVersion: number | null;
    capabilities: string | null;
    lastHeartbeatAt: number | null;
    revokedAt: number | null;
  }>(
    `SELECT id, agentVersion, protocolVersion, capabilities, lastHeartbeatAt, revokedAt
       FROM compute_node WHERE id = ? AND workspaceId = ?`,
    input.nodeId,
    input.workspaceId,
  );
  if (!node) return null;

  const status = deriveNodeStatus({
    revokedAt: node.revokedAt,
    lastHeartbeatAt: node.lastHeartbeatAt,
    now,
  });
  const report = evaluatePreflight({
    belongsToWorkspace: true,
    status,
    agentVersion: node.agentVersion,
    protocolVersion: node.protocolVersion,
    capabilities: safeCapabilities(node.capabilities),
  });

  return {
    ...report,
    nodeId: node.id,
    agentVersion: node.agentVersion,
    protocolVersion: node.protocolVersion,
    status,
    compatibility: evaluateCompatibility({
      agentVersion: node.agentVersion,
      protocolVersion: node.protocolVersion,
    }),
  };
}
