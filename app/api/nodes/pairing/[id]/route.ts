import { recordEvidence } from '@/lib/server/audit';
import { cancelPairing, readPairingStatus } from '@/lib/server/node-onboarding';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

/**
 * Pairing ticket status and cancellation.
 *
 * The response carries no secret: never the code, never its hash, never a node
 * token. The plaintext code is shown once, at creation, and is unrecoverable
 * afterwards by design -- if the operator loses it they issue a new ticket,
 * which costs nothing and keeps this endpoint useless to an attacker who has
 * only an id.
 */

export async function GET(
  request: Request,
  context: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { id } = await context.params;
  const status = await readPairingStatus({
    workspaceId: auth.session.workspace.id,
    pairingId: id,
  });
  // Opaque for a foreign workspace: identical to a ticket that never existed,
  // so this cannot be used to confirm that an id is real.
  if (!status) {
    return Response.json({ error: 'Pairing ticket not found.' }, { status: 404 });
  }
  return Response.json({ pairing: status });
}

export async function DELETE(
  request: Request,
  context: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;

  const { id } = await context.params;
  const result = await cancelPairing({
    workspaceId: auth.session.workspace.id,
    pairingId: id,
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }

  // Evidence only when this call actually changed something. Recording an
  // idempotent no-op would pad the trail with events that describe nothing.
  if (!result.alreadyTerminal) {
    await recordEvidence({
      action: 'node.pairing.cancel',
      organizationId: auth.session.organization.id,
      workspaceId: auth.session.workspace.id,
      actorType: auth.session.principal,
      actorId: auth.session.actor.userId,
      resourceId: id,
      outcome: 'success',
      request,
      metadata: { reason: 'operator_cancelled' },
    });
  }
  return Response.json({ cancelled: true, alreadyTerminal: result.alreadyTerminal });
}
