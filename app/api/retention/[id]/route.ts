import {
  RETENTION_LIMITS,
  isRetentionDataClass,
  parseRetentionMutation,
} from '@/lib/retention';
import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { mutateRetentionPolicy } from '@/lib/server/retention';
import { requireApiSession } from '@/lib/server/session';
import { recordWorkflowSecurityEvent } from '@/lib/server/workflow-events';

/**
 * Retention policy mutations.
 *
 * `[id]` is a reviewed data class, never a table. It is matched against the
 * closed allowlist before anything else happens, and the request body may only
 * carry the exact fields one of four operations declares — dry-run,
 * set-window, enable, disable. A body mentioning a table, column, or SQL
 * fragment is refused and recorded as a security event rather than ignored.
 */
export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;

  if (
    request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !==
    'application/json'
  ) {
    return Response.json(
      { error: 'Retention mutations require application/json.' },
      { status: 415, headers: limited.headers },
    );
  }

  const { id } = await params;
  if (!isRetentionDataClass(id)) {
    return Response.json(
      { error: 'Unknown retention data class.' },
      { status: 404, headers: limited.headers },
    );
  }

  const parsedBody = await readBoundedJson(request, RETENTION_LIMITS.requestBytes);
  if (!parsedBody.ok) return parsedBody.response;

  const parsed = parseRetentionMutation(parsedBody.body, id);
  const result = parsed.ok
    ? await mutateRetentionPolicy({
        organizationId: auth.session.organization.id,
        workspaceId: auth.session.workspace.id,
        dataClass: id,
        actor: auth.session.actor,
        mutation: parsed.mutation,
        now: Date.now(),
      })
    : {
        ok: false as const,
        status: 400,
        error: parsed.error,
        securityCode: parsed.securityCode,
      };

  const securityCode = result.ok ? null : result.securityCode;
  if (securityCode) {
    await recordWorkflowSecurityEvent({
      workspaceId: auth.session.workspace.id,
      type: securityCode,
      severity:
        securityCode.includes('injection') || securityCode.includes('cross-tenant')
          ? 'critical'
          : 'high',
      detail:
        'A retention mutation was rejected by the server-authoritative data lifecycle policy.',
    }).catch(() => undefined);
  }

  // The mutation path already audits successful and denied policy changes with
  // full context; this records the transport-level rejections it never sees.
  if (!parsed.ok) {
    await recordAudit({
      organizationId: auth.session.organization.id,
      workspaceId: auth.session.workspace.id,
      actorType: auth.session.principal,
      actorId: auth.session.actor.userId,
      action: 'retention.invalid.denied',
      resourceType: 'retention_policy',
      resourceId: id,
      outcome: 'denied',
      ...requestAuditContext(request),
      metadata: { dataClass: id, role: auth.session.actor.role, zeroCost: true },
    }).catch(() => undefined);
  }

  return result.ok
    ? Response.json(result, { headers: limited.headers })
    : Response.json(
        { error: result.error },
        { status: result.status, headers: limited.headers },
      );
}
