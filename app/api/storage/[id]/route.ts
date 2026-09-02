import { enforceRateLimit } from '@/lib/server/rate-limit';
import { recordEvidence } from '@/lib/server/audit';
import { requireApiSession } from '@/lib/server/session';
import { deleteObject, downloadObject } from '@/lib/server/storage';

function disposition(name: string): string {
  return `attachment; filename*=UTF-8''${encodeURIComponent(name)}`;
}

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const { id } = await params;
  const result = await downloadObject(auth.session.workspace.id, id);
  if (!result.ok)
    return Response.json({ error: result.error }, { status: result.status });

  const headers = new Headers();
  result.body.writeHttpMetadata(headers);
  headers.set('Content-Type', result.object.contentType);
  headers.set('Content-Length', String(result.body.size));
  headers.set('Content-Disposition', disposition(result.object.name));
  headers.set('Cache-Control', 'private, no-store');
  headers.set('ETag', result.body.httpEtag);
  headers.set('X-Content-Type-Options', 'nosniff');
  return new Response(result.body.body, { headers });
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const limited = await enforceRateLimit(
    'api:write',
    auth.session.actor.userId,
  );
  if (limited.response) return limited.response;

  const { id } = await params;
  const result = await deleteObject({
    workspaceId: auth.session.workspace.id,
    id,
    actor: auth.session.user.email,
  });
  if (!result.ok)
    return Response.json({ error: result.error }, { status: result.status });
  await recordEvidence({
    action: 'storage.delete',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: id,
    outcome: 'success',
    request,
  });
  return Response.json({ deleted: id });
}
