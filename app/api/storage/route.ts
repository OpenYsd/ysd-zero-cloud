import { STORAGE_LIMITS } from '@/lib/storage';
import { recordEvidence } from '@/lib/server/audit';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import { listStorage, uploadObject } from '@/lib/server/storage';

const MAX_MULTIPART_BYTES = STORAGE_LIMITS.objectBytes + 1024 * 1024;

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json(await listStorage(auth.session.workspace.id));
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const limited = await enforceRateLimit(
    'api:write',
    auth.session.actor.userId,
  );
  if (limited.response) return limited.response;

  // `formData()` buffers the multipart envelope. Require a bounded body before
  // asking the runtime to parse it so a chunked, unbounded upload cannot use
  // the Worker as a memory sink.
  const contentLength = Number(request.headers.get('content-length'));
  if (!Number.isFinite(contentLength) || contentLength <= 0) {
    return Response.json(
      { error: 'A Content-Length header is required for uploads.' },
      { status: 411 },
    );
  }
  if (contentLength > MAX_MULTIPART_BYTES) {
    return Response.json(
      { error: 'The upload exceeds the 10 MB Zero Mode object limit.' },
      { status: 413 },
    );
  }

  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return Response.json(
      { error: 'Expected a multipart form upload.' },
      { status: 400 },
    );
  }

  const file = form.get('file');
  if (!(file instanceof File)) {
    return Response.json(
      { error: 'Choose a file to upload.' },
      { status: 400 },
    );
  }

  const result = await uploadObject({
    workspaceId: auth.session.workspace.id,
    actor: auth.session.user.email,
    file,
  });
  if (!result.ok)
    return Response.json({ error: result.error }, { status: result.status });
  await recordEvidence({
    action: 'storage.write',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: result.object.id,
    outcome: 'success',
    request,
    metadata: { bytes: result.object.size },
  });
  return Response.json({ object: result.object }, { status: 201 });
}
