import {
  authenticateAgentRequest,
  confirmArtifactImport,
} from '@/lib/server/nodes';
import { readBoundedJson } from '@/lib/server/node-request';

/**
 * A replacement node reporting that the imported bytes are installed.
 *
 * The body carries only what identifies the work: the reserved artifact, the
 * source artifact it came from, the checksum the node measured, its size, and
 * the revision the transfer settled on. None of it is believed on its own --
 * the control plane re-reads all of it and compares. The deployment stays
 * blocked afterwards, because bytes existing is not a port being agreed.
 */
export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const parsed = await readBoundedJson(request, 1024);
  if (!parsed.ok) return parsed.response;
  const auth = await authenticateAgentRequest(request, parsed.raw);
  if (!auth.ok) return auth.response;
  const { id } = await params;
  const result = await confirmArtifactImport(auth.context, id, parsed.body);
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result);
}
