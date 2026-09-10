import {
  authenticateAgentRequest,
  readArtifactImportPreflight,
} from '@/lib/server/nodes';
import { readBoundedJson } from '@/lib/server/node-request';

/**
 * Authorizes one replacement node to import one backup.
 *
 * The node names a deployment and nothing else. It does not supply a checksum,
 * an artifact id, or a revision -- every one of those is read from the control
 * plane, because a node asking to import bytes must not also be the one
 * deciding which bytes are correct. What comes back is a reservation: the
 * artifact row the imported copy will become, and the checksum it has to match.
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
  const result = await readArtifactImportPreflight(auth.context, id);
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result);
}
