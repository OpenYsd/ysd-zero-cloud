import {
  authenticateAgentRequest,
  confirmArtifactRestore,
} from '@/lib/server/nodes';
import { readBoundedJson } from '@/lib/server/node-request';

/**
 * A node reporting that it has put one lost artifact back.
 *
 * The only write this whole feature makes to the control plane, and it moves
 * exactly one projection: an artifact recorded as gone is recorded as present
 * again. Everything that decides *which* artifact -- deployment, node, current
 * release, checksum -- is read from the database and has to agree with what the
 * node supplies. Repeating the call changes nothing further.
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
  const result = await confirmArtifactRestore(auth.context, id, parsed.body);
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result);
}
