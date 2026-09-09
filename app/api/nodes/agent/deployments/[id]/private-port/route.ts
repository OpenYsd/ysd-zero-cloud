import {
  authenticateAgentRequest,
  negotiatePrivatePort,
} from '@/lib/server/nodes';
import { readBoundedJson } from '@/lib/server/node-request';

/**
 * A node reporting which private ports it can actually bind.
 *
 * The control plane assigns the port; only the node can know whether the
 * operating system will hand it over. Windows reserves blocks for Hyper-V and
 * WSL, and a port inside one fails to bind while nothing is listening on it.
 * This is the one place that fact reaches the control plane, and it moves
 * exactly one column.
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
  const result = await negotiatePrivatePort(auth.context, id, parsed.body);
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result);
}
