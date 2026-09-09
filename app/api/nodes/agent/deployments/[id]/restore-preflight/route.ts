import {
  authenticateAgentRequest,
  readArtifactRestorePreflight,
} from '@/lib/server/nodes';
import { readBoundedJson } from '@/lib/server/node-request';

/**
 * Read-only. Tells an authenticated node what the control plane already
 * believes about one of its own deployments, so an artifact restore can refuse
 * a bundle that belongs somewhere else. Writes nothing.
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
  const result = await readArtifactRestorePreflight(auth.context, id);
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result);
}
