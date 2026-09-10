import {
  authenticateAgentRequest,
  clearReplacementImportBlock,
} from '@/lib/server/nodes';
import { readBoundedJson } from '@/lib/server/node-request';

/**
 * The last step of a replacement recovery, and deliberately the smallest.
 *
 * By the time a node calls this, the imported artifact is verified and present
 * and the private port has been negotiated. All this does is retire the reason
 * Phase 18 was refusing to look at the deployment. It starts nothing, builds
 * nothing, fetches nothing, and does not touch desired state -- the operator
 * never issues a Start, because ordinary reconciliation takes it from here.
 * Calling it twice is a no-op.
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
  const result = await clearReplacementImportBlock(auth.context, id);
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result);
}
