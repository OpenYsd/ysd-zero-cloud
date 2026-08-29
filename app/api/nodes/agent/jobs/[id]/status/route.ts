import {
  authenticateAgentRequest,
  readAgentJobStatus,
} from '@/lib/server/nodes';
import { readBoundedJson } from '@/lib/server/node-request';

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const parsed = await readBoundedJson(request, 1024);
  if (!parsed.ok) return parsed.response;
  const auth = await authenticateAgentRequest(request, parsed.raw);
  if (!auth.ok) return auth.response;
  const { id } = await params;
  const result = await readAgentJobStatus(auth.context, id, parsed.body.leaseId);
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result);
}
