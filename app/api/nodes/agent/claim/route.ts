import { authenticateAgentRequest, claimNextJob } from '@/lib/server/nodes';
import { readBoundedJson } from '@/lib/server/node-request';

export async function POST(request: Request): Promise<Response> {
  const parsed = await readBoundedJson(request, 1024);
  if (!parsed.ok) return parsed.response;
  const auth = await authenticateAgentRequest(request, parsed.raw);
  if (!auth.ok) return auth.response;
  return Response.json({ job: await claimNextJob(auth.context) });
}
