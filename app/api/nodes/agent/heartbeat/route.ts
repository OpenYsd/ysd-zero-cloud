import { authenticateAgentRequest, recordHeartbeat } from '@/lib/server/nodes';
import { readBoundedJson } from '@/lib/server/node-request';

export async function POST(request: Request): Promise<Response> {
  const parsed = await readBoundedJson(request, 32 * 1024);
  if (!parsed.ok) return parsed.response;
  const auth = await authenticateAgentRequest(request, parsed.raw);
  if (!auth.ok) return auth.response;
  const result = await recordHeartbeat({
    context: auth.context,
    capabilities: parsed.body.capabilities,
    metrics: parsed.body.metrics,
    agentVersion: parsed.body.agentVersion,
    gameServers: parsed.body.gameServers,
    appDeployments: parsed.body.appDeployments,
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result);
}
