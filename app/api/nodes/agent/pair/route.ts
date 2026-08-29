import { pairNode } from '@/lib/server/nodes';
import { readBoundedJson } from '@/lib/server/node-request';
import { clientAddress, enforceRateLimit } from '@/lib/server/rate-limit';

export async function POST(request: Request): Promise<Response> {
  const limited = await enforceRateLimit(
    'node:pair',
    clientAddress(request) || 'anonymous',
  );
  if (limited.response) return limited.response;
  const parsed = await readBoundedJson(request, 16 * 1024);
  if (!parsed.ok) return parsed.response;
  const result = await pairNode({
    code: parsed.body.code,
    agentVersion: parsed.body.agentVersion,
    protocolVersion: parsed.body.protocolVersion,
    platform: parsed.body.platform,
    architecture: parsed.body.architecture,
    capabilities: parsed.body.capabilities,
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result, { status: 201 });
}
