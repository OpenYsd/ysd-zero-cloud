import { APP_RUNTIME_LIMITS, type AppEnvironment } from '@/lib/app-runtime';
import { planDeployment } from '@/lib/server/deployments';
import { recordAppRuntimeSecurityEvent } from '@/lib/server/app-runtime-control';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

function environment(value: unknown): AppEnvironment {
  return value === 'Preview' || value === 'Development' ? value : 'Production';
}

function boundedInteger(value: unknown, fallback: number, minimum: number, maximum: number): number | null {
  if (value === undefined) return fallback;
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
    ? value
    : null;
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const parsed = await readBoundedJson(request, 8_192);
  if (!parsed.ok) return parsed.response;
  const body = parsed.body;
  const allowedKeys = new Set([
    'repository', 'branch', 'commit', 'nodeId', 'environment', 'healthPath',
    'memoryMb', 'diskQuotaBytes', 'target', 'zeroMode',
  ]);
  const unexpectedKeys = Object.keys(body).filter((key) => !allowedKeys.has(key));
  const repository = typeof body.repository === 'string' ? body.repository.trim() : '';
  const nodeId = typeof body.nodeId === 'string' ? body.nodeId.trim() : '';
  if (!repository || repository.length > 220) return Response.json({ error: 'A bounded GitHub repository is required.' }, { status: 400 });
  if (!/^node_[a-f0-9]{24}$/.test(nodeId)) return Response.json({ error: 'Select a paired Compute Node.' }, { status: 400 });
  if (
    unexpectedKeys.length > 0 ||
    (body.target !== undefined && body.target !== 'user-node') ||
    (body.zeroMode !== undefined && body.zeroMode !== true)
  ) {
    const forbiddenTunnel = unexpectedKeys.some((key) => /tunnel|argo|spectrum|upnp/i.test(key));
    const forbiddenProvider = unexpectedKeys.some((key) => /provider|billing|paid|fallback|gpu/i.test(key)) ||
      (body.target !== undefined && body.target !== 'user-node') || body.zeroMode === false;
    await recordAppRuntimeSecurityEvent({
      workspaceId: auth.session.workspace.id,
      nodeId: /^node_[a-f0-9]{24}$/.test(nodeId) ? nodeId : null,
      type: forbiddenTunnel ? 'app-forbidden-tunnel' : forbiddenProvider ? 'app-forbidden-provider' : 'app-unsafe-script',
      severity: 'critical',
      detail: 'A Smart Deploy request attempted to extend the fixed Zero Mode input contract.',
    });
    return Response.json(
      { error: 'Paid providers, hosted builds, public tunnels, and Zero Mode overrides are forbidden.' },
      { status: 400 },
    );
  }
  const branch = typeof body.branch === 'string' ? body.branch.trim() : null;
  const commit = typeof body.commit === 'string' ? body.commit.trim() : null;
  const healthPath = typeof body.healthPath === 'string' ? body.healthPath.trim() : '/';
  if (!/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,127}$/.test(healthPath)) {
    return Response.json({ error: 'Health checks must use a relative localhost path.' }, { status: 400 });
  }
  const memoryMb = boundedInteger(body.memoryMb, 512, APP_RUNTIME_LIMITS.memoryMinimumMb, APP_RUNTIME_LIMITS.memoryMaximumMb);
  const diskQuotaBytes = boundedInteger(body.diskQuotaBytes, 512 * 1024 ** 2, APP_RUNTIME_LIMITS.diskMinimumBytes, APP_RUNTIME_LIMITS.diskMaximumBytes);
  if (!memoryMb || !diskQuotaBytes) return Response.json({ error: 'The RAM or disk guard is outside the allowed range.' }, { status: 400 });
  const result = await planDeployment({
    workspaceId: auth.session.workspace.id,
    actor: auth.session.user.email,
    repository,
    branch,
    commit,
    nodeId,
    environment: environment(body.environment),
    healthPath,
    memoryMb,
    diskQuotaBytes,
    idempotencyKey: request.headers.get('idempotency-key'),
    allowedProjectIds: auth.session.actor.projectIds,
  });
  if (!result.ok) {
    return Response.json(
      { error: result.error, plan: result.plan, deployment: result.deployment, zeroMode: true },
      { status: result.status },
    );
  }
  return Response.json(
    { plan: result.plan, deployment: result.deployment, duplicate: result.duplicate, zeroMode: true },
    { status: result.duplicate ? 200 : 202 },
  );
}
