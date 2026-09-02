import { writeLog } from '@/lib/server/logs';
import { recordEvidence } from '@/lib/server/audit';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import { isWorkspaceSetting, updateWorkspaceSetting } from '@/lib/server/workspace';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json({ workspace: auth.session.workspace });
}

/**
 * Applies one workspace setting.
 *
 * Turning Zero Mode off is a deliberate, recorded act: the log line is written
 * before the response returns so the change cannot happen silently.
 */
export async function PATCH(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;

  let body: { setting?: unknown; value?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return Response.json({ error: 'Expected a JSON body.' }, { status: 400 });
  }

  const setting = typeof body.setting === 'string' ? body.setting : '';
  if (!isWorkspaceSetting(setting)) {
    return Response.json({ error: `Unknown setting: ${setting}` }, { status: 400 });
  }
  if (typeof body.value !== 'boolean') {
    return Response.json({ error: 'value must be a boolean.' }, { status: 400 });
  }

  const workspace = await updateWorkspaceSetting(auth.session.workspace.id, setting, body.value);
  if (!workspace) return Response.json({ error: 'Workspace not found.' }, { status: 404 });

  await writeLog({
    workspaceId: workspace.id,
    level: setting === 'zeroMode' && !body.value ? 'WARN' : 'INFO',
    source: 'workspace',
    message: `${setting} set to ${body.value ? 'on' : 'off'}`,
    actor: auth.session.user.email,
    resource: workspace.id,
  });

  await recordEvidence({
    action: 'workspace.settings.update',
    organizationId: auth.session.organization.id,
    workspaceId: workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: workspace.id,
    outcome: 'success',
    request,
    metadata: { setting, value: body.value },
  });
  return Response.json({ workspace });
}
