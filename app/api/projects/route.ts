import { createProject, listProjects } from '@/lib/server/projects';
import { recordEvidence } from '@/lib/server/audit';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json({
    projects: await listProjects(auth.session.workspace.id, auth.session.actor.projectIds),
  });
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;

  let body: { name?: unknown; repository?: unknown; environment?: unknown; region?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return Response.json({ error: 'Expected a JSON body.' }, { status: 400 });
  }

  const result = await createProject({
    workspaceId: auth.session.workspace.id,
    actor: auth.session.user.email,
    name: typeof body.name === 'string' ? body.name : '',
    repository: typeof body.repository === 'string' ? body.repository : null,
    environment: typeof body.environment === 'string' ? body.environment : undefined,
    region: typeof body.region === 'string' ? body.region : undefined,
  });

  if (!result.ok) return Response.json({ error: result.error }, { status: result.status });
  await recordEvidence({
    action: 'project.create',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: result.project.id,
    outcome: 'success',
    request,
    metadata: {
      framework: result.project.framework,
      environment: result.project.environment,
      region: result.project.region,
    },
  });
  return Response.json({ project: result.project }, { status: 201 });
}
