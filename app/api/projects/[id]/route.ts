import { deleteProject, getProject, getProjectReadinessReport } from '@/lib/server/projects';
import { recordEvidence } from '@/lib/server/audit';
import { requireApiSession } from '@/lib/server/session';

/**
 * Single-project detail read, including the full readiness report.
 *
 * The Projects list never calls this: it reads the six denormalised summary
 * columns already on each row instead. This exists for the one place a full
 * blocker list is actually needed -- one project a user has opened -- so it
 * costs exactly two bounded, tenant-scoped reads regardless of how large the
 * stored report is.
 */
export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const project = await getProject(auth.session.workspace.id, id, auth.session.actor.projectIds);
  if (!project) return Response.json({ error: 'Project not found.' }, { status: 404 });

  const report = await getProjectReadinessReport(
    auth.session.workspace.id,
    id,
    auth.session.actor.projectIds,
  );
  return Response.json({ project, report });
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const removed = await deleteProject(
    auth.session.workspace.id,
    id,
    auth.session.user.email,
    auth.session.actor.projectIds,
  );
  if (!removed) return Response.json({ error: 'Project not found.' }, { status: 404 });
  await recordEvidence({
    action: 'project.delete',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: id,
    outcome: 'success',
    request,
  });
  return Response.json({ deleted: id });
}
