import { analyzeProjectReadiness } from '@/lib/server/projects';
import { recordEvidence } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

/**
 * Repository readiness analysis. Reads a public GitHub repository and stores a
 * verdict; nothing here builds, executes, or deploys. The repository comes
 * only from the already tenant-scoped project row -- never from the request --
 * so this route accepts no body fields at all.
 *
 * A foreign or unknown project id gets the same 404 `deleteProject` already
 * uses: existence is never disclosed to a caller who cannot reach the project,
 * and no evidence is written for that case, so a foreign project's identity
 * cannot leak into this workspace's own audit trail.
 */
export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  // Rate limited before any outbound GitHub work, per user rather than per
  // project, so retrying against one blocked repository cannot be used to
  // launder a higher effective budget across many projects.
  const limited = await enforceRateLimit('deploy:analyze', auth.session.actor.userId);
  if (limited.response) return limited.response;

  if (
    request.headers.get('content-type')?.split(';', 1)[0]!.trim().toLowerCase() !==
    'application/json'
  ) {
    return Response.json(
      { error: 'Analyze requires application/json.' },
      { status: 415, headers: limited.headers },
    );
  }
  const parsed = await readBoundedJson(request, 512);
  if (!parsed.ok) return parsed.response;
  if (Object.keys(parsed.body).length > 0) {
    return Response.json(
      { error: 'This endpoint takes no request fields.' },
      { status: 400, headers: limited.headers },
    );
  }

  const { id } = await params;
  const result = await analyzeProjectReadiness({
    workspaceId: auth.session.workspace.id,
    projectId: id,
    projectIds: auth.session.actor.projectIds,
  });

  if (!result.ok) {
    // A missing project stays a plain 404: no evidence, nothing that could
    // identify a foreign project or repository to this workspace's trail.
    // Discriminated by `projectNotFound`, not by status code: GitHub's own
    // inspection can independently fail with a 404-shaped error (repository
    // renamed, rate-limited), and that case still belongs in this tenant's
    // evidence trail -- the project genuinely exists and is theirs.
    if (result.projectNotFound) {
      return Response.json({ error: result.error }, { status: 404, headers: limited.headers });
    }
    await recordEvidence({
      action: 'project.readiness.denied',
      organizationId: auth.session.organization.id,
      workspaceId: auth.session.workspace.id,
      actorType: auth.session.principal,
      actorId: auth.session.actor.userId,
      resourceId: id,
      outcome: 'denied',
      request,
      metadata: { reason: result.error },
    });
    return Response.json(
      { error: result.error },
      { status: result.status, headers: limited.headers },
    );
  }

  await recordEvidence({
    action: 'project.readiness.analyze',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: id,
    outcome: 'success',
    request,
    metadata: {
      owner: result.owner,
      repository: result.repository,
      commit: result.report.commit,
      branch: result.report.branch ?? '',
      framework: result.report.framework ?? '',
      verdict: result.report.verdict,
      blockedCount: result.report.blockedCount,
      reportVersion: result.report.version,
    },
  });

  return Response.json({ report: result.report }, { headers: limited.headers });
}
