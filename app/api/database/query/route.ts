import { writeLog } from '@/lib/server/logs';
import { isInstanceOwner } from '@/lib/server/owner';
import { requireApiSession } from '@/lib/server/session';
import { runEditorQuery } from '@/lib/server/studio';

/**
 * Runs one statement from the SQL Editor.
 *
 * A blocked statement is answered with 422 and the reason the guard gave, so
 * the editor can explain the refusal instead of showing a generic failure.
 *
 * Unlike Database Studio, results here cannot be limited to one workspace: an
 * arbitrary statement would have to be rewritten to carry a tenant predicate,
 * which needs a real SQL planner. Every workspace shares one D1 database, so
 * until that exists the editor stays closed to everyone but the instance
 * owner.
 */
export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { user, workspace } = auth.session;
  if (!(await isInstanceOwner(user.id, user.email))) {
    await writeLog({
      workspaceId: workspace.id,
      level: 'WARN',
      source: 'database',
      message: 'SQL Editor refused: not the instance owner',
      actor: user.email,
    });
    return Response.json(
      {
        error:
          'The SQL Editor is limited to the instance owner, because a raw statement cannot be scoped to one workspace. Use Database Studio, which shows your own rows.',
      },
      { status: 403 },
    );
  }

  let body: { sql?: unknown; allowWrite?: unknown; limit?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return Response.json({ error: 'Expected a JSON body.' }, { status: 400 });
  }

  const sql = typeof body.sql === 'string' ? body.sql : '';
  if (!sql.trim()) return Response.json({ error: 'sql is required' }, { status: 400 });
  if (sql.length > 10_000) {
    return Response.json({ error: 'Statements are limited to 10,000 characters.' }, { status: 400 });
  }

  const allowWrite = body.allowWrite === true;

  try {
    const result = await runEditorQuery(sql, {
      allowWrite,
      limit: typeof body.limit === 'number' ? body.limit : undefined,
    });

    if (!result.analysis.allowed) {
      await writeLog({
        workspaceId: workspace.id,
        level: 'WARN',
        source: 'database',
        message: `Statement blocked · ${result.analysis.reason}`,
        actor: user.email,
      });
      return Response.json(result, { status: 422 });
    }

    if (result.analysis.kind === 'write') {
      await writeLog({
        workspaceId: workspace.id,
        source: 'database',
        message: `${result.analysis.verb} affected ${result.rowsWritten} row${result.rowsWritten === 1 ? '' : 's'}`,
        actor: user.email,
        resource: result.analysis.referencedTables.join(', ') || null,
      });
    }

    return Response.json(result);
  } catch (error) {
    // A syntax error is the operator's, not the server's: report it as a
    // failed statement rather than a 500.
    return Response.json(
      { error: error instanceof Error ? error.message : 'The statement could not be run.' },
      { status: 422 },
    );
  }
}
