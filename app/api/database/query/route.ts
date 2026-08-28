import { writeLog } from '@/lib/server/logs';
import { requireApiSession } from '@/lib/server/session';
import { runEditorQuery } from '@/lib/server/studio';

/**
 * Runs one statement from the SQL Editor.
 *
 * A blocked statement is answered with 422 and the reason the guard gave, so
 * the editor can explain the refusal instead of showing a generic failure.
 */
export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

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
        workspaceId: auth.session.workspace.id,
        level: 'WARN',
        source: 'database',
        message: `Statement blocked · ${result.analysis.reason}`,
        actor: auth.session.user.email,
      });
      return Response.json(result, { status: 422 });
    }

    if (result.analysis.kind === 'write') {
      await writeLog({
        workspaceId: auth.session.workspace.id,
        source: 'database',
        message: `${result.analysis.verb} affected ${result.rowsWritten} row${result.rowsWritten === 1 ? '' : 's'}`,
        actor: auth.session.user.email,
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
