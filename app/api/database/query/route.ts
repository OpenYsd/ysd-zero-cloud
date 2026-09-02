import { can } from '@/lib/roles';
import { recordEvidence, statementFingerprint } from '@/lib/server/audit';
import { writeLog } from '@/lib/server/logs';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import { runEditorQuery } from '@/lib/server/studio';

/**
 * Runs one statement from the SQL Editor.
 *
 * A blocked statement is answered with 422 and the reason the guard gave, so
 * the editor can explain the refusal instead of showing a generic failure.
 *
 * Unlike Database Studio, arbitrary SQL cannot be proven organization-scoped
 * without a real SQL planner. Phase 7 therefore keeps this route closed to
 * every organization role; retaining the guarded implementation preserves a
 * future migration path without weakening tenant isolation today.
 */
export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { user, workspace, actor } = auth.session;

  const limited = await enforceRateLimit('sql:query', actor.userId);
  if (limited.response) return limited.response;

  if (!can(actor, 'sql-editor.run')) {
    await writeLog({
      workspaceId: workspace.id,
      level: 'WARN',
      source: 'database',
      message: 'SQL Editor refused: organization isolation requires Database Studio',
      actor: user.email,
    });
    await recordEvidence({
      action: 'database.query.execute',
      organizationId: auth.session.organization.id,
      workspaceId: workspace.id,
      actorType: auth.session.principal,
      actorId: actor.userId,
      outcome: 'denied',
      request,
      metadata: { reason: 'sql-editor-closed' },
    });
    return Response.json(
      {
        error:
          'Raw SQL is disabled in multi-organization mode because it cannot be scoped safely. Use Database Studio, which applies organization and workspace predicates.',
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
      await recordEvidence({
        action: 'database.query.execute',
        organizationId: auth.session.organization.id,
        workspaceId: workspace.id,
        actorType: auth.session.principal,
        actorId: actor.userId,
        outcome: 'denied',
        request,
        metadata: {
          kind: result.analysis.kind,
          statementHash: await statementFingerprint(sql),
          reason: 'guard-blocked',
        },
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

    // The statement itself is never stored: it can embed literal credentials.
    // A truncated digest still correlates repeat executions.
    await recordEvidence({
      action: 'database.query.execute',
      organizationId: auth.session.organization.id,
      workspaceId: workspace.id,
      actorType: auth.session.principal,
      actorId: actor.userId,
      outcome: 'success',
      request,
      metadata: {
        kind: result.analysis.kind,
        verb: result.analysis.verb,
        statementHash: await statementFingerprint(sql),
        rowsWritten: result.rowsWritten,
        tables: result.analysis.referencedTables.join(',').slice(0, 240),
      },
    });
    return Response.json(result);
  } catch (error) {
    // A syntax error is the operator's, not the server's: report it as a
    // failed statement rather than a 500.
    await recordEvidence({
      action: 'database.query.execute',
      organizationId: auth.session.organization.id,
      workspaceId: workspace.id,
      actorType: auth.session.principal,
      actorId: actor.userId,
      outcome: 'failed',
      request,
      metadata: { statementHash: await statementFingerprint(sql), reason: 'statement-error' },
    });
    return Response.json(
      { error: error instanceof Error ? error.message : 'The statement could not be run.' },
      { status: 422 },
    );
  }
}
