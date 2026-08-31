import { can } from '@/lib/roles';
import { listAuditEvents } from '@/lib/server/audit';
import { requireApiSession } from '@/lib/server/session';

function csvCell(value: unknown): string {
  let text = typeof value === 'string' ? value : JSON.stringify(value);
  // Spreadsheet applications treat these prefixes as formulas even inside a
  // quoted CSV cell. Audit data contains request-controlled user agents, so
  // neutralize them before export.
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'audit.read')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  const url = new URL(request.url);
  const outcome = url.searchParams.get('outcome');
  const events = await listAuditEvents(auth.session.organization.id, {
    workspaceId: url.searchParams.get('workspaceId') ?? undefined,
    actorId: url.searchParams.get('actorId') ?? undefined,
    action: url.searchParams.get('action') ?? undefined,
    outcome: outcome === 'success' || outcome === 'denied' || outcome === 'failed' ? outcome : undefined,
    from: Number(url.searchParams.get('from')) || undefined,
    to: Number(url.searchParams.get('to')) || undefined,
    limit: Number(url.searchParams.get('limit')) || undefined,
  });
  const format = url.searchParams.get('format');
  if (format === 'csv') {
    if (!can(auth.session.actor, 'audit.export')) return Response.json({ error: 'Export not permitted.' }, { status: 403 });
    const columns = ['id', 'createdAt', 'workspaceId', 'actorType', 'actorId', 'action', 'resourceType', 'resourceId', 'outcome', 'ipAddress', 'userAgent', 'metadata'] as const;
    const csv = [columns.join(','), ...events.map((event) => columns.map((column) => csvCell(event[column])).join(','))].join('\n');
    return new Response(csv, { headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="ysd-audit.csv"' } });
  }
  if (format === 'json') {
    if (!can(auth.session.actor, 'audit.export')) return Response.json({ error: 'Export not permitted.' }, { status: 403 });
    return new Response(JSON.stringify(events, null, 2), { headers: { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename="ysd-audit.json"' } });
  }
  return Response.json({ events });
}
