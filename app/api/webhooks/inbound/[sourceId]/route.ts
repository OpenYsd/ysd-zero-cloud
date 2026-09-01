import { ingestWebhook } from '@/lib/server/webhook-sources';

export async function POST(
  request: Request,
  { params }: { params: Promise<{ sourceId: string }> },
): Promise<Response> {
  const { sourceId } = await params;
  return ingestWebhook(request, sourceId);
}

export function GET(): Response {
  return Response.json({ error: 'Webhook ingress accepts signed JSON POST requests only.' }, { status: 405 });
}
