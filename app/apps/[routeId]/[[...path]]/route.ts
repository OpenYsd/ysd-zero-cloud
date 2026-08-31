import { handlePublicGateway } from '@/lib/server/public-exposure';

type Context = { params: Promise<{ routeId: string; path?: string[] }> };

async function gateway(request: Request, context: Context): Promise<Response> {
  const { routeId } = await context.params;
  return handlePublicGateway(request, routeId);
}

export const GET = gateway;
export const HEAD = gateway;
export const POST = gateway;
export const PUT = gateway;
export const PATCH = gateway;
export const DELETE = gateway;
export const OPTIONS = gateway;
