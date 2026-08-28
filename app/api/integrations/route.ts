import { getIntegrationCatalog } from '@/lib/integrations';

export async function GET() {
  return Response.json({
    mode: 'mock-first',
    integrations: getIntegrationCatalog().map(({ envKeys, ...integration }) => ({
      ...integration,
      requiredConfiguration: envKeys,
    })),
  });
}
