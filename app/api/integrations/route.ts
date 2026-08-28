import { getIntegrationCatalog } from '@/lib/integrations';
import { runtimeEnv } from '@/lib/server/env';

/**
 * What is live and what is still simulated. Only the names of the required
 * configuration keys are reported, never their values.
 */
export async function GET(): Promise<Response> {
  const integrations = getIntegrationCatalog(runtimeEnv);
  return Response.json({
    mode: integrations.every((integration) => integration.status === 'mock') ? 'mock-first' : 'partial',
    integrations: integrations.map(({ envKeys, ...integration }) => ({
      ...integration,
      requiredConfiguration: envKeys,
    })),
  });
}
