import { buildNetworkState, type NetworkState } from '@/lib/networking';
import { can, type Actor } from '@/lib/roles';
import { query } from './db';
import { runtimeEnv } from './env';
import {
  listExposureDomains,
  listPublicExposures,
  publicExposureAvailability,
} from './public-exposure';
import { storageAvailable } from './storage';

export async function readNetworkState(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
}): Promise<NetworkState> {
  const [services, exposures, domains] = await Promise.all([
    query<{
      deploymentId: string;
      repository: string;
      environment: string;
      localPort: number | null;
      nodeName: string;
    }>(
      `SELECT d.id AS deploymentId, d.repository, d.environment,
              d.localPort, n.name AS nodeName
         FROM deployment d JOIN compute_node n ON n.id = d.nodeId
        WHERE d.workspaceId = ? AND d.state = 'healthy'
          AND d.localAddress IS NOT NULL AND d.deletedAt IS NULL
        ORDER BY d.createdAt DESC LIMIT 50`,
      input.workspaceId,
    ),
    listPublicExposures(input),
    listExposureDomains(input.organizationId, input.workspaceId),
  ]);
  const availability = publicExposureAvailability();
  return buildNetworkState({
    origin:
      runtimeEnv.BETTER_AUTH_URL?.trim() ||
      runtimeEnv.NEXT_PUBLIC_SITE_URL?.trim() ||
      'http://localhost:3000',
    mode: runtimeEnv.YSD_NETWORK_MODE?.trim(),
    storageAvailable: storageAvailable(),
    localServices: services,
    exposures,
    domains,
    availability,
    permissions: {
      manageExposure: can(input.actor, 'exposure.manage'),
      createPreview: can(input.actor, 'exposure.preview'),
      manageDomains: can(input.actor, 'domain.manage'),
    },
  });
}
