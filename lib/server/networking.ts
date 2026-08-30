import { buildNetworkState, type NetworkState } from '@/lib/networking';
import { runtimeEnv } from './env';
import { storageAvailable } from './storage';
import { query } from './db';

export async function readNetworkState(workspaceId: string): Promise<NetworkState> {
  const services = await query<{ id: string; repository: string; localAddress: string; nodeName: string }>(
    `SELECT d.id, d.repository, d.localAddress, n.name AS nodeName
     FROM deployment d JOIN compute_node n ON n.id = d.nodeId
     WHERE d.workspaceId = ? AND d.state = 'healthy' AND d.exposure = 'private'
       AND d.localAddress IS NOT NULL AND d.deletedAt IS NULL
     ORDER BY d.createdAt DESC LIMIT 50`,
    workspaceId,
  );
  return buildNetworkState({
    origin:
      runtimeEnv.BETTER_AUTH_URL?.trim() ||
      runtimeEnv.NEXT_PUBLIC_SITE_URL?.trim() ||
      'http://localhost:3000',
    mode: runtimeEnv.YSD_NETWORK_MODE?.trim(),
    storageAvailable: storageAvailable(),
    localServices: services.map((service) => ({
      id: service.id,
      repository: service.repository,
      address: service.localAddress,
      nodeName: service.nodeName,
    })),
  });
}
