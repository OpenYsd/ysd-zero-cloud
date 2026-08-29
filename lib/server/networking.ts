import { buildNetworkState, type NetworkState } from '@/lib/networking';
import { runtimeEnv } from './env';
import { storageAvailable } from './storage';

export function readNetworkState(): NetworkState {
  return buildNetworkState({
    origin:
      runtimeEnv.BETTER_AUTH_URL?.trim() ||
      runtimeEnv.NEXT_PUBLIC_SITE_URL?.trim() ||
      'http://localhost:3000',
    mode: runtimeEnv.YSD_NETWORK_MODE?.trim(),
    storageAvailable: storageAvailable(),
  });
}
