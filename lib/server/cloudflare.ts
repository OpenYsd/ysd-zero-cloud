import { hasCloudflareApi } from '@/lib/integrations';
import { runtimeEnv } from './env';

/**
 * Read-only Cloudflare account calls.
 *
 * Only used for figures the Workers runtime cannot see from inside itself.
 * Every request here is a GET against a documented endpoint on the free plan;
 * nothing in this module creates, modifies, or bills a resource.
 */

const API = 'https://api.cloudflare.com/client/v4';
const TIMEOUT_MS = 4000;

type ApiResponse<T> = { success: boolean; result?: T };

async function get<T>(path: string): Promise<T | null> {
  if (!hasCloudflareApi(runtimeEnv)) return null;
  try {
    const response = await fetch(`${API}${path}`, {
      headers: {
        Authorization: `Bearer ${runtimeEnv.CLOUDFLARE_API_TOKEN!}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) return null;
    const body = (await response.json()) as ApiResponse<T>;
    return body.success ? (body.result ?? null) : null;
  } catch {
    return null;
  }
}

/**
 * Bytes stored by the workspace database.
 *
 * D1's SQLite authorizer rejects `PRAGMA page_count` and `page_size`, so the
 * size is not observable from inside a Worker. Cloudflare reports it on the
 * D1 metadata endpoint instead.
 *
 * @returns `null` when no API token is configured, which the usage surface
 * renders as "not reported" rather than as zero.
 */
export async function d1DatabaseSize(): Promise<number | null> {
  const databaseId = runtimeEnv.CLOUDFLARE_D1_DATABASE_ID?.trim();
  if (!databaseId) return null;

  const result = await get<{ file_size?: number; database_size?: number }>(
    `/accounts/${runtimeEnv.CLOUDFLARE_ACCOUNT_ID!}/d1/database/${databaseId}`,
  );
  const size = result?.file_size ?? result?.database_size;
  return typeof size === 'number' ? size : null;
}
