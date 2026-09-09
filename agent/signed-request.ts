/**
 * One signed request to the control plane.
 *
 * Lifted out of the CLI so the App Runtime can use the same authenticated
 * channel rather than growing a second one. The wire format is unchanged:
 * `ysd-node-request-v1` over method, path, timestamp, nonce and a body hash,
 * exactly as every other Agent request signs it.
 */
import { randomToken, signAgentRequest } from '../lib/nodes.ts';

export class ControlPlaneError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function jsonRequest<T>(url: string, init: RequestInit): Promise<T> {
  const timeout = AbortSignal.timeout(30_000);
  const response = await fetch(url, {
    ...init,
    signal: init.signal ? AbortSignal.any([init.signal, timeout]) : timeout,
  });
  if (!response.ok) {
    throw new ControlPlaneError(
      response.status,
      `Control plane answered ${response.status}.`,
    );
  }
  return (await response.json()) as T;
}

export async function signedPost<T>(input: {
  origin: string;
  token: string;
  pathname: string;
  body: Record<string, unknown>;
  signal?: AbortSignal;
}): Promise<T> {
  const raw = JSON.stringify(input.body);
  const timestamp = Date.now();
  const nonce = randomToken(18);
  const signature = await signAgentRequest(input.token, {
    method: 'POST',
    pathname: input.pathname,
    timestamp,
    nonce,
    body: raw,
  });
  return await jsonRequest<T>(`${input.origin}${input.pathname}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${input.token}`,
      'Content-Type': 'application/json',
      'X-YSD-Timestamp': String(timestamp),
      'X-YSD-Nonce': nonce,
      'X-YSD-Signature': signature,
    },
    body: raw,
    signal: input.signal,
  });
}
