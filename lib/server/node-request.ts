/** Bounded JSON reader for the public agent surface. */

export type JsonBodyResult =
  | { ok: true; raw: string; body: Record<string, unknown> }
  | { ok: false; response: Response };

export async function readBoundedJson(
  request: Request,
  maximumBytes = 64 * 1024,
): Promise<JsonBodyResult> {
  const length = Number(request.headers.get('content-length'));
  if (!Number.isFinite(length) || length < 0) {
    return {
      ok: false,
      response: Response.json(
        { error: 'A Content-Length header is required.' },
        { status: 411 },
      ),
    };
  }
  if (length > maximumBytes) {
    return {
      ok: false,
      response: Response.json(
        { error: 'The request body is too large.' },
        { status: 413 },
      ),
    };
  }
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > maximumBytes) {
    return {
      ok: false,
      response: Response.json(
        { error: 'The request body is too large.' },
        { status: 413 },
      ),
    };
  }
  try {
    const parsed: unknown = JSON.parse(raw || '{}');
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      throw new Error('not an object');
    }
    return { ok: true, raw, body: parsed as Record<string, unknown> };
  } catch {
    return {
      ok: false,
      response: Response.json(
        { error: 'Expected a JSON object.' },
        { status: 400 },
      ),
    };
  }
}
