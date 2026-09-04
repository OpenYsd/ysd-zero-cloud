import { NextResponse } from 'next/server';

import { SECURITY_HEADERS } from '@/lib/security-headers';

/**
 * Applies the security response headers to everything the Worker produces.
 *
 * Cloudflare's `_headers` file only covers static assets, and almost every
 * response here is server-rendered, so they are set in middleware instead. The
 * header set itself lives in `lib/security-headers.ts`, which YSD Shield also
 * reads, so the reported posture cannot drift from what is served.
 */
export function middleware() {
  const response = NextResponse.next();
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    response.headers.set(name, value);
  }
  return response;
}

export const config = {
  // Everything except the static asset paths, which Cloudflare serves directly
  // and which carry no session or user data.
  //
  // `agent/` is the Compute Node release: a public, immutable, version-pinned
  // bundle plus its checksum and manifest. It has to be listed here for the
  // same reason the two files above are. Anything the matcher covers reaches
  // the app router first, which answers an unknown path with the 404 page --
  // so without this the download 404s even though the Worker is holding the
  // asset. That is exactly what happened on the first 0.16.0 deploy, and it
  // only shows up in Production: the dev server serves `public/` directly and
  // never consults this matcher.
  matcher: ['/((?!_next/static|_next/image|agent/|favicon.svg|og.png).*)'],
};
