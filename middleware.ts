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
  matcher: ['/((?!_next/static|_next/image|favicon.svg|og.png).*)'],
};
