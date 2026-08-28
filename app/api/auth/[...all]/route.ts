import { getAuth } from '@/lib/server/auth';

/**
 * Better Auth owns every path under `/api/auth`. Sign-in, sign-up, session
 * lookup, sign-out, and the OAuth callback all arrive here.
 */
async function handler(request: Request): Promise<Response> {
  const auth = await getAuth();
  return auth.handler(request);
}

export { handler as GET, handler as POST };
