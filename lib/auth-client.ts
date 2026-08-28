'use client';

import { createAuthClient } from 'better-auth/react';

/**
 * Browser-side auth. The base URL is left unset so the client talks to the
 * origin it was served from, which keeps preview deployments working without
 * a per-environment build.
 */
export const authClient = createAuthClient();

export const { sendVerificationEmail, signIn, signUp, signOut, useSession } =
  authClient;
