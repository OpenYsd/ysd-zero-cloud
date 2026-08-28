import type { Metadata } from 'next';
import { redirect } from 'next/navigation';
import { AuthForm } from '@/components/auth-form';
import { hasGithubOAuth } from '@/lib/integrations';
import { runtimeEnv } from '@/lib/server/env';
import { readSession } from '@/lib/server/session';

export const metadata: Metadata = { title: 'Sign in' };

export default async function SignInPage() {
  if (await readSession()) redirect('/');
  return <AuthForm mode="sign-in" githubEnabled={hasGithubOAuth(runtimeEnv)} />;
}
