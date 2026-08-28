import type { Metadata } from 'next';
import { redirect } from 'next/navigation';
import { AuthForm } from '@/components/auth-form';
import { hasGithubOAuth } from '@/lib/integrations';
import { runtimeEnv } from '@/lib/server/env';
import { turnstileSiteKey } from '@/lib/server/turnstile';
import { readSession } from '@/lib/server/session';

export const metadata: Metadata = { title: 'Create workspace' };

export default async function SignUpPage() {
  if (await readSession()) redirect('/');
  return <AuthForm
      mode="sign-up"
      githubEnabled={hasGithubOAuth(runtimeEnv)}
      turnstileSiteKey={turnstileSiteKey()}
    />;
}
