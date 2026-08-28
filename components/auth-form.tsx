'use client';

import { NavLink } from '@/components/nav-link';
import { useCallback, useState } from 'react';
import { CloudCog, GitBranch, Loader2, LockKeyhole } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { TurnstileWidget } from '@/components/turnstile-widget';
import { signIn, signUp } from '@/lib/auth-client';

/**
 * Sign-in and sign-up.
 *
 * Better Auth owns credential handling; this form only collects fields and
 * reports back what the server said. GitHub is offered only when the workspace
 * has OAuth credentials configured, so the button is never a dead end.
 */

const MIN_PASSWORD_LENGTH = 12;

export function AuthForm({
  mode,
  githubEnabled,
  turnstileSiteKey,
}: {
  mode: 'sign-in' | 'sign-up';
  githubEnabled: boolean;
  /** Null when the instance has no Turnstile keys; the challenge is then skipped. */
  turnstileSiteKey: string | null;
}) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [challengeToken, setChallengeToken] = useState('');

  const isSignUp = mode === 'sign-up';
  const challengeRequired = turnstileSiteKey !== null;

  // Stable so the widget is not torn down and re-rendered on every keystroke.
  const handleToken = useCallback((token: string) => setChallengeToken(token), []);

  async function handleSubmit(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (isSignUp && password.length < MIN_PASSWORD_LENGTH) {
      setError(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }

    if (challengeRequired && !challengeToken) {
      setError('Please complete the challenge before continuing.');
      return;
    }

    setPending(true);
    try {
      // `fetchOptions.body` merges the challenge token into the request Better
      // Auth sends, which the route handler reads before passing it on.
      const extra = challengeRequired
        ? { fetchOptions: { body: { turnstileToken: challengeToken } } }
        : {};
      const result = isSignUp
        ? await signUp.email({
            name: name.trim() || email.split('@')[0]!,
            email,
            password,
            ...extra,
          })
        : await signIn.email({ email, password, ...extra });

      if (result.error) {
        setError(result.error.message ?? 'That did not work. Check your details and try again.');
        return;
      }

      // A full document load, not `router.push`. Signing in changes what the
      // root layout renders — the workspace shell replaces the bare auth
      // frame — and vinext's client router leaves the cached layout in place
      // on a soft navigation, landing the operator on the overview still
      // wrapped in the signed-out shell. See `components/nav-link.tsx` for
      // the underlying defect.
      window.location.assign('/');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'That did not work.');
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="w-full max-w-[400px]">
      <div className="mb-7 text-center">
        <span className="mx-auto grid size-11 place-items-center rounded-[13px] bg-[#b7ff3c] text-[#08110d] shadow-[0_0_32px_rgba(183,255,60,.22)]">
          <CloudCog className="size-6" strokeWidth={2.3} />
        </span>
        <h1 className="mt-4 text-xl font-semibold tracking-[-0.03em] text-white">
          {isSignUp ? 'Create your workspace' : 'Sign in to YSD Zero Cloud'}
        </h1>
        <p className="mt-1.5 text-xs text-white/35">
          {isSignUp
            ? 'One account, one workspace, zero cost by default.'
            : 'Your cloud is waiting, and it still costs nothing.'}
        </p>
      </div>

      <form onSubmit={handleSubmit} className="cloud-card space-y-4 p-6">
        {isSignUp && (
          <div className="space-y-1.5">
            <Label htmlFor="name" className="text-[11px] text-white/45">Name</Label>
            <Input
              id="name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              autoComplete="name"
              placeholder="Your name"
              className="h-9 border-white/[0.08] bg-black/15 text-xs"
            />
          </div>
        )}

        <div className="space-y-1.5">
          <Label htmlFor="email" className="text-[11px] text-white/45">Email</Label>
          <Input
            id="email"
            type="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            autoComplete="email"
            placeholder="you@example.com"
            className="h-9 border-white/[0.08] bg-black/15 text-xs"
          />
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="password" className="text-[11px] text-white/45">Password</Label>
          <Input
            id="password"
            type="password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete={isSignUp ? 'new-password' : 'current-password'}
            minLength={isSignUp ? MIN_PASSWORD_LENGTH : undefined}
            placeholder={isSignUp ? `At least ${MIN_PASSWORD_LENGTH} characters` : '••••••••••••'}
            className="h-9 border-white/[0.08] bg-black/15 text-xs"
          />
        </div>

        <TurnstileWidget siteKey={turnstileSiteKey} onToken={handleToken} />

        {error && (
          <p role="alert" className="rounded-lg border border-red-400/20 bg-red-400/[0.06] px-3 py-2 text-[11px] text-red-300">
            {error}
          </p>
        )}

        <Button
          type="submit"
          disabled={pending}
          className="h-9 w-full bg-[#b7ff3c] text-xs font-semibold text-[#07100c] hover:bg-[#cbff72]"
        >
          {pending ? <Loader2 className="animate-spin" /> : <LockKeyhole />}
          {isSignUp ? 'Create workspace' : 'Sign in'}
        </Button>

        {githubEnabled && (
          <>
            <div className="flex items-center gap-3 text-[10px] uppercase tracking-[0.14em] text-white/20">
              <span className="h-px flex-1 bg-white/[0.07]" /> or <span className="h-px flex-1 bg-white/[0.07]" />
            </div>
            <Button
              type="button"
              variant="outline"
              disabled={pending}
              onClick={() => signIn.social({ provider: 'github', callbackURL: '/' })}
              className="h-9 w-full border-white/[0.08] bg-white/[0.025] text-xs"
            >
              <GitBranch /> Continue with GitHub
            </Button>
          </>
        )}
      </form>

      <p className="mt-5 text-center text-[11px] text-white/32">
        {isSignUp ? 'Already have a workspace? ' : 'Need a workspace? '}
        <NavLink href={isSignUp ? '/sign-in' : '/sign-up'} className="text-[#c8ff69] hover:underline">
          {isSignUp ? 'Sign in' : 'Create one'}
        </NavLink>
      </p>
    </div>
  );
}
