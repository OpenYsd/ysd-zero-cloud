/** Provider-neutral email configuration and message helpers. */

export type EmailProvider = {
  id: 'resend';
  apiKey: string;
  from: string;
};

export type EmailVerificationState =
  | 'enabled'
  | 'unavailable-no-domain'
  | 'not-configured';

export type EmailVerificationStatus = {
  state: EmailVerificationState;
  provider: EmailProvider | null;
};

function configuredProvider(
  env: Record<string, unknown>,
): EmailProvider | null {
  const apiKey =
    typeof env.RESEND_API_KEY === 'string' ? env.RESEND_API_KEY.trim() : '';
  const from =
    typeof env.YSD_EMAIL_FROM === 'string' ? env.YSD_EMAIL_FROM.trim() : '';
  if (!apiKey || !from) return null;
  return { id: 'resend', apiKey, from };
}

/**
 * Why verification is or is not active.
 *
 * Production explicitly uses `disabled-no-domain` until an owned sending
 * domain exists. That gate wins even if stale provider secrets remain, so a
 * partial setup can never begin sending from an unverified identity or lock
 * operators out. Moving to `enabled` is a deliberate configuration change
 * made only after the domain and provider are both ready.
 */
export function emailVerificationStatus(
  env: Record<string, unknown>,
): EmailVerificationStatus {
  const mode =
    typeof env.YSD_EMAIL_VERIFICATION_MODE === 'string'
      ? env.YSD_EMAIL_VERIFICATION_MODE.trim().toLowerCase()
      : '';

  if (mode === 'disabled-no-domain') {
    return { state: 'unavailable-no-domain', provider: null };
  }

  const provider = configuredProvider(env);
  if (provider && (mode === '' || mode === 'enabled')) {
    return { state: 'enabled', provider };
  }

  return { state: 'not-configured', provider: null };
}

/**
 * Email verification is enabled only when delivery is actually usable.
 *
 * An API key by itself is insufficient: Resend's shared onboarding sender can
 * only deliver to the Resend account owner. Requiring an explicit sender keeps
 * a partial setup from locking every other account out at sign-in.
 */
export function readEmailProvider(
  env: Record<string, unknown>,
): EmailProvider | null {
  return emailVerificationStatus(env).provider;
}

export function verificationMessage(
  name: string,
  url: string,
): { subject: string; text: string } {
  return {
    subject: 'Confirm your YSD Zero Cloud address',
    text: [
      `Hello ${name || 'there'},`,
      '',
      'Confirm this address to finish setting up your YSD Zero Cloud workspace:',
      '',
      url,
      '',
      'The link is valid for 24 hours. If you did not create this account, ignore this message.',
    ].join('\n'),
  };
}
