/** Provider-neutral email configuration and message helpers. */

export type EmailProvider = {
  id: 'resend';
  apiKey: string;
  from: string;
};

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
  const apiKey =
    typeof env.RESEND_API_KEY === 'string' ? env.RESEND_API_KEY.trim() : '';
  const from =
    typeof env.YSD_EMAIL_FROM === 'string' ? env.YSD_EMAIL_FROM.trim() : '';
  if (!apiKey || !from) return null;
  return { id: 'resend', apiKey, from };
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
