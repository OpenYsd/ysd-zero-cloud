import { runtimeEnv } from './env';

/**
 * Transactional email.
 *
 * There is no zero-cost way to send mail from a Worker without an external
 * provider, so this is an optional adapter rather than a hard dependency.
 * Resend's free tier is the supported provider; it needs an API key the
 * operator creates themselves.
 *
 * The important consequence is in `lib/server/auth.ts`: email verification is
 * only *required* when a provider is configured. Requiring a verified address
 * with no way to deliver the verification link would lock every operator out
 * of their own instance, which is a worse outcome than an unverified address.
 */

export type EmailProvider = {
  id: 'resend';
  from: string;
};

export function readEmailProvider(): EmailProvider | null {
  const apiKey = runtimeEnv.RESEND_API_KEY?.trim();
  if (!apiKey) return null;
  return {
    id: 'resend',
    from: runtimeEnv.YSD_EMAIL_FROM?.trim() || 'YSD Zero Cloud <onboarding@resend.dev>',
  };
}

export function isEmailConfigured(): boolean {
  return readEmailProvider() !== null;
}

export type SendResult = { ok: true } | { ok: false; error: string };

/**
 * Sends one message.
 *
 * @returns A result rather than throwing, so a delivery failure surfaces as an
 * audit line instead of a 500 on the sign-up the operator was completing.
 */
export async function sendEmail(input: {
  to: string;
  subject: string;
  text: string;
}): Promise<SendResult> {
  const provider = readEmailProvider();
  if (!provider) return { ok: false, error: 'No email provider is configured.' };

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${runtimeEnv.RESEND_API_KEY!.trim()}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: provider.from,
        to: [input.to],
        subject: input.subject,
        text: input.text,
      }),
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      return { ok: false, error: `Resend responded ${response.status}: ${detail.slice(0, 200)}` };
    }
    return { ok: true };
  } catch (cause) {
    return { ok: false, error: cause instanceof Error ? cause.message : 'Delivery failed.' };
  }
}

export function verificationMessage(name: string, url: string): { subject: string; text: string } {
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
