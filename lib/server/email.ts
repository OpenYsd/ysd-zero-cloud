import { runtimeEnv } from './env';
import {
  readEmailProvider as readProviderFrom,
  type EmailProvider,
} from '@/lib/email';

export { verificationMessage } from '@/lib/email';

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

export function readEmailProvider(): EmailProvider | null {
  return readProviderFrom(runtimeEnv);
}

export function isEmailConfigured(): boolean {
  return readEmailProvider() !== null;
}

export type SendResult = { ok: true } | { ok: false; error: string };

/**
 * Sends one message.
 *
 * @returns A result rather than throwing, so a delivery failure surfaces as a
 * diagnostic line instead of a 500 on the sign-up the operator was completing.
 */
export async function sendEmail(input: {
  to: string;
  subject: string;
  text: string;
}): Promise<SendResult> {
  const provider = readEmailProvider();
  if (!provider)
    return { ok: false, error: 'No email provider is configured.' };

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${provider.apiKey}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': crypto.randomUUID(),
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
      return {
        ok: false,
        error: `Resend rejected the message with status ${response.status}.`,
      };
    }
    return { ok: true };
  } catch (cause) {
    return {
      ok: false,
      error: cause instanceof Error ? cause.message : 'Delivery failed.',
    };
  }
}
