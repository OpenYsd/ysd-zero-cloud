/**
 * Account vocabulary and validation.
 *
 * Pure, and outside `lib/server/*` on purpose: that directory reaches for
 * `cloudflare:workers` and cannot be loaded by the test runner, so keeping the
 * rules here means they are executed by tests rather than only read.
 *
 * Nothing in this module handles a credential. Password strength is Better
 * Auth's job — it already enforces the configured 12–256 character policy, and
 * duplicating that here would create a second source of truth that could drift.
 * What lives here is the shape of a display name and the boundaries of what an
 * account form may submit.
 */

export const ACCOUNT_LIMITS = {
  displayNameMinimum: 2,
  displayNameMaximum: 60,
  requestBytes: 2_048,
  /** Mirrors `emailAndPassword.minPasswordLength` in the auth options. */
  passwordMinimum: 12,
  passwordMaximum: 256,
} as const;

export type AccountParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === allowed.length && keys.every((key) => allowed.includes(key))
  );
}

/**
 * Normalises a display name.
 *
 * Collapses internal whitespace so " Ada  Lovelace " and "Ada Lovelace" are the
 * same name, and rejects control characters outright — they render as nothing
 * but travel through logs and exports as surprises.
 */
export function normalizeDisplayName(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 32 || code === 127) return null;
  }
  const clean = value.trim().replace(/\s+/g, ' ');
  if (clean.length < ACCOUNT_LIMITS.displayNameMinimum) return null;
  if (clean.length > ACCOUNT_LIMITS.displayNameMaximum) return null;
  return clean;
}

/**
 * A profile update body.
 *
 * Strict-shape: exactly one key. A body carrying `userId`, `organizationId`,
 * `workspaceId`, or `email` is refused rather than quietly ignored, so a caller
 * cannot hope some later layer honours it. Tenancy and identity always come
 * from the session.
 */
export function parseProfileUpdate(
  body: unknown,
): AccountParseResult<{ displayName: string }> {
  if (!record(body)) return { ok: false, error: 'A JSON object is required.' };

  for (const forbidden of [
    'userId',
    'id',
    'organizationId',
    'workspaceId',
    'actorId',
    'email',
    'role',
    'emailVerified',
    'passwordChangedAt',
  ]) {
    if (forbidden in body) {
      return {
        ok: false,
        error: 'Only your display name can be changed here.',
      };
    }
  }

  if (!exactKeys(body, ['displayName'])) {
    return { ok: false, error: 'Unexpected fields in the request body.' };
  }

  const displayName = normalizeDisplayName(body.displayName);
  if (!displayName) {
    return {
      ok: false,
      error: `A display name must be ${ACCOUNT_LIMITS.displayNameMinimum}–${ACCOUNT_LIMITS.displayNameMaximum} characters and contain no control characters.`,
    };
  }
  return { ok: true, value: { displayName } };
}

export type PasswordChange = {
  currentPassword: string;
  newPassword: string;
};

/**
 * A password change body.
 *
 * Only shape is checked here. The current password is never compared, and the
 * new password's strength is left to Better Auth so the configured policy stays
 * the single source of truth. The confirmation field is required so a mismatch
 * is caught before anything reaches the credential store.
 */
export function parsePasswordChange(
  body: unknown,
): AccountParseResult<PasswordChange> {
  if (!record(body)) return { ok: false, error: 'A JSON object is required.' };

  if (!exactKeys(body, ['currentPassword', 'newPassword', 'confirmPassword'])) {
    return { ok: false, error: 'Unexpected fields in the request body.' };
  }

  const { currentPassword, newPassword, confirmPassword } = body;
  if (
    typeof currentPassword !== 'string' ||
    typeof newPassword !== 'string' ||
    typeof confirmPassword !== 'string'
  ) {
    return { ok: false, error: 'Every password field is required.' };
  }
  if (!currentPassword) {
    return { ok: false, error: 'Enter your current password.' };
  }
  if (newPassword !== confirmPassword) {
    return { ok: false, error: 'The new passwords do not match.' };
  }
  if (newPassword.length < ACCOUNT_LIMITS.passwordMinimum) {
    return {
      ok: false,
      error: `A new password must be at least ${ACCOUNT_LIMITS.passwordMinimum} characters.`,
    };
  }
  if (newPassword.length > ACCOUNT_LIMITS.passwordMaximum) {
    return {
      ok: false,
      error: `A new password may be at most ${ACCOUNT_LIMITS.passwordMaximum} characters.`,
    };
  }
  if (newPassword === currentPassword) {
    return { ok: false, error: 'Choose a password you have not used here before.' };
  }
  return { ok: true, value: { currentPassword, newPassword } };
}

/**
 * Why changing the sign-in address is switched off.
 *
 * Better Auth gates `changeEmail` behind a verification callback, and this
 * deployment has no sending domain — `YSD_EMAIL_VERIFICATION_MODE` is
 * `disabled-no-domain`. Allowing the address to change with no way to prove the
 * new one is reachable would let a typo silently lock an operator out of their
 * own organization, with no recovery channel to undo it.
 *
 * The honest answer is to say so in the UI rather than ship a form that looks
 * available and either fails or quietly does something unsafe.
 */
export const EMAIL_CHANGE_AVAILABILITY = {
  available: false,
  reason:
    'Changing your sign-in address needs a way to verify the new one. This deployment has no email sending domain, so the change is unavailable rather than unverified.',
} as const;

/** Initials for the avatar. Deterministic, and never a stored image. */
export function accountInitials(name: string, email: string): string {
  const source = name.trim() || email;
  const parts = source.split(/[\s@._-]+/).filter(Boolean);
  return `${parts[0]?.[0] ?? 'Y'}${parts[1]?.[0] ?? ''}`.toUpperCase();
}

/** The name the shell shows. Never the full address. */
export function accountDisplayName(user: {
  name: string;
  email: string;
}): string {
  const name = user.name.trim();
  if (name) return name;
  return user.email.split('@')[0] || 'Account';
}
