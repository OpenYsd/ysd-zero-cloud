/**
 * Choosing an organization and workspace from a stored preference.
 *
 * `ysd_organization` and `ysd_workspace` are written for a year and are
 * `HttpOnly`, so a user cannot clear them from the console. Before this module
 * existed, a preference that no longer resolved made `resolveOrganizationAccess`
 * return `null`, which `readSession` reported as "no session". The effect was
 * that a completely valid login bounced straight back to `/sign-in`, for ever,
 * until the browser's site data was cleared.
 *
 * A preference is a preference. If it cannot be honoured, the right answer is
 * to use a membership the user really has — not to pretend they are signed out.
 *
 * These functions are pure and live outside `lib/server/*` on purpose: that
 * directory reaches for `cloudflare:workers` and cannot be imported by the test
 * runner, so the rule that actually fixes the bug would otherwise only be
 * assertable by reading source. Here it can be executed.
 *
 * Security note: neither function performs any filtering of its own. The caller
 * must pass a list that is already restricted to the authenticated user's real,
 * active memberships — and, for workspaces, already restricted to the resolved
 * organization. Selecting the first entry of an already-scoped list cannot
 * cross a tenant boundary; selecting from an unscoped list would. The scoping
 * stays in the SQL that builds these lists.
 */

export type ContextSelection<T> = {
  /** `null` only when the candidate list is genuinely empty. */
  selected: T | null;
  /**
   * True when a preference was supplied, could not be honoured, and a valid
   * candidate was used instead. Callers that own a response use this to rewrite
   * the stale cookie.
   */
  repaired: boolean;
};

function select<T>(
  candidates: readonly T[],
  requested: string | null | undefined,
  identify: (candidate: T) => string,
): ContextSelection<T> {
  const first = candidates[0] ?? null;
  if (!requested) return { selected: first, repaired: false };

  const match = candidates.find((candidate) => identify(candidate) === requested);
  if (match) return { selected: match, repaired: false };

  // The preference named something this user cannot reach. Fall back rather
  // than reporting no access at all.
  return { selected: first, repaired: first !== null };
}

/**
 * @param memberships Already restricted to the user's active memberships in
 * active organizations, ordered most-recently-used first.
 */
export function selectMembership<T extends { organizationId: string }>(
  memberships: readonly T[],
  requestedOrganizationId?: string | null,
): ContextSelection<T> {
  return select(memberships, requestedOrganizationId, (row) => row.organizationId);
}

/**
 * @param workspaces Already restricted to the resolved organization and to
 * workspaces this member may enter.
 */
export function selectWorkspace<T extends { id: string }>(
  workspaces: readonly T[],
  requestedWorkspaceId?: string | null,
): ContextSelection<T> {
  return select(workspaces, requestedWorkspaceId, (row) => row.id);
}
