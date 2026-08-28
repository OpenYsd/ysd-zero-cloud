/**
 * Request-time clock.
 *
 * Server components read "now" through this seam rather than calling
 * `Date.now()` in a component body. The instant is captured once per request
 * and threaded down, so a page and everything it renders agree on the same
 * moment instead of each re-deriving a slightly different one.
 */
export async function requestTime(): Promise<number> {
  return Date.now();
}
