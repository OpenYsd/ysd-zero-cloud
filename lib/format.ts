/**
 * Display helpers shared by the server-rendered surfaces.
 *
 * All of them take an explicit `now` so a value rendered on the server and
 * re-rendered on the client cannot disagree and trip a hydration mismatch.
 */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** Short relative time, e.g. `now`, `3m ago`, `2h ago`, `5d ago`. */
export function relativeTime(timestamp: number, now: number): string {
  const delta = now - timestamp;
  if (!Number.isFinite(delta)) return '—';
  if (delta < 0) return 'scheduled';
  if (delta < MINUTE) return 'now';
  if (delta < HOUR) return `${Math.floor(delta / MINUTE)}m ago`;
  if (delta < DAY) return `${Math.floor(delta / HOUR)}h ago`;
  if (delta < 30 * DAY) return `${Math.floor(delta / DAY)}d ago`;
  return `${Math.floor(delta / (30 * DAY))}mo ago`;
}

/** Wall-clock time with milliseconds, for the log stream. */
export function logTime(timestamp: number): string {
  const date = new Date(timestamp);
  const pad = (value: number, width = 2) => String(value).padStart(width, '0');
  return `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}.${pad(date.getUTCMilliseconds(), 3)}`;
}

export function duration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms / 1000)}s`;
}

/** Always renders as currency, and is only ever called with a real figure. */
export function money(amount: number): string {
  if (!Number.isFinite(amount)) return 'over limit';
  return `$${amount.toFixed(2)}`;
}
