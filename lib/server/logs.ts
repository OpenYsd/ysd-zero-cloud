import { createId } from '@/lib/crypto';
import {
  isLogLevel,
  isLogSource,
  LOG_LEVELS,
  LOG_SOURCES,
  type LogEvent,
  type LogLevel,
  type LogSource,
} from '@/lib/domain';
import { execute, query } from './db';

/**
 * The workspace event log.
 *
 * Every mutating action writes here, so the Logs surface reflects what the
 * workspace actually did rather than a sample feed. Writes are best-effort:
 * losing an audit line must never fail the operation it was describing.
 */

export { isLogLevel, isLogSource, LOG_LEVELS, LOG_SOURCES };
export type { LogEvent, LogLevel, LogSource };

export type LogInput = {
  workspaceId: string;
  level?: LogLevel;
  source: LogSource;
  message: string;
  actor?: string | null;
  resource?: string | null;
};

export async function writeLog(input: LogInput): Promise<void> {
  try {
    await execute(
      `INSERT INTO log_event (id, workspaceId, level, source, message, actor, resource, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      createId('evt'),
      input.workspaceId,
      input.level ?? 'INFO',
      input.source,
      input.message,
      input.actor ?? null,
      input.resource ?? null,
      Date.now(),
    );
  } catch {
    // An unwritable audit line is not worth failing a deployment over. The
    // gap shows up as a hole in the log rather than a broken request.
  }
}

export type LogFilter = {
  search?: string;
  source?: LogSource;
  level?: LogLevel;
  limit?: number;
};

export async function listLogs(workspaceId: string, filter: LogFilter = {}): Promise<LogEvent[]> {
  const conditions = ['workspaceId = ?'];
  const params: unknown[] = [workspaceId];

  if (filter.source) {
    conditions.push('source = ?');
    params.push(filter.source);
  }
  if (filter.level) {
    conditions.push('level = ?');
    params.push(filter.level);
  }
  if (filter.search?.trim()) {
    conditions.push('(LOWER(message) LIKE ? OR LOWER(resource) LIKE ?)');
    const needle = `%${filter.search.trim().toLowerCase()}%`;
    params.push(needle, needle);
  }

  const limit = Math.min(500, Math.max(1, filter.limit ?? 100));
  params.push(limit);

  return query<LogEvent>(
    `SELECT id, level, source, message, actor, resource, createdAt
     FROM log_event
     WHERE ${conditions.join(' AND ')}
     ORDER BY createdAt DESC
     LIMIT ?`,
    ...params,
  );
}
