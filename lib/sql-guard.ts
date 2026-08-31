/**
 * Safety analysis for statements typed into the SQL Editor.
 *
 * The editor talks to the same D1 database that stores credentials, so every
 * statement is classified before it reaches the driver. The analyser is
 * deliberately conservative: anything it cannot confidently prove safe is
 * blocked rather than guessed at.
 */

export type SqlKind = 'read' | 'write' | 'blocked';

export type SqlAnalysis = {
  allowed: boolean;
  kind: SqlKind;
  /** Leading keyword, upper-cased. Empty for an empty statement. */
  verb: string;
  /** The statement with comments stripped and the trailing separator removed. */
  statement: string;
  reason: string;
  /** Identifiers that looked like table references, lower-cased. */
  referencedTables: string[];
};

/**
 * Credential material. The editor may never read or write these: masking
 * happens in Database Studio, and raw SQL would walk straight around it.
 */
export const PROTECTED_TABLES = ['account', 'session', 'verification'] as const;

/** Readable but never writable through the editor. */
export const READ_ONLY_TABLES = ['user'] as const;

const READ_VERBS = new Set(['SELECT', 'WITH', 'EXPLAIN', 'PRAGMA', 'VALUES']);
const WRITE_VERBS = new Set(['INSERT', 'UPDATE', 'DELETE', 'REPLACE']);

/** Statements that reshape the database or reach outside it are never allowed. */
const FORBIDDEN_VERBS = new Set([
  'ATTACH',
  'DETACH',
  'VACUUM',
  'ALTER',
  'DROP',
  'CREATE',
  'REINDEX',
  'BEGIN',
  'COMMIT',
  'ROLLBACK',
  'SAVEPOINT',
  'RELEASE',
  'ANALYZE',
]);

/**
 * Introspection pragmas Database Studio depends on. Everything else is out.
 *
 * This is the intersection of "safe to expose" and "D1 actually permits":
 * D1 runs SQLite behind an authorizer that rejects `page_count`, `page_size`,
 * `database_list`, `integrity_check`, and the rest with `SQLITE_AUTH`. Listing
 * them here would only trade a clear refusal for a driver error.
 */
const ALLOWED_PRAGMAS = new Set([
  'table_info',
  'table_list',
  'table_xinfo',
  'index_list',
  'index_info',
  'index_xinfo',
  'foreign_key_list',
  'quick_check',
]);

/** Keywords that introduce a table reference in SQLite. */
const TABLE_INTRODUCERS = new Set(['FROM', 'JOIN', 'INTO', 'UPDATE', 'TABLE']);

const SINGLE_QUOTE = String.fromCharCode(39);
const DOUBLE_QUOTE = String.fromCharCode(34);
const BACKTICK = String.fromCharCode(96);
const QUOTE_CHARS = new Set([SINGLE_QUOTE, DOUBLE_QUOTE, BACKTICK]);

/**
 * Removes line and block comments without touching quoted text, so a literal
 * that merely looks like a comment survives intact.
 */
export function stripSqlComments(sql: string): string {
  let out = '';
  let index = 0;
  while (index < sql.length) {
    const char = sql[index]!;
    const next = sql[index + 1];

    if (QUOTE_CHARS.has(char)) {
      const quote = char;
      out += char;
      index += 1;
      while (index < sql.length) {
        out += sql[index];
        // A doubled quote is an escaped quote, not a terminator.
        if (sql[index] === quote && sql[index + 1] === quote) {
          out += sql[index + 1];
          index += 2;
          continue;
        }
        if (sql[index] === quote) {
          index += 1;
          break;
        }
        index += 1;
      }
      continue;
    }

    if (char === '[') {
      while (index < sql.length && sql[index] !== ']') {
        out += sql[index];
        index += 1;
      }
      out += ']';
      index += 1;
      continue;
    }

    if (char === '-' && next === '-') {
      while (index < sql.length && sql[index] !== '\n') index += 1;
      out += ' ';
      continue;
    }

    if (char === '/' && next === '*') {
      index += 2;
      while (index < sql.length && !(sql[index] === '*' && sql[index + 1] === '/')) index += 1;
      index += 2;
      out += ' ';
      continue;
    }

    out += char;
    index += 1;
  }
  return out;
}

/** Splits on statement separators that sit outside quoted text. */
export function splitStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = '';
  let index = 0;
  let trigger = false;
  while (index < sql.length) {
    const char = sql[index]!;
    if (QUOTE_CHARS.has(char)) {
      const quote = char;
      current += char;
      index += 1;
      while (index < sql.length) {
        current += sql[index];
        if (sql[index] === quote && sql[index + 1] === quote) {
          current += sql[index + 1];
          index += 2;
          continue;
        }
        if (sql[index] === quote) {
          index += 1;
          break;
        }
        index += 1;
      }
      continue;
    }
    if (char === ';') {
      // SQLite triggers contain semicolon-delimited statements inside
      // `BEGIN ... END`. Keep that body together so the lazy migration runner
      // prepares the complete CREATE TRIGGER statement. The SQL Editor never
      // accepts CREATE, but migrations use this same splitter.
      trigger ||= /^\s*CREATE\s+(?:TEMP(?:ORARY)?\s+)?TRIGGER\b/i.test(current);
      if (trigger && !/\bEND\s*$/i.test(current)) {
        current += char;
        index += 1;
        continue;
      }
      statements.push(current);
      current = '';
      trigger = false;
      index += 1;
      continue;
    }
    current += char;
    index += 1;
  }
  statements.push(current);
  return statements.map((statement) => statement.trim()).filter(Boolean);
}

type Token = { value: string; upper: string; quoted: boolean };

function tokenize(sql: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;
  while (index < sql.length) {
    const char = sql[index]!;

    if (/\s/.test(char)) {
      index += 1;
      continue;
    }

    if (char === DOUBLE_QUOTE || char === BACKTICK || char === '[') {
      const closing = char === '[' ? ']' : char;
      index += 1;
      let value = '';
      while (index < sql.length && sql[index] !== closing) {
        value += sql[index];
        index += 1;
      }
      index += 1;
      tokens.push({ value, upper: value.toUpperCase(), quoted: true });
      continue;
    }

    if (char === SINGLE_QUOTE) {
      // String literals cannot name a table, so they are dropped entirely.
      index += 1;
      while (index < sql.length) {
        if (sql[index] === SINGLE_QUOTE && sql[index + 1] === SINGLE_QUOTE) {
          index += 2;
          continue;
        }
        if (sql[index] === SINGLE_QUOTE) {
          index += 1;
          break;
        }
        index += 1;
      }
      continue;
    }

    if (/[A-Za-z_]/.test(char)) {
      let value = '';
      while (index < sql.length && /[A-Za-z0-9_$.]/.test(sql[index]!)) {
        value += sql[index];
        index += 1;
      }
      tokens.push({ value, upper: value.toUpperCase(), quoted: false });
      continue;
    }

    if (/[0-9]/.test(char)) {
      while (index < sql.length && /[0-9.eE+-]/.test(sql[index]!)) index += 1;
      continue;
    }

    tokens.push({ value: char, upper: char, quoted: true });
    index += 1;
  }
  return tokens;
}

function bareName(identifier: string): string {
  const parts = identifier.split('.');
  return (parts[parts.length - 1] ?? identifier).toLowerCase();
}

function collectTables(tokens: Token[]): string[] {
  const tables = new Set<string>();
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token.quoted || !TABLE_INTRODUCERS.has(token.upper)) continue;
    const candidate = tokens[index + 1];
    if (!candidate) continue;
    if (!candidate.quoted && (candidate.upper === 'SELECT' || candidate.value === '(')) continue;
    if (!/^[A-Za-z_][A-Za-z0-9_$.]*$/.test(candidate.value)) continue;
    tables.add(bareName(candidate.value));
  }
  return [...tables].sort();
}

function blocked(
  statement: string,
  verb: string,
  reason: string,
  referencedTables: string[] = [],
): SqlAnalysis {
  return { allowed: false, kind: 'blocked', verb, statement, reason, referencedTables };
}

/**
 * Classifies a single statement.
 *
 * @param sql Raw editor input.
 * @param options.allowWrite Whether the caller explicitly opted into writes.
 */
export function analyzeStatement(sql: string, options: { allowWrite?: boolean } = {}): SqlAnalysis {
  const cleaned = stripSqlComments(sql);
  const statements = splitStatements(cleaned);

  if (statements.length === 0) {
    return blocked('', '', 'Enter a statement to run.');
  }
  if (statements.length > 1) {
    return blocked(statements[0]!, '', 'Run one statement at a time.');
  }

  const statement = statements[0]!;
  const tokens = tokenize(statement);
  const first = tokens[0];
  if (!first) return blocked(statement, '', 'Enter a statement to run.');

  const verb = first.quoted ? '' : first.upper;
  const referencedTables = collectTables(tokens);

  if (FORBIDDEN_VERBS.has(verb)) {
    return blocked(
      statement,
      verb,
      `${verb} changes database structure and is disabled in the SQL Editor.`,
      referencedTables,
    );
  }

  if (verb === 'PRAGMA') {
    const target = tokens[1];
    const name = target ? bareName(target.value) : '';
    if (!ALLOWED_PRAGMAS.has(name)) {
      return blocked(
        statement,
        verb,
        `PRAGMA ${name || 'statement'} is not on the read-only allow list.`,
        referencedTables,
      );
    }
    if (statement.includes('=')) {
      return blocked(statement, verb, 'Assigning a PRAGMA value is disabled.', referencedTables);
    }
    return {
      allowed: true,
      kind: 'read',
      verb,
      statement,
      reason: 'Read-only introspection pragma.',
      referencedTables,
    };
  }

  const isWriteVerb = WRITE_VERBS.has(verb);
  // SQLite allows a CTE in front of a write, so a WITH statement only counts as
  // a read when no write verb appears anywhere inside it.
  const hasWriteToken = tokens.some((token) => !token.quoted && WRITE_VERBS.has(token.upper));
  const write = isWriteVerb || (verb === 'WITH' && hasWriteToken);

  if (!READ_VERBS.has(verb) && !isWriteVerb) {
    return blocked(
      statement,
      verb,
      `${verb || 'This statement'} is not supported by the SQL Editor.`,
      referencedTables,
    );
  }

  const protectedHit = referencedTables.find((table) =>
    (PROTECTED_TABLES as readonly string[]).includes(table),
  );
  if (protectedHit) {
    return blocked(
      statement,
      verb,
      `Table "${protectedHit}" holds credential material and is not reachable from the SQL Editor.`,
      referencedTables,
    );
  }

  if (write) {
    const readOnlyHit = referencedTables.find((table) =>
      (READ_ONLY_TABLES as readonly string[]).includes(table),
    );
    if (readOnlyHit) {
      return blocked(
        statement,
        verb,
        `Table "${readOnlyHit}" is read-only in the SQL Editor.`,
        referencedTables,
      );
    }
    if (!options.allowWrite) {
      return blocked(
        statement,
        verb,
        'Enable write mode to run a statement that changes data.',
        referencedTables,
      );
    }
    return {
      allowed: true,
      kind: 'write',
      verb,
      statement,
      reason: 'Write approved in write mode.',
      referencedTables,
    };
  }

  return {
    allowed: true,
    kind: 'read',
    verb,
    statement,
    reason: 'Read-only statement.',
    referencedTables,
  };
}

/**
 * Appends a row limit to a bare read so the editor can never stream an
 * unbounded result set out of D1.
 */
export function withRowLimit(statement: string, limit: number): string {
  const normalized = statement.trim().replace(/;+$/, '');
  if (/\blimit\b/i.test(normalized)) return normalized;
  if (!/^(select|with|values)\b/i.test(normalized)) return normalized;
  return `${normalized} LIMIT ${Math.max(1, Math.floor(limit))}`;
}
