-- Security hardening: instance roles, sign-in attempt history, and the
-- application's own rate-limit counters.
--
-- Timestamps are integer epoch milliseconds, matching 0002_workspace.sql.

-- Instance role and suspension state, kept out of Better Auth's `user` table
-- so the generated auth schema stays exactly what Better Auth expects and can
-- be regenerated without touching this.
CREATE TABLE IF NOT EXISTS user_role (
  userId TEXT PRIMARY KEY REFERENCES "user" (id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member',
  suspendedAt INTEGER,
  suspendedReason TEXT,
  updatedAt INTEGER NOT NULL,
  updatedBy TEXT
);

CREATE INDEX IF NOT EXISTS user_role_role_idx ON user_role (role);

-- Every sign-in attempt, successful or not. Brute-force lockout and the
-- suspicious-login rules both read from here, and it is the evidence trail
-- when an account is questioned.
CREATE TABLE IF NOT EXISTS auth_attempt (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  userAgent TEXT,
  outcome TEXT NOT NULL,
  createdAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_attempt_email_idx ON auth_attempt (email, createdAt DESC);
CREATE INDEX IF NOT EXISTS auth_attempt_ip_idx ON auth_attempt (ip, createdAt DESC);
CREATE INDEX IF NOT EXISTS auth_attempt_created_idx ON auth_attempt (createdAt DESC);

-- Fixed-window counters for the application's own endpoints. Separate from
-- Better Auth's `rateLimit` table, which only covers `/api/auth/*`.
CREATE TABLE IF NOT EXISTS rate_limit (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  windowStart INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS rate_limit_window_idx ON rate_limit (windowStart);
