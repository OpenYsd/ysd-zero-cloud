# YSD Zero Cloud

YSD Zero Cloud is a zero-cost-first cloud operating system. Version `0.2.0` replaces the mock
foundation with a real one: authentication, persistence, security scanning, and the cost guard all
run against a live Cloudflare D1 database.

**Live:** <https://ysd-zero-cloud.ysd-zero-cloud.workers.dev>

This is a standalone project intended only for `OpenYsd/ysd-zero-cloud`. It has no dependency on,
and makes no changes to, `OpenYsd/ysd-ai`.

## What is live

Every figure on these surfaces is read from your own D1 database at request time.

| Surface | Backed by |
| --- | --- |
| Sign in / sign up | Better Auth on D1, email + password, optional GitHub OAuth |
| Home | Live project, deployment, table, and usage counts |
| Projects | `project` table, with create and delete |
| Deployments | Smart Deploy plans recorded in `deployment`, accepted and blocked alike |
| Databases | Live schema introspection of the D1 database |
| Database Studio | Real rows, paginated and filtered, with credential columns redacted |
| SQL Editor | Real statements, classified by the SQL guard; limited to the instance owner |
| Logs | The `log_event` audit trail every mutating action writes to |
| Secrets | AES-GCM sealed values in `secret`, write-only by design |
| Usage | Counts measured from D1 against the free-tier catalog |
| Zero Mode | A workspace setting the server enforces, not a client preference |
| YSD Shield | Rules scored against a real snapshot of the workspace |

Storage, AI, Game Servers, Nodes, and Networking are still design previews. They are labelled
`Preview` in the navigation and carry a notice on the page explaining what is missing, because a
convincing screen of invented numbers is worse than an honest empty one.

## Zero Mode

Zero Mode is on by default and enforced on the server. `POST /api/smart-deploy` reads the flag from
the workspace row and ignores any value in the request body, so a client cannot ask for the guard to
be lifted — turning it off is a settings change, and settings changes are written to the audit log.

A plan is rejected unless **every** resource in it is both free-tier eligible and projected at
exactly zero. There is no budget, no threshold, and no allowance for "just a little". Blocked plans
are still recorded: a refusal is the more interesting half of an audit trail.

The project has no billing relationship with any provider. `lib/zero-mode.ts` holds the catalog of
resources the planner may reach for, and each entry states why it is free.

## Tenancy

One D1 database backs every workspace, so who can see which rows is a design decision rather than a
side effect:

- **Every API is workspace-scoped.** A route reads the caller's workspace id from their session and
  filters on it; nothing accepts a workspace id from the client.
- **Database Studio is row-scoped.** `lib/tenancy.ts` derives a predicate per table — `workspaceId`
  for product tables, the caller's own id for `workspace` and `user`, `userId` for auth records. A
  table nobody has classified returns a predicate that matches nothing, so adding a table without
  thinking about tenancy makes it invisible rather than public.
- **The SQL Editor is limited to the instance owner.** An arbitrary statement cannot be rewritten to
  carry a tenant predicate without a real SQL planner, so rather than leak every workspace through
  it, the editor answers 403 for everyone else and points them at Studio. The owner is
  `YSD_OWNER_EMAIL`, or the first registered account when that is unset.

## Security

- **Secrets are write-only.** Values are sealed with AES-GCM (HKDF-derived key) before they reach
  the database, and there is no endpoint that unseals them. Rotating means replacing.
- **The SQL Editor cannot reach credentials.** `account`, `session`, and `verification` are
  unreachable; `user` is read-only; writes need an explicit opt-in; structural statements, stacked
  statements, and pragmas outside a short allow list are refused. See `lib/sql-guard.ts` and its
  tests.
- **Database Studio redacts on the server.** Password hashes, tokens, and ciphertext are masked
  before a row leaves the Worker, so an API client sees the same redaction the browser does.
- **Every API route requires a session** and is scoped to the caller's workspace.

## Local development

Requirements: Node.js 22.13 or newer and npm.

```bash
npm install
npm run dev
```

Open the printed URL and create a workspace. The schema is applied on the first request, so no
database setup is needed — Miniflare provisions a local D1 database automatically.

> **Windows note.** Miniflare stores the local database at
> `<state>/v3/d1/miniflare-D1DatabaseObject/<database-id>.sqlite`. In a deeply nested checkout that
> path can cross the 260-character limit, and SQLite reports the failure only as
> `internal error; reference = …`. Set `YSD_LOCAL_STATE_PATH` to something short and restart:
>
> ```bash
> YSD_LOCAL_STATE_PATH=C:/ysd-state npm run dev
> ```

## Verification

```bash
npm test
npm run typecheck
npm run lint
npm run build
```

## Deployment

Everything below is on Cloudflare's free plan. There is no billing relationship, no paid binding,
and nothing that can be upgraded into one.

```bash
wrangler d1 create ysd-zero-cloud
```

Paste the returned `database_id` into `wrangler.jsonc`, then:

```bash
wrangler secret put BETTER_AUTH_SECRET
```

```bash
npm run db:migrate
```

```bash
npm run predeploy && npm run deploy
```

`predeploy` builds and then normalises the generated `dist/server/wrangler.json`: the Vite plugin
emits it with the wrangler version it bundles, which still writes fields a newer CLI refuses.

`BETTER_AUTH_SECRET` is required outside development. The app falls back to a published development
constant locally and refuses to start on that constant anywhere else.

## Configuration

Copy `.env.example` to `.env.local`. Only `BETTER_AUTH_SECRET` is required, and only outside
development; every other entry unlocks an optional integration and is reported as
`Not configured` in Settings until it is set.

| Integration | Adds | Keys |
| --- | --- | --- |
| Cloudflare D1 | Workspace database and auth storage | `DB` binding |
| GitHub sign-in | OAuth sign-in | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` |
| GitHub repositories | Real framework detection in Smart Deploy | `GITHUB_TOKEN` |
| Cloudflare account | Reports D1 storage size | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_D1_DATABASE_ID` |
| Supabase | Optional PostgreSQL adapter | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` |

Without a `GITHUB_TOKEN`, Smart Deploy still inspects public repositories anonymously and marks the
plan `inspected`; when it cannot read the repository it falls back to name-based inference and says
so rather than presenting a guess as a fact.

## Acceptance run

`public-acceptance.py` drives the deployed URL the way a browser would — real sign-up, real session
cookies, real D1 writes — and asserts on auth gating, workspace isolation, the SQL guard, Zero Mode
enforcement, and every page.

```bash
python public-acceptance.py
```

Point it elsewhere with `YSD_ACCEPTANCE_BASE`. Set `YSD_ACCEPTANCE_OWNER_EMAIL` and
`YSD_ACCEPTANCE_OWNER_PASSWORD` to also exercise the owner-only SQL Editor path; without them the
run still asserts that a non-owner is refused, which is the half that matters for security.

## Database

Migrations live in `db/migrations` and run two ways: automatically on the first request of a Worker
isolate (idempotent, so a cold start racing another converges), and through
`wrangler d1 migrations apply` for a deliberate deploy.

`db/migrations/0001_auth.sql` is generated from Better Auth itself rather than hand-written, so the
schema cannot drift from the options the app boots with:

```bash
npm run auth:schema
```

## Architecture

```text
app/
  page.tsx               Overview, loaded per request
  [section]/             Workspace sections
  databases/[tool]/      Database Studio and SQL Editor
  sign-in, sign-up/      Better Auth screens
  api/                   Session-scoped route handlers
components/              Server views plus the interactive client surfaces
lib/
  domain.ts              Shapes that cross the server/client boundary
  zero-mode.ts           Cost policy and the free-tier resource catalog
  free-tier.ts           Allowances and usage arithmetic
  sql-guard.ts           SQL Editor statement classification
  tenancy.ts             Row-level scoping for the surfaces that read D1 directly
  shield.ts              Security rules and scoring, as pure functions
  crypto.ts              AES-GCM envelope encryption for secrets
  server/                D1 access, auth, and the per-surface data modules
db/migrations/           SQL applied to D1
tests/                   Node test runner coverage of every pure module
```

The server modules are the only place `cloudflare:workers` is imported. Client components read
their types from `lib/domain.ts` so no Worker code can reach a browser bundle.

The frontend is built with React 19, Vinext, Tailwind CSS, shadcn components, and Cloudflare
Workers output.

## Roadmap

1. Execute accepted plans through a deploy pipeline rather than recording them.
2. Back Storage with R2 and retire that preview.
3. Add organizations, roles, and per-member audit scoping.
4. Connected-node agent, which unlocks the Game Servers and Nodes surfaces.
5. Read domains and routes from the Cloudflare API for Networking.
