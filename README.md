# YSD Zero Cloud

YSD Zero Cloud is a zero-cost-first cloud operating system. Version `0.3.0` runs authentication,
persistence, security scanning, the cost guard, private-object storage policy, and network inventory
against Cloudflare Workers and D1.

**Live:** <https://ysd-zero-cloud.ysd-zero-cloud.workers.dev>

This is a standalone project intended only for `OpenYsd/ysd-zero-cloud`. It has no dependency on,
and makes no changes to, `OpenYsd/ysd-ai`.

## What is live

Live surfaces are derived at request time from your own D1 database or the
deployed Worker's explicit zero-cost configuration.

| Surface           | Backed by                                                                     |
| ----------------- | ----------------------------------------------------------------------------- |
| Sign in / sign up | Better Auth on D1, email + password, optional GitHub OAuth                    |
| Home              | Live project, deployment, table, and usage counts                             |
| Projects          | `project` table, with create and delete                                       |
| Deployments       | Smart Deploy plans recorded in `deployment`, accepted and blocked alike       |
| Databases         | Live schema introspection of the D1 database                                  |
| Database Studio   | Real rows, paginated and filtered, with credential columns redacted           |
| SQL Editor        | Real statements, classified by the SQL guard; limited to the instance owner   |
| Logs              | The `log_event` audit trail every mutating action writes to                   |
| Secrets           | AES-GCM sealed values in `secret`, write-only by design                       |
| Usage             | Counts measured from D1 against the free-tier catalog                         |
| Zero Mode         | A workspace setting the server enforces, not a client preference              |
| YSD Shield        | Rules scored against a real snapshot of the workspace                         |
| Storage           | Private R2 adapter, D1 authorization index, and hard account/workspace quotas |
| Networking        | Deployed workers.dev origin, TLS, route exposure, and binding inventory       |

AI, Game Servers, and Nodes are still design previews. Storage and Networking are live surfaces.
The current Cloudflare account returns `10042: Please enable R2`, so Storage honestly renders the
implemented adapter as unavailable and refuses uploads; no bucket, public endpoint, or billable
resource is created while that account-level gate remains.

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

## Roles

Three instance roles: `owner`, `admin`, `member`. They govern the _instance_ —
who may administer accounts, who may reach the raw SQL Editor — and never what
anyone may see inside another workspace. Tenant isolation is enforced
separately and is not widened by any role.

- **owner** — everything, including the SQL Editor. Bootstrapped from
  `YSD_OWNER_EMAIL`, or the earliest account when that is unset.
- **admin** — account management: roles, suspension. Deliberately does _not_
  inherit the SQL Editor, because a raw statement cannot be scoped to one
  workspace.
- **member** — their own workspace, nothing else. Every new sign-up is a member.

The rules in `lib/roles.ts` stop self-promotion, acting on an equal or
superior, granting ownership without being an owner, and demoting the last
owner. Suspending an account drops its sessions immediately.

## Abuse protection

Public sign-up stays open, so the unauthenticated surface is layered:

1. **Rate limiting** — fixed-window counters in D1, because a Worker isolate is
   discarded between requests and an in-memory counter would enforce nothing.
   Sign-in and sign-up have tighter budgets than ordinary API traffic, and
   every guarded response advertises `RateLimit-*` headers.
2. **Turnstile** — free on every Cloudflare plan. Configuration-gated: without
   keys the widget cannot render, so requiring a token would lock everyone out.
   Verification fails _closed_ if Cloudflare cannot be reached.
3. **Brute-force lockout** — separate from rate limiting, because a stuffing
   run spread across many addresses stays under any per-IP limit while still
   hammering one account. Failures are counted back to the last success, so a
   mistyped password does not accumulate forever.
4. **Suspicious-login auditing** — a successful sign-in from a new network or
   device, after a run of failures, or against an account being probed from
   several addresses, is recorded to the audit log. These are reported, not
   blocked: people travel and buy laptops.

Email verification is wired end to end but only _required_ when a mail provider
is configured, for the same reason Turnstile is gated.

Production explicitly sets `YSD_EMAIL_VERIFICATION_MODE=disabled-no-domain` because the Cloudflare
account has no owned sending domain. That gate overrides stale email credentials and keeps delivery
off. Shield reports **Email verification unavailable: no owned sending domain** as a low-severity
operational constraint, not as a code defect. No Resend account is required until an owned domain is
deliberately added later.

YSD Shield checks all of the above and reports anything unconfigured, so a
missing protection is visible rather than assumed.

## Private object storage

R2 is never exposed through `r2.dev` or a custom domain. The only planned binding is `STORAGE`, and
objects are addressed through session-protected `/api/storage/*` routes after D1 confirms the
workspace owner. Upload bodies require a bounded `Content-Length`, each object stops at 10 MB, each
workspace at 256 MB, and the whole account at 1 GB. Monthly Class A and Class B operations stop at
5% of R2 Standard's published free allowances. There is no overflow or paid fallback.

Until Cloudflare enables R2 for this account, the binding is omitted from the deployed config and
the API returns 503 before attempting an R2 operation. When R2 can be enabled at a confirmed `$0`,
create only `ysd-zero-cloud-storage`, bind it as `STORAGE`, and set
`YSD_R2_BUCKET_NAME=ysd-zero-cloud-storage` for the deployment guard.

## Networking

Networking is inventory, not a provisioning loophole. It derives the actual HTTPS workers.dev
origin and shows which routes are public, session-scoped, or internal bindings. The production mode
is `workers-dev-only`: zero custom domains, zero tunnels, zero public R2 endpoints, and no Argo,
Spectrum, load balancer, or paid route.

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

## Known upstream issue: client navigation

`next/link` is not used anywhere in this application, and that is deliberate.

vinext's client Link runtime is broken in its production bundle. On click the handler calls
`preventDefault()` and then reaches for `navigateClientSide`, which the chunk it is dynamically
imported from never exports under that name — the bundler mangles the export list and the by-name
destructure finds nothing. The call throws, the `window.location.assign` fallback sits in an
unreachable `else`, and the browser's own navigation has already been cancelled. Every link in the
application was inert. Reproduced on the deployed Worker in vinext `1.0.0-beta.5` and
`1.0.0-beta.8`.

`components/nav-link.tsx` renders a plain anchor instead. The same defect breaks `router.push`, so
signing in and out use `window.location.assign` rather than a soft navigation — otherwise the root
layout stays cached and the operator lands on the overview still wrapped in the signed-out shell.

The cost is a full document load per navigation. When vinext ships a working Link, pointing
`NavLink` at `next/link` reverts the whole change.

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

Before every deployment, explicitly attest the free plan and expected D1 binding in the current
shell. The deployment is blocked unless the confirmed monthly estimate is exactly zero:

```bash
YSD_FREE_TIER_VERIFIED=true \
YSD_ESTIMATED_MONTHLY_COST=0 \
YSD_D1_DATABASE_ID=4175f8f4-34ff-4234-bbf4-72cc2602c520 \
npm run deploy
```

PowerShell:

```powershell
$env:YSD_FREE_TIER_VERIFIED = 'true'
$env:YSD_ESTIMATED_MONTHLY_COST = '0'
$env:YSD_D1_DATABASE_ID = '4175f8f4-34ff-4234-bbf4-72cc2602c520'
npm run deploy
```

The `predeploy` lifecycle builds, normalises the generated `dist/server/wrangler.json`, and runs
the Zero Mode deployment guard automatically. The guard refuses an unexpected D1 database, any
paid-capable binding, or a cost value other than exactly zero. The Vite plugin emits the generated
configuration with the Wrangler version it bundles, so normalisation also removes fields a newer
CLI refuses.

`BETTER_AUTH_SECRET` is required outside development. The app falls back to a published development
constant locally and refuses to start on that constant anywhere else.

## Configuration

Copy `.env.example` to `.env.local`. Only `BETTER_AUTH_SECRET` is required, and only outside
development; every other entry unlocks an optional integration and is reported as
`Not configured` in Settings until it is set.

| Integration          | Adds                                                              | Keys                                                                         |
| -------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Cloudflare D1        | Workspace database and auth storage                               | `DB` binding                                                                 |
| Cloudflare R2        | Private object storage (account enablement currently unavailable) | `STORAGE` binding                                                            |
| Better Auth          | D1-backed identities and sessions                                 | `BETTER_AUTH_SECRET`                                                         |
| Cloudflare Turnstile | Bot protection for sign-in and sign-up                            | `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY`                                 |
| Verification email   | Configuration-gated off until an owned sending domain exists      | `YSD_EMAIL_VERIFICATION_MODE`, then `RESEND_API_KEY`, `YSD_EMAIL_FROM`       |
| GitHub sign-in       | OAuth sign-in                                                     | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`                                   |
| GitHub repositories  | Real framework detection in Smart Deploy                          | `GITHUB_TOKEN`                                                               |
| Cloudflare account   | Reports D1 storage size                                           | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_D1_DATABASE_ID` |

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
  nav-link.tsx           Plain-anchor navigation; see the note above
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
2. Enable the already-implemented private R2 binding only if Cloudflare confirms `$0` account activation.
3. Add organizations, roles, and per-member audit scoping.
4. Connected-node agent, which unlocks the Game Servers and Nodes surfaces.
5. Add owned-domain inventory only after a domain exists; keep workers.dev as the zero-cost default.
