# YSD Zero Cloud

YSD Zero Cloud is a zero-cost-first cloud operating system. Version `0.10.0` runs authentication,
persistence, security scanning, the cost guard, private-object storage policy, network inventory,
an outbound-only user-owned compute control plane, a private Node.js App Runtime, local AI
scheduling, private Minecraft Java server orchestration, organization collaboration, and a
fail-closed Public App Exposure control plane against Cloudflare Workers and D1. It also includes
the tenant-isolated YSD Workflows engine: immutable published versions, bounded D1 execution,
internal notifications, audit history, one global free-plan scheduler tick, and a signed inbound
External Event Gateway with workspace-scoped webhook sources.

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
| Deployments       | Safe Node.js builds and lifecycle actions on paired user-owned Compute Nodes  |
| Databases         | Live schema introspection of the D1 database                                  |
| Database Studio   | Real rows, paginated and filtered, with credential columns redacted           |
| SQL Editor        | Real statements, classified by the SQL guard; limited to the instance owner   |
| Logs              | The `log_event` audit trail every mutating action writes to                   |
| Secrets           | AES-GCM sealed values in `secret`, write-only by design                       |
| Usage             | Counts measured from D1 against the free-tier catalog                         |
| Zero Mode         | A workspace setting the server enforces, not a client preference              |
| YSD Shield        | Rules scored against a real snapshot of the workspace                         |
| Storage           | Private R2 adapter, D1 authorization index, and hard account/workspace quotas |
| Networking        | YSD Gateway routes, exposure/domain policy, TLS/health state, and inventory   |
| Nodes             | Paired user-owned agents, signed job leases, heartbeats, metrics, and audit   |
| YSD AI Compute    | Approved local models, safe scheduling, cancellation, results, and metrics   |
| App Runtime       | Private Node.js deploy, health, logs, metrics, rollback, and artifact guards  |
| Game Servers      | Private Minecraft Java lifecycle, players, backups, logs, and resource guards|
| Workflows         | D1 workflows plus signed, source-bound External Event integrations           |

Storage, Networking, Nodes, App Runtime, YSD AI Compute, and Game Servers are live surfaces.
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

Organization roles are `owner`, `admin`, `developer`, and `viewer`. Owner/admin
manage production exposure and owned-domain inventory. A developer can deploy
and may create an expiring Preview route only when Preview deployments are
enabled; a viewer is read-only. Project restrictions intersect every role and
service-account scope. The SQL Editor remains unavailable to organization
roles because arbitrary SQL cannot be made tenant-safe by a client-side flag.

The rules in `lib/roles.ts` stop self-promotion, acting on an equal or superior,
granting ownership without being an owner, and demoting the last owner.
Suspending an account drops its sessions immediately.

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

Phase 8 adds `public_exposure` and `exposure_domain` metadata, the path-based
`/apps/<route-id>/` YSD Gateway, D1 rate limits, server-side authenticated access,
health and artifact gates, deterministic expiring Preview identities, custom-domain
ownership proof, lifecycle cleanup, role enforcement, audit events, and Shield rules.
The Gateway performs an exact registered-deployment lookup and has no user URL,
IP, endpoint, command, or provider input; arbitrary upstreams and SSRF-shaped
fields are rejected and audited.

The current account review found Workers Free active, no payment method, zero
owned Zones, and zero Tunnels. A Cloudflare Tunnel can be outbound-only, but a
published application still requires an owned Zone in this architecture. No
Tunnel, custom hostname, route, domain, paid load balancer, router port, UPnP,
or firewall rule was created. Public policies therefore persist as
`unavailable_zero_mode`, no URL is claimed, TLS stays unavailable, and Gateway
requests return a generic 503. Custom-domain inventory and DNS TXT ownership
verification remain available for a hostname the user already owns; attachment
is blocked until a future review proves an owned Cloudflare Zone and a `$0.00`
path without Billing.

Node origins remain private and are redacted from UI and API responses. The
deployment guard pins the verified plan/billing/Zone/Tunnel state and refuses
`routes`, service bindings, paid providers, or a client `zeroMode=false` bypass.
YSD Shield checks unexpected exposure, unhealthy/revoked routes, missing TLS,
unverified or conflicting domains, open-proxy/SSRF attempts, origin leaks,
route volume, disabled rate limits, domain churn, low-privilege changes,
connector anomalies, orphan routes, and paid-provider bypass attempts.

## External Event Gateway

Phase 10 adds organization/workspace-scoped webhook sources on the existing Worker and D1. An
owner or admin creates a source and receives its secret once. D1 stores an AES-GCM envelope and a
non-reversible fingerprint; Database Studio masks both fields. Rotation replaces the credential,
and disabling or archiving the source stops ingress server-side.

Inbound v1 requests use `POST /api/webhooks/inbound/<source-id>`, `Content-Type: application/json`,
and a body no larger than 32 KiB. Four headers bind the request:

- `x-ysd-timestamp`: current Unix time in seconds, within five minutes.
- `x-ysd-event-id`: a stable source event identifier.
- `x-ysd-nonce`: a new 16–128 character URL-safe random value.
- `x-ysd-signature`: `v1=` plus the lowercase HMAC-SHA256 hex digest of
  `timestamp.eventId.nonce.rawJsonBody`.

The JSON root contains `event`, optional `subject`, and optional `data`. `data` accepts only the
bounded scalar keys `status`, `severity`, `category`, `action`, `environment`, `ref`, `label`,
`count`, `value`, and `success`. URLs, internal addresses, commands, shells, scripts, providers,
secret-shaped values, nested objects, and unknown fields fail closed. D1 enforces single-use event
IDs and nonce digests per source, while separate source and workspace rate limits protect the
shared Worker. Accepted data becomes a server-trusted `external.event` with a correlation ID; the
gateway stores only safe delivery metadata and never stores the raw body, signature, or nonce.

There is deliberately no generic outbound HTTP, JavaScript, shell, Queue, Durable Object, or
Cloudflare Workflows action. Phase 10 reuses the existing Worker, D1 database, Workflow engine, and
one-minute Cron Trigger, so the projected incremental monthly cost remains `$0.00` under Zero Mode.

## Compute Nodes

Compute Nodes make the Worker a control plane for machines the operator already owns. The agent
opens no listener and exposes no local port: it sends outbound HTTPS heartbeats, polls D1-backed
work, verifies the Worker's signed lease claim, runs one allowlisted handler, and posts a signed
completion. Cloudflare never performs the workload compute.

- Pairing tickets carry 192 bits of entropy, expire after ten minutes, and are consumed once. D1
  stores only their SHA-256 digest.
- Each node receives a separate bearer credential. D1 stores it inside the same AES-GCM envelope
  used for workspace secrets and also keeps a one-way digest for verification. Revocation erases the
  ciphertext; the retained digest can identify and block use of the exact revoked token without
  preserving anything that can authenticate.
- Every agent request signs the method, path, timestamp, random nonce, and exact body with HMAC.
  Nonces are unique per node in D1 and timestamps have a one-minute window, so captured requests
  cannot be replayed.
- Claims bind the workspace, node, job type, payload digest, lease id, expiry, and attempt. Expired
  leases return to the queue up to three attempts, then become timed out. An idempotency key stops a
  browser retry from creating a duplicate job.
- The agent has no `eval`, generic script, command, or shell handler. It runs diagnostics, reviewed
  local AI handlers, fixed App Runtime executable/argument contracts, and a fixed Minecraft Java
  invocation with `shell=false`. Ollama and llama.cpp use fixed loopback APIs; model acquisition
  uses an approved catalog and explicit operator consent.
- The local credential file is AES-256-GCM encrypted with a passphrase that never leaves the node.
  See `agent/README.md` for pairing and service-run instructions.

YSD Shield inspects stale and offline nodes, minimum agent version, revoked-node activity, unsigned
jobs, stale leases, forged or replayed AI claims, model integrity, forbidden providers, payload
abuse, resource pressure, anomalous volume, private Game Server exposure, backup integrity, crash
loops, unsafe properties, and lifecycle activity after revocation.

## YSD App Runtime / Smart Deploy

Smart Deploy now turns a public GitHub repository into a pinned, tenant-scoped Node.js deployment
on a paired machine owned by the operator. The Worker inspects repository metadata and creates a
structured safe-build contract; the user-owned Node downloads the pinned GitHub archive, installs
from exactly one lockfile with lifecycle scripts disabled, starts `node` with a fixed argument
array, and performs a localhost-only health check. Cloudflare stores control-plane metadata only and
does not perform application builds or runtime compute.

App Runtime v1 accepts npm, pnpm, or Yarn only when the matching lockfile is present. It detects
Node HTTP, Express, and Fastify contracts with an exact `node relative/file.js` entrypoint. Next.js,
Vite, NestJS, user build scripts, lifecycle hooks, repository package-manager configuration,
submodules, LFS pointers, arbitrary Git URLs, shell fields, executable paths, provider overrides,
and paid tunnels fail closed. Private repositories are rejected in v1 rather than proxying source
or credentials through the control plane.

Each deployment receives a collision-checked loopback port and stays `private`; YSD never opens a
router port, UPnP mapping, public bind, domain, or tunnel. Start, stop, restart, redeploy, rollback,
delete, and status actions reuse the signed Phase 3 job queue. Artifacts carry checksums and a
Node-signed manifest, retention is bounded, logs are bounded and redacted twice, environment values
are encrypted/write-only, and health failure, crash loops, cancellation, resource pressure, stale
leases, replay, revocation, symlink escape, and cross-workspace access are all fail-closed states.

## YSD AI Compute

AI Center dispatches inference only to a paired, online machine that already owns the compute.
The scheduler requires the selected allowlisted runtime and model cache, sufficient free RAM/VRAM,
safe CPU load, and a free concurrency slot. D1 stores workspace-scoped model/cache metadata, job
leases, token estimates, latency, bounded results, cancellation state, and audit events. Prompts
cannot introduce a network target, filesystem path, shell field, provider override, or executable.

The initial reviewed catalog contains small Ollama library models and a generic already-loaded
llama.cpp local model. Downloads are optional, explicitly approved, disk-guarded, and remain on the
user's node. No Workers AI binding, paid queue, GPU service, billing relationship, or provider
fallback is configured.

## YSD Game Servers

Game Servers schedules allowlisted Minecraft Java Vanilla releases on a paired machine owned by the
operator. The Worker and D1 retain only tenant-scoped control metadata, bounded redacted log tails,
signed action state, and local-backup checksums. Server binaries, worlds, full logs, and backups stay
inside a per-workspace, per-server directory on the node.

Lifecycle actions are limited to create, start, stop, restart, status, and delete. Player management
is limited to list, whitelist, kick, op, and deop; there is no console textbox. Configuration is a
fixed safe `server.properties` shape. Downloads can reach only Mojang's reviewed HTTPS metadata and
binary hosts, the binary is hash-verified, Java runs with fixed arguments and no shell, and symlink or
path traversal boundaries fail closed. RAM, disk reserve, port ownership, concurrency, crash-loop,
lease, replay, revocation, and idempotency guards apply before local work.

No public port, UPnP rule, tunnel, paid provider, R2 bucket, or inbound agent listener is created.
Joining a server remains a deliberate local-networking choice made outside YSD.

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
- **Agent routes require signed requests.** A bearer token alone is insufficient: timestamp, nonce,
  path, method, and body must all match the HMAC, and every nonce is accepted once.

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

With the local server running on port 3000 and interactive Turnstile keys omitted, the real
Worker+D1 node protocol can be exercised end to end:

```bash
python node-acceptance.py
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
paid-capable binding or custom route, a changed Phase 8 account attestation, or a cost value other
than exactly zero. The Vite plugin emits the generated
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
| GitHub repositories  | Safe public-repository inspection for Node.js App Runtime          | `GITHUB_TOKEN`                                                               |
| Cloudflare account   | Reports D1 storage size                                           | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_D1_DATABASE_ID` |

Without a `GITHUB_TOKEN`, Smart Deploy still inspects public repositories anonymously, subject to
GitHub's public rate limit. It never falls back to repository-name guesses and never accepts a
private source it could not inspect.

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
agent/                    Outbound-only Node Agent and encrypted local credential store
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
4. Add another game only after it has an equally narrow reviewed runtime contract.
5. Add owned-domain inventory only after a domain exists; keep workers.dev as the zero-cost default.
