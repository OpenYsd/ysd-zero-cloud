# YSD Zero Cloud

YSD Zero Cloud is a zero-cost-first cloud operating system. Version `0.1.0` is a local, mock-backed product foundation for managing applications, data, AI, game infrastructure, connected nodes, and security from one workspace.

This is a standalone project intended only for `OpenYsd/ysd-zero-cloud`. It has no dependency on, and makes no changes to, `OpenYsd/ysd-ai`.

## v0.1 surfaces

- Home overview with resource health and free-tier usage
- Projects and deployment history
- Smart Deploy repository analysis and provider planning
- Databases, Database Studio, and SQL Editor
- Storage buckets and object usage
- AI endpoints and mock inference playground
- Game servers with idle sleep behavior
- Bring-your-own nodes
- Live-style logs and networking
- Encrypted secret inventory
- Usage and projected cost
- Workspace settings and integration readiness
- YSD Shield security center

## Zero Mode

Zero Mode is enabled by default. Before Smart Deploy can proceed, every planned resource is checked by `lib/zero-mode.ts`. A plan is blocked when a resource:

- has a projected monthly cost above zero; or
- is not explicitly eligible for a free tier.

The protection logic is isolated and covered by unit tests so real provider adapters can reuse the same policy later.

## Mock-first integrations

The UI works without external credentials. `lib/integrations.ts` exposes a provider-neutral catalog for GitHub, Cloudflare, and Supabase, while `GET /api/integrations` reports which adapters are still in mock mode.

Copy `.env.example` to `.env.local` when real credentials become available. Do not commit secrets.

| Provider | Planned responsibility | Required configuration |
| --- | --- | --- |
| GitHub | Repository discovery and webhooks | `GITHUB_TOKEN` |
| Cloudflare | Workers, DNS, and R2 | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` |
| Supabase | PostgreSQL, Auth, and Storage | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` |

## Local development

Requirements: Node.js 22.13 or newer and npm.

```bash
npm install
npm run dev
```

Open the local URL printed in the terminal. The development server chooses the next available port if `3000` is occupied.

## Verification

```bash
npm test
npm run typecheck
npm run lint
npm run build
```

## Architecture

```text
app/
  [section]/             Cloud OS routes
  databases/[tool]/      Database Studio and SQL Editor
  api/                   Integration and Smart Deploy boundaries
components/
  cloud-shell.tsx        Shared responsive operating surface
  section-dashboard.tsx  Product-specific route views
  smart-deploy-panel.tsx Interactive deployment planner
  database-workspace.tsx Mock data and query workspace
lib/
  integrations.ts        Provider-neutral adapter catalog
  smart-deploy.ts        Extensible plan builder
  zero-mode.ts           Cost protection policy
tests/                   Node test runner coverage
```

The frontend is built with React 19, Vinext, Tailwind CSS, shadcn components, and Cloudflare-compatible ESM output.

## Roadmap

1. Add OAuth-based GitHub repository discovery and signed webhooks.
2. Implement Cloudflare and Supabase adapters behind the existing integration boundary.
3. Persist projects and deployment state.
4. Add authenticated organizations, roles, and audit trails.
5. Execute Smart Deploy plans through durable background workflows.
