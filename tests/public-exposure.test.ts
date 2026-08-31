import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import {
  domainVerificationQueryUrl,
  gatewayDecision,
  gatewayResponseHeaders,
  ipAllowed,
  normalizeCustomHostname,
  parseExposureMutation,
  type GatewayCandidate,
} from '../lib/public-exposure.ts';
import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';

const NOW = Date.UTC(2026, 7, 31, 12);
const DEPLOYMENT_ID = `dpl_${'a'.repeat(24)}`;

const READY: GatewayCandidate = {
  mode: 'public',
  status: 'active',
  accessPolicy: 'public',
  transportState: 'ready',
  health: 'healthy',
  tls: 'cloudflare',
  verification: 'not_required',
  expiresAt: null,
  rateLimitEnabled: true,
};

function mutation(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    deploymentId: DEPLOYMENT_ID,
    mode: 'public',
    accessPolicy: 'authenticated',
    fallbackPolicy: 'none',
    rateLimitEnabled: true,
    rateLimitPerMinute: 60,
    ipAllowlist: [],
    preview: false,
    ...overrides,
  };
}

void test('private, missing, expired, and revoked routes are publicly invisible', () => {
  for (const route of [
    null,
    { ...READY, mode: 'private' as const },
    { ...READY, status: 'expired' as const },
    { ...READY, status: 'revoked' as const },
    { ...READY, expiresAt: NOW - 1 },
  ]) {
    assert.deepEqual(gatewayDecision({ route, now: NOW, authenticatedMember: true, ipAllowed: true }), {
      action: 'not-found', status: 404,
    });
  }
});

void test('a reviewed healthy route is forwardable only after every gate passes', () => {
  assert.deepEqual(gatewayDecision({ route: READY, now: NOW, authenticatedMember: false, ipAllowed: true }), {
    action: 'forward', status: 200,
  });
  assert.deepEqual(gatewayDecision({
    route: { ...READY, accessPolicy: 'authenticated' }, now: NOW,
    authenticatedMember: false, ipAllowed: true,
  }), { action: 'authenticate', status: 401 });
  assert.deepEqual(gatewayDecision({
    route: { ...READY, accessPolicy: 'authenticated' }, now: NOW,
    authenticatedMember: true, ipAllowed: true,
  }), { action: 'forward', status: 200 });
  assert.deepEqual(gatewayDecision({ route: READY, now: NOW, authenticatedMember: true, ipAllowed: false }), {
    action: 'deny', status: 403,
  });
});

void test('stale, offline, revoked, failed, disconnected, and unverified TLS routes fail closed', () => {
  for (const route of [
    { ...READY, health: 'stale' as const },
    { ...READY, health: 'offline' as const },
    { ...READY, health: 'revoked' as const },
    { ...READY, health: 'failed' as const },
    { ...READY, transportState: 'disconnected' as const },
    { ...READY, rateLimitEnabled: false },
    { ...READY, mode: 'custom-domain' as const, verification: 'pending' as const },
    { ...READY, mode: 'custom-domain' as const, verification: 'verified' as const, tls: 'unavailable' as const },
  ]) {
    assert.deepEqual(gatewayDecision({ route, now: NOW, authenticatedMember: true, ipAllowed: true }), {
      action: 'unavailable', status: 503,
    });
  }
});

void test('user-provided upstreams, SSRF targets, paid providers, commands, and Zero Mode overrides are rejected', () => {
  const hostile = [
    ['upstreamUrl', 'http://169.254.169.254/latest/meta-data'],
    ['originIp', '127.0.0.1'],
    ['endpoint', 'http://10.0.0.1'],
    ['upstream', 'http://192.168.1.10'],
    ['originAddress', 'http://172.16.0.2'],
    ['targetIp', '::1'],
    ['targetAddress', 'fd00::1'],
    ['tunnelProvider', 'paid'],
    ['command', 'cloudflared tunnel run'],
    ['zeroMode', false],
    ['billing', true],
  ] as const;
  for (const [key, value] of hostile) {
    const result = parseExposureMutation(mutation({ [key]: value }), NOW);
    assert.equal(result.ok, false, key);
    if (!result.ok) {
      assert.equal(result.status, 400);
      assert.equal(result.securityEvent, 'gateway-upstream-rejected');
    }
  }
});

void test('route ids are deployment-derived and public routes cannot disable abuse protection', () => {
  assert.equal(parseExposureMutation(mutation({ deploymentId: 'forged' }), NOW).ok, false);
  assert.equal(parseExposureMutation(mutation({ rateLimitEnabled: false }), NOW).ok, false);
  assert.equal(parseExposureMutation(mutation({ rateLimitPerMinute: 4 }), NOW).ok, false);
  assert.equal(parseExposureMutation(mutation({ rateLimitPerMinute: 601 }), NOW).ok, false);
  assert.equal(parseExposureMutation(mutation({ rateLimitPerMinute: 60 }), NOW).ok, true);
});

void test('IPv4 allowlists accept canonical CIDRs and deny internal or forged clients outside policy', () => {
  assert.equal(ipAllowed('203.0.113.8', ['203.0.113.0/24']), true);
  assert.equal(ipAllowed('127.0.0.1', ['203.0.113.0/24']), false);
  assert.equal(ipAllowed('10.0.0.1', ['203.0.113.0/24']), false);
  assert.equal(parseExposureMutation(mutation({ ipAllowlist: ['203.0.113.1/24'] }), NOW).ok, false);
});

void test('custom hostnames exclude IPs, internal names, workers.dev, and DNS-query SSRF', () => {
  for (const hostname of ['127.0.0.1', 'localhost', 'app.internal', 'fake.workers.dev', 'host:8080', 'a.example']) {
    assert.equal(normalizeCustomHostname(hostname), null, hostname);
    assert.equal(domainVerificationQueryUrl(hostname), null, hostname);
  }
  assert.equal(normalizeCustomHostname('App.Owned-Domain.com.'), 'app.owned-domain.com');
  assert.equal(
    domainVerificationQueryUrl('app.owned-domain.com'),
    'https://cloudflare-dns.com/dns-query?name=_ysd-verification.app.owned-domain.com&type=TXT',
  );
});

void test('gateway responses suppress caching, referrers, and metadata leaks', () => {
  const headers = gatewayResponseHeaders({ 'x-extra': 'yes' });
  assert.equal(headers.get('cache-control'), 'no-store, max-age=0');
  assert.equal(headers.get('referrer-policy'), 'no-referrer');
  assert.equal(headers.get('x-content-type-options'), 'nosniff');
  assert.equal(headers.get('x-ysd-gateway'), 'fail-closed');
  assert.equal(headers.get('server'), null);
});

function migration(name: string): string {
  return readFileSync(new URL(`../db/migrations/${name}`, import.meta.url), 'utf8');
}

function apply(database: DatabaseSync, name: string): void {
  const sql = migration(name);
  if (name === '0010_organizations.sql' || name === '0011_public_exposure.sql') {
    for (const statement of splitStatements(stripSqlComments(sql))) database.exec(statement);
  } else {
    database.exec(sql);
  }
}

function exposureDatabase(): DatabaseSync {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = ON');
  for (const name of ['0001_auth.sql', '0002_workspace.sql', '0004_security.sql', '0006_compute_nodes.sql', '0009_app_runtime.sql', '0010_organizations.sql', '0011_public_exposure.sql']) {
    apply(database, name);
  }
  database.exec(`
    INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt)
      VALUES ('user_1','Owner','owner@owned.test',1,NULL,1,1), ('user_2','Other','other@owned.test',1,NULL,1,1);
    INSERT INTO organization (id,name,slug,ownerUserId,status,adminCanRevokeSessions,createdAt,updatedAt)
      VALUES ('org_1','One','one','user_1','active',1,1,1), ('org_2','Two','two','user_2','active',1,1,1);
    INSERT INTO workspace (id,name,ownerUserId,zeroMode,autoScan,sleepIdleServers,previewDeployments,createdAt,updatedAt,organizationId)
      VALUES ('ws_1','One','user_1',1,1,1,1,1,1,'org_1'), ('ws_2','Two','user_2',1,1,1,1,1,1,'org_2');
    INSERT INTO project (id,workspaceId,name,framework,environment,region,status,visibility,createdAt,updatedAt)
      VALUES ('project_1','ws_1','App','Node.js','Production','Local','healthy','private',1,1),
             ('project_2','ws_2','Other App','Node.js','Production','Local','healthy','private',1,1);
    INSERT INTO node_pairing (id,workspaceId,codeHash,name,createdBy,expiresAt,createdAt)
      VALUES ('pair_1','ws_1','hash_1','Node','user_1',9999999999999,1), ('pair_2','ws_2','hash_2','Node','user_2',9999999999999,1);
    INSERT INTO compute_node (id,workspaceId,pairingId,name,agentVersion,protocolVersion,platform,architecture,capabilities,tokenCiphertext,tokenHash,pairedAt,lastHeartbeatAt,createdAt,updatedAt)
      VALUES ('node_1','ws_1','pair_1','Node 1','1.0.0',1,'linux','x64','[]','cipher_1','token_1',1,${NOW},1,1),
             ('node_2','ws_2','pair_2','Node 2','1.0.0',1,'linux','x64','[]','cipher_2','token_2',1,${NOW},1,1);
    INSERT INTO deployment (id,workspaceId,projectId,repository,target,framework,commitSha,state,estimatedMonthlyCost,zeroModeEnabled,plan,createdAt,branch,environment,nodeId,currentArtifactId,localPort,localAddress,exposure,observedBind,healthPath,updatedAt)
      VALUES ('dpl_db_1','ws_1','project_1','openysd/app','node','Node.js','abc','healthy',0,1,'free',1,'main','Production','node_1',NULL,3000,'http://127.0.0.1:3000','private','loopback','/',1),
             ('dpl_db_2','ws_2','project_2','openysd/other','node','Node.js','def','healthy',0,1,'free',1,'main','Production','node_2',NULL,3001,'http://127.0.0.1:3001','private','loopback','/',1);
    INSERT INTO app_artifact (id,workspaceId,deploymentId,projectId,nodeId,commitSha,version,state,manifest,checksum,sizeBytes,createdAt,verifiedAt,activatedAt)
      VALUES ('art_1','ws_1','dpl_db_1','project_1','node_1','abc',1,'verified','{}','sum',1,1,1,1);
    UPDATE deployment SET currentArtifactId = 'art_1' WHERE id = 'dpl_db_1';
  `);
  return database;
}

void test('D1 prevents duplicate routes/domains, forged targets, and cross-organization writes', () => {
  const database = exposureDatabase();
  try {
    database.prepare(`INSERT INTO public_exposure
      (id,organizationId,workspaceId,projectId,deploymentId,routeId,routePath,mode,status,accessPolicy,transport,transportState,targetNodeId,targetArtifactId,healthState,tlsState,verificationState,fallbackPolicy,rateLimitEnabled,rateLimitPerMinute,ipAllowlist,isPreview,createdBy,createdAt,updatedAt)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      'exp_1','org_1','ws_1','project_1','dpl_db_1','route_1','/apps/route_1/','private','disabled','authenticated','none','unavailable_zero_mode','node_1','art_1','healthy','unavailable','not_required','none',1,60,'[]',0,'user_1',1,1,
    );
    assert.throws(() => database.prepare(`INSERT INTO public_exposure
      (id,organizationId,workspaceId,projectId,deploymentId,routeId,routePath,mode,status,accessPolicy,transport,transportState,targetNodeId,healthState,tlsState,verificationState,fallbackPolicy,rateLimitEnabled,rateLimitPerMinute,ipAllowlist,isPreview,createdBy,createdAt,updatedAt)
      VALUES ('exp_2','org_2','ws_1','project_1','dpl_db_1','route_2','/apps/route_2/','private','disabled','public','none','unavailable_zero_mode','node_1','healthy','unavailable','not_required','none',1,60,'[]',1,'user_2',1,1)`).run(), /tenant or target mismatch/);
    assert.throws(() => database.prepare("UPDATE public_exposure SET targetNodeId = 'node_2' WHERE id = 'exp_1'").run(), /tenant or target mismatch/);

    database.prepare(`INSERT INTO exposure_domain
      (id,organizationId,workspaceId,hostname,dnsRecordName,tokenHash,tokenPrefix,ownershipState,providerState,attachState,tlsState,createdBy,createdAt,updatedAt)
      VALUES ('dom_1','org_1','ws_1','app.owned-domain.com','_ysd-verification.app.owned-domain.com','hash_a','prefix','pending','no_owned_zone','detached','unavailable','user_1',1,1)`).run();
    assert.throws(() => database.prepare(`INSERT INTO exposure_domain
      (id,organizationId,workspaceId,hostname,dnsRecordName,tokenHash,tokenPrefix,ownershipState,providerState,attachState,tlsState,createdBy,createdAt,updatedAt)
      VALUES ('dom_2','org_2','ws_2','app.owned-domain.com','_ysd-verification.app.owned-domain.com','hash_b','prefix','pending','no_owned_zone','detached','unavailable','user_2',1,1)`).run(), /UNIQUE constraint failed/);
    assert.throws(() => database.prepare(`INSERT INTO exposure_domain
      (id,organizationId,workspaceId,hostname,dnsRecordName,tokenHash,tokenPrefix,ownershipState,providerState,attachState,tlsState,createdBy,createdAt,updatedAt)
      VALUES ('dom_3','org_2','ws_1','other.owned-domain.com','_ysd-verification.other.owned-domain.com','hash_c','prefix','pending','no_owned_zone','detached','unavailable','user_2',1,1)`).run(), /tenant mismatch/);
  } finally {
    database.close();
  }
});

void test('the migration stores no upstream URL, node IP, command, or tunnel credential field', () => {
  const sql = migration('0011_public_exposure.sql').toLowerCase();
  for (const forbidden of ['upstreamurl', 'originip', 'shellcommand', 'tunnelcredential', 'providerendpoint']) {
    assert.equal(sql.includes(forbidden), false, forbidden);
  }
  assert.match(sql, /public_exposure_tenant_guard/);
  assert.match(sql, /exposure_domain_tenant_guard/);
});

void test('migration 0011 preserves existing Phase 7 tenants and is safe to re-apply', () => {
  const database = new DatabaseSync(':memory:');
  try {
    database.exec('PRAGMA foreign_keys = ON');
    for (const name of ['0001_auth.sql', '0002_workspace.sql', '0004_security.sql', '0006_compute_nodes.sql', '0009_app_runtime.sql']) apply(database, name);
    database.exec(`
      INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt)
        VALUES ('legacy_owner','Legacy Owner','legacy@owned.test',1,NULL,1,1);
      INSERT INTO workspace (id,name,ownerUserId,zeroMode,autoScan,sleepIdleServers,previewDeployments,createdAt,updatedAt)
        VALUES ('legacy_ws','Legacy Workspace','legacy_owner',1,1,1,0,1,1);
      INSERT INTO project (id,workspaceId,name,framework,environment,region,status,visibility,createdAt,updatedAt)
        VALUES ('legacy_project','legacy_ws','Legacy App','Node.js','Production','Local','idle','private',1,1);
      INSERT INTO user_role (userId,role,updatedAt) VALUES ('legacy_owner','owner',1);
    `);
    apply(database, '0010_organizations.sql');
    const before = database.prepare(`SELECT w.id, w.organizationId, w.zeroMode, m.role
      FROM workspace w JOIN organization_member m
        ON m.organizationId = w.organizationId AND m.userId = w.ownerUserId
      WHERE w.id = 'legacy_ws'`).get() as Record<string, unknown>;
    apply(database, '0011_public_exposure.sql');
    apply(database, '0011_public_exposure.sql');
    const after = database.prepare(`SELECT w.id, w.organizationId, w.zeroMode, m.role
      FROM workspace w JOIN organization_member m
        ON m.organizationId = w.organizationId AND m.userId = w.ownerUserId
      WHERE w.id = 'legacy_ws'`).get() as Record<string, unknown>;
    assert.deepEqual(after, before);
    assert.equal((database.prepare('PRAGMA foreign_key_check').all()).length, 0);
    assert.equal((database.prepare('SELECT COUNT(*) AS total FROM public_exposure').get() as { total: number }).total, 0);
    assert.equal((database.prepare('SELECT COUNT(*) AS total FROM exposure_domain').get() as { total: number }).total, 0);
  } finally {
    database.close();
  }
});

void test('Phase 8 API handlers generate audit events and never accept an upstream target', () => {
  const exposureRoute = readFileSync(new URL('../app/api/exposures/route.ts', import.meta.url), 'utf8');
  const domainRoute = readFileSync(new URL('../app/api/domains/route.ts', import.meta.url), 'utf8');
  assert.match(exposureRoute, /recordAudit/);
  assert.match(exposureRoute, /exposure\.enable/);
  assert.match(exposureRoute, /exposure\.route\.change/);
  assert.match(domainRoute, /exposure\.domain\.inventory/);
  assert.doesNotMatch(exposureRoute, /parsed\.body\.(?:upstream|url|ip|endpoint)/i);
});

void test('Smart Deploy creates one private fail-closed exposure record atomically', () => {
  const source = readFileSync(new URL('../lib/server/deployments.ts', import.meta.url), 'utf8');
  assert.match(source, /INSERT INTO public_exposure/);
  assert.match(source, /'private', 'disabled', 'authenticated'/);
  assert.match(source, /'none', 'unavailable_zero_mode'/);
  assert.match(source, /preview\|\$\{workspaceTenant\.organizationId\}/);
  assert.match(source, /database\.batch\(\[/);
});
