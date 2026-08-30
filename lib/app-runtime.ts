/**
 * YSD App Runtime protocol and repository policy.
 *
 * The control plane and Node Agent share this module. Jobs describe an
 * allowlisted operation and structured identifiers; they never carry a shell
 * command, executable path, arbitrary argument list, URL, or filesystem path.
 */

export const APP_RUNTIME_JOB_TYPE = 'app-runtime.action' as const;

export const APP_RUNTIME_OPERATIONS = [
  'deploy',
  'start',
  'stop',
  'restart',
  'redeploy',
  'rollback',
  'delete',
  'status',
] as const;

export type AppRuntimeOperation = (typeof APP_RUNTIME_OPERATIONS)[number];
export type AppEnvironment = 'Production' | 'Preview' | 'Development';
export type AppPackageManager = 'npm' | 'pnpm' | 'yarn';
export type AppFramework =
  | 'Node.js'
  | 'Express'
  | 'Fastify'
  | 'Next.js'
  | 'Vite'
  | 'NestJS';

export const APP_RUNTIME_LIMITS = {
  minimumNodeMajor: 25,
  supportedNodeMajors: [25, 26] as readonly number[],
  portMinimum: 41_000,
  portMaximum: 41_999,
  memoryMinimumMb: 128,
  memoryMaximumMb: 2_048,
  diskMinimumBytes: 128 * 1024 ** 2,
  diskMaximumBytes: 2 * 1024 ** 3,
  diskReserveBytes: 512 * 1024 ** 2,
  memoryReserveBytes: 256 * 1024 ** 2,
  compressedSourceBytes: 32 * 1024 ** 2,
  extractedSourceBytes: 256 * 1024 ** 2,
  extractedFiles: 12_000,
  buildTimeoutMs: 10 * 60_000,
  actionTimeoutMs: 2 * 60_000,
  healthAttempts: 12,
  healthTimeoutMs: 3_000,
  healthBackoffMs: 1_000,
  maximumLogBytes: 128 * 1024,
  maximumResultLogLines: 80,
  maximumArtifactsPerProject: 5,
  maximumDeploymentsPerNode: 12,
  crashWindowMs: 5 * 60_000,
  maximumRestarts: 3,
} as const;

/** Defense-in-depth redaction shared by the Node Agent and control plane. */
export function redactAppRuntimeCredentials(value: string): string {
  return value
    .replace(
      /\b((?:[a-z0-9]+[_-])*(?:token|secret|password|passphrase|api[_-]?key|private[_-]?key|authorization))\s*[=:]\s*(?:"[^"]*"|'[^']*'|\S+)/gi,
      '$1=[REDACTED]',
    )
    .replace(/Bearer\s+[A-Za-z0-9._~-]+/gi, 'Bearer [REDACTED]');
}

export type AppRuntimeCapabilities = {
  available: boolean;
  nodeVersion: string;
  nodeMajor: number;
  permissionModel: boolean;
  networkGuard: boolean;
  packageManagers: AppPackageManager[];
  activeDeployments: number;
  maxDeployments: number;
};

export type SafeBuildContract = {
  version: 1;
  framework: AppFramework;
  packageManager: AppPackageManager;
  lockfile: 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock';
  nodeMajor: number;
  installPolicy: 'frozen-lockfile-ignore-scripts';
  buildPolicy: 'none';
  startPolicy: 'node-entry';
  entrypoint: string;
  envNames: string[];
};

export type RepositoryAnalysis = {
  framework: AppFramework;
  dependencies: string[];
  packageManager: AppPackageManager | null;
  lockfile: SafeBuildContract['lockfile'] | null;
  nodeMajor: number | null;
  entrypoint: string | null;
  envNames: string[];
  ignoredScripts: string[];
  blockedReasons: string[];
  contract: SafeBuildContract | null;
};

export type RepositoryAnalysisInput = {
  packageJson: string | null;
  files: string[];
  nvmrc?: string | null;
  envExample?: string | null;
  lockfileContent?: string | null;
};

export type AppRuntimeJobPayload = {
  operation: AppRuntimeOperation;
  deploymentId: string;
  projectId: string;
  actionId: string;
  artifactId: string | null;
  targetArtifactId: string | null;
  source: {
    owner: string;
    repository: string;
    commit: string;
  } | null;
  contract: SafeBuildContract | null;
  environment: AppEnvironment;
  environmentCiphertext: string | null;
  port: number;
  healthPath: string;
  memoryMb: number;
  diskQuotaBytes: number;
  retainArtifacts: number;
};

export type AppRuntimeSnapshot = {
  deploymentId: string;
  projectId: string;
  artifactId: string | null;
  state: 'running' | 'stopped' | 'crash_loop';
  port: number;
  bind: '127.0.0.1' | '0.0.0.0' | 'unknown';
  pid: number | null;
  uptimeSeconds: number;
  restartCount: number;
  crashLoop: boolean;
  memoryUsedBytes: number | null;
  observedAt: number;
};

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function onlyKeys(value: JsonRecord, allowed: readonly string[]): boolean {
  const set = new Set(allowed);
  return Object.keys(value).every((key) => set.has(key));
}

function integer(value: unknown, minimum: number, maximum: number): number | null {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
    ? value
    : null;
}

function cleanVersion(value: unknown): string {
  return typeof value === 'string' ? value.trim().slice(0, 128) : '';
}

function safeRelativeFile(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().replace(/\\/g, '/').replace(/^\.\//, '');
  if (
    normalized.length < 3 ||
    normalized.length > 240 ||
    normalized.startsWith('/') ||
    normalized.includes('//') ||
    normalized.split('/').some((part) => !part || part === '.' || part === '..') ||
    normalized.split('/').some((part) => part.startsWith('.')) ||
    normalized.startsWith('node_modules/') ||
    !/\.(?:cjs|mjs|js)$/.test(normalized)
  ) {
    return null;
  }
  return normalized;
}

function parseStartScript(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 260) return null;
  const match = /^node\s+(\.?\/?[A-Za-z0-9_./-]+\.(?:cjs|mjs|js))$/.exec(
    value.trim(),
  );
  return match ? safeRelativeFile(match[1]) : null;
}

function parseEnvNames(value: string | null | undefined): string[] {
  if (!value || value.length > 64 * 1024) return [];
  const names = new Set<string>();
  for (const line of value.split(/\r?\n/).slice(0, 500)) {
    const match = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=/.exec(line);
    if (match && !['HOST', 'PORT', 'NODE_ENV', 'PATH', 'NODE_OPTIONS'].includes(match[1]!)) {
      names.add(match[1]!);
    }
  }
  return [...names].sort().slice(0, 100);
}

function chooseNodeMajor(engines: string, nvmrc: string): number | null {
  const allowed = [...APP_RUNTIME_LIMITS.supportedNodeMajors].sort((a, b) => b - a);
  const nvmMajor = Number.parseInt(nvmrc.replace(/^v/i, '').split('.')[0] ?? '', 10);
  if (Number.isSafeInteger(nvmMajor)) {
    return allowed.includes(nvmMajor) ? nvmMajor : null;
  }
  if (!engines) return allowed[0] ?? null;
  if (engines.length > 128 || /[^0-9vVxX.*<>=~^|\s.-]/.test(engines)) return null;
  for (const major of allowed) {
    const minimum = /(?:^|\s)>=\s*v?(\d+)/.exec(engines);
    const maximum = /(?:^|\s)<\s*v?(\d+)/.exec(engines);
    if (minimum || maximum) {
      if (minimum && major < Number(minimum[1])) continue;
      if (maximum && major >= Number(maximum[1])) continue;
      return major;
    }
    const exact = engines.match(/\d+/g)?.map(Number) ?? [];
    if (exact.includes(major)) return major;
  }
  return null;
}

function frameworkFor(dependencies: Set<string>): AppFramework {
  if (dependencies.has('next') || dependencies.has('vinext')) return 'Next.js';
  if (dependencies.has('vite')) return 'Vite';
  if (dependencies.has('@nestjs/core')) return 'NestJS';
  if (dependencies.has('express')) return 'Express';
  if (dependencies.has('fastify')) return 'Fastify';
  return 'Node.js';
}

function packageManagerFor(files: Set<string>): {
  manager: AppPackageManager | null;
  lockfile: SafeBuildContract['lockfile'] | null;
  error: string | null;
} {
  const locks = [
    ['npm', 'package-lock.json'],
    ['pnpm', 'pnpm-lock.yaml'],
    ['yarn', 'yarn.lock'],
  ] as const;
  const found = locks.filter(([, lock]) => files.has(lock));
  if (found.length === 0) {
    return { manager: null, lockfile: null, error: 'A supported lockfile is required.' };
  }
  if (found.length > 1) {
    return { manager: null, lockfile: null, error: 'Exactly one package-manager lockfile is allowed.' };
  }
  return { manager: found[0]![0], lockfile: found[0]![1], error: null };
}

export function lockfilePolicyError(
  manager: AppPackageManager,
  content: string | null | undefined,
): string | null {
  if (!content || content.length > 8 * 1024 * 1024) {
    return 'The lockfile is missing or too large to inspect safely.';
  }
  if (manager === 'npm') {
    try {
      const parsed = JSON.parse(content) as { lockfileVersion?: unknown };
      if (typeof parsed.lockfileVersion !== 'number' || parsed.lockfileVersion < 2) {
        return 'npm requires package-lock lockfileVersion 2 or newer.';
      }
      const pending: unknown[] = [parsed];
      let inspected = 0;
      while (pending.length > 0) {
        const value = pending.pop();
        if (!isRecord(value)) continue;
        inspected += 1;
        if (inspected > 100_000) return 'The npm lockfile structure is too large to inspect safely.';
        for (const [key, nested] of Object.entries(value)) {
          if (key === 'resolved' && typeof nested === 'string' &&
              !/^https:\/\/registry\.npmjs\.org\/[A-Za-z0-9@%_./+~-]+(?:\.tgz)?$/i.test(nested)) {
            return 'The lockfile references a non-registry, local, Git, or unapproved network source.';
          }
          if (key === 'version' && typeof nested === 'string' &&
              /^(?:git\+|git:|ssh:|file:|link:|workspace:|https?:)/i.test(nested)) {
            return 'The lockfile references a non-registry, local, Git, or unapproved network source.';
          }
          if (isRecord(nested)) pending.push(nested);
        }
      }
    } catch {
      return 'package-lock.json is not valid JSON.';
    }
  } else if (/\b(?:git\+|git:|ssh:|file:|link:|workspace:|https?:\/\/(?!registry\.npmjs\.org\/))/i.test(content)) {
    return 'The lockfile references a non-registry, local, Git, or unapproved network source.';
  }
  return null;
}

const LIFECYCLE_HOOKS = [
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepublish',
  'prepublishOnly',
  'prepack',
  'postpack',
] as const;

const FORBIDDEN_REPOSITORY_CONFIG = [
  '.npmrc',
  '.yarnrc',
  '.yarnrc.yml',
  '.pnpmfile.cjs',
  'pnpm-workspace.yaml',
] as const;

/** Builds a fixed Node.js contract or a deterministic list of refusal reasons. */
export function analyzeNodeRepository(input: RepositoryAnalysisInput): RepositoryAnalysis {
  const files = new Set(
    input.files
      .map((file) => file.replace(/\\/g, '/').replace(/^\.\//, ''))
      .filter((file) => file.length <= 240),
  );
  const blockedReasons: string[] = [];
  let manifest: JsonRecord = {};
  if (!input.packageJson || input.packageJson.length > 256 * 1024) {
    blockedReasons.push('A bounded package.json is required.');
  } else {
    try {
      const parsed: unknown = JSON.parse(input.packageJson);
      if (!isRecord(parsed)) throw new Error('not an object');
      manifest = parsed;
    } catch {
      blockedReasons.push('package.json is invalid.');
    }
  }

  const dependenciesRecord = isRecord(manifest.dependencies) ? manifest.dependencies : {};
  const developmentRecord = isRecord(manifest.devDependencies) ? manifest.devDependencies : {};
  const dependencies = [...new Set([...Object.keys(dependenciesRecord), ...Object.keys(developmentRecord)])].sort();
  const framework = frameworkFor(new Set(dependencies));
  const packageManager = packageManagerFor(files);
  if (packageManager.error) blockedReasons.push(packageManager.error);

  const forbiddenConfig = FORBIDDEN_REPOSITORY_CONFIG.filter((name) =>
    [...files].some((file) => file === name || file.endsWith(`/${name}`)),
  );
  if (forbiddenConfig.length > 0) {
    blockedReasons.push(`Repository package-manager configuration is forbidden: ${forbiddenConfig.join(', ')}.`);
  }

  const scripts = isRecord(manifest.scripts) ? manifest.scripts : {};
  const hooks = LIFECYCLE_HOOKS.filter((name) => typeof scripts[name] === 'string');
  if (hooks.length > 0) {
    blockedReasons.push(`Package lifecycle hooks are not allowed: ${hooks.join(', ')}.`);
  }
  if (typeof scripts.build === 'string' && scripts.build.trim()) {
    blockedReasons.push('User-defined build scripts are not executed in the Node.js v1 contract.');
  }
  if (manifest.workspaces !== undefined) {
    blockedReasons.push('Package-manager workspaces are not enabled in the Node.js v1 contract.');
  }
  const unsafeDependency = [...Object.entries(dependenciesRecord), ...Object.entries(developmentRecord)]
    .find(([, version]) => typeof version !== 'string' || /^(?:git\+|git:|ssh:|file:|link:|workspace:|https?:)/i.test(version));
  if (unsafeDependency) {
    blockedReasons.push(`Dependency ${unsafeDependency[0]} does not use an approved registry version.`);
  }

  const ignoredScripts = Object.keys(scripts)
    .filter((name) => name !== 'start' && name !== 'build' && !(LIFECYCLE_HOOKS as readonly string[]).includes(name))
    .sort();
  const engines = isRecord(manifest.engines) ? cleanVersion(manifest.engines.node) : '';
  const nodeMajor = chooseNodeMajor(engines, cleanVersion(input.nvmrc));
  if (nodeMajor === null) {
    blockedReasons.push(`Node.js must resolve to the ${APP_RUNTIME_LIMITS.supportedNodeMajors.join(' or ')} allowlist.`);
  }

  let entrypoint = parseStartScript(scripts.start);
  if (!entrypoint) entrypoint = safeRelativeFile(manifest.main);
  if (!entrypoint) {
    blockedReasons.push('Use a start script in the exact form "node relative/file.js" or a safe package.json main field.');
  } else if (!files.has(entrypoint)) {
    blockedReasons.push(`The declared entrypoint ${entrypoint} is not present in the repository tree.`);
  }

  if (framework === 'Next.js' || framework === 'Vite' || framework === 'NestJS') {
    blockedReasons.push(`${framework} was detected, but its build/runtime contract is not enabled in Node.js v1.`);
  }
  if (packageManager.manager && packageManager.lockfile) {
    const lockError = lockfilePolicyError(packageManager.manager, input.lockfileContent);
    if (lockError) blockedReasons.push(lockError);
  }

  const envNames = parseEnvNames(input.envExample);
  const uniqueReasons = [...new Set(blockedReasons)];
  const contract =
    uniqueReasons.length === 0 && packageManager.manager && packageManager.lockfile && nodeMajor && entrypoint
      ? {
          version: 1 as const,
          framework,
          packageManager: packageManager.manager,
          lockfile: packageManager.lockfile,
          nodeMajor,
          installPolicy: 'frozen-lockfile-ignore-scripts' as const,
          buildPolicy: 'none' as const,
          startPolicy: 'node-entry' as const,
          entrypoint,
          envNames,
        }
      : null;
  return {
    framework,
    dependencies,
    packageManager: packageManager.manager,
    lockfile: packageManager.lockfile,
    nodeMajor,
    entrypoint,
    envNames,
    ignoredScripts,
    blockedReasons: uniqueReasons,
    contract,
  };
}

function validIdentifier(value: unknown, prefix: string): value is string {
  return typeof value === 'string' && new RegExp(`^${prefix}_[a-f0-9]{24}$`).test(value);
}

function validEnvironment(value: unknown): value is AppEnvironment {
  return value === 'Production' || value === 'Preview' || value === 'Development';
}

function validContract(value: unknown): value is SafeBuildContract {
  if (!isRecord(value) || !onlyKeys(value, [
    'version', 'framework', 'packageManager', 'lockfile', 'nodeMajor',
    'installPolicy', 'buildPolicy', 'startPolicy', 'entrypoint', 'envNames',
  ])) return false;
  const entrypoint = safeRelativeFile(value.entrypoint);
  const envNames = Array.isArray(value.envNames) ? value.envNames : null;
  const managerLockMatches =
    (value.packageManager === 'npm' && value.lockfile === 'package-lock.json') ||
    (value.packageManager === 'pnpm' && value.lockfile === 'pnpm-lock.yaml') ||
    (value.packageManager === 'yarn' && value.lockfile === 'yarn.lock');
  return value.version === 1 &&
    ['Node.js', 'Express', 'Fastify'].includes(String(value.framework)) &&
    ['npm', 'pnpm', 'yarn'].includes(String(value.packageManager)) &&
    ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'].includes(String(value.lockfile)) &&
    APP_RUNTIME_LIMITS.supportedNodeMajors.includes(Number(value.nodeMajor)) &&
    managerLockMatches && value.installPolicy === 'frozen-lockfile-ignore-scripts' &&
    value.buildPolicy === 'none' && value.startPolicy === 'node-entry' &&
    entrypoint === value.entrypoint && envNames !== null && envNames.length <= 100 &&
    envNames.every((name) => typeof name === 'string' && /^[A-Z][A-Z0-9_]{1,63}$/.test(name)) &&
    new Set(envNames).size === envNames.length;
}

/** Strict validator for the sole App Runtime queue payload. */
export function validateAppRuntimeJobPayload(value: unknown):
  | { ok: true; payload: AppRuntimeJobPayload }
  | { ok: false; error: string } {
  if (!isRecord(value) || !onlyKeys(value, [
    'operation', 'deploymentId', 'projectId', 'actionId', 'artifactId',
    'targetArtifactId', 'source', 'contract', 'environment',
    'environmentCiphertext', 'port', 'healthPath', 'memoryMb',
    'diskQuotaBytes', 'retainArtifacts',
  ])) return { ok: false, error: 'The App Runtime payload shape is invalid.' };
  if (!(APP_RUNTIME_OPERATIONS as readonly unknown[]).includes(value.operation)) {
    return { ok: false, error: 'The App Runtime operation is not allowlisted.' };
  }
  if (!validIdentifier(value.deploymentId, 'dpl') ||
      !validIdentifier(value.projectId, 'prj') ||
      !validIdentifier(value.actionId, 'dact')) {
    return { ok: false, error: 'App Runtime identifiers are invalid.' };
  }
  const artifactId = value.artifactId === null ? null : validIdentifier(value.artifactId, 'art') ? value.artifactId : undefined;
  const targetArtifactId = value.targetArtifactId === null ? null : validIdentifier(value.targetArtifactId, 'art') ? value.targetArtifactId : undefined;
  if (artifactId === undefined || targetArtifactId === undefined || !validEnvironment(value.environment)) {
    return { ok: false, error: 'Artifact or environment scope is invalid.' };
  }
  const port = integer(value.port, APP_RUNTIME_LIMITS.portMinimum, APP_RUNTIME_LIMITS.portMaximum);
  const memoryMb = integer(value.memoryMb, APP_RUNTIME_LIMITS.memoryMinimumMb, APP_RUNTIME_LIMITS.memoryMaximumMb);
  const diskQuotaBytes = integer(value.diskQuotaBytes, APP_RUNTIME_LIMITS.diskMinimumBytes, APP_RUNTIME_LIMITS.diskMaximumBytes);
  const retainArtifacts = integer(value.retainArtifacts, 1, APP_RUNTIME_LIMITS.maximumArtifactsPerProject);
  if (!port || !memoryMb || !diskQuotaBytes || !retainArtifacts ||
      typeof value.healthPath !== 'string' || !/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,127}$/.test(value.healthPath)) {
    return { ok: false, error: 'Port, resource, retention, or health policy is invalid.' };
  }
  if (value.environmentCiphertext !== null &&
      (typeof value.environmentCiphertext !== 'string' || value.environmentCiphertext.length > 64 * 1024 || !value.environmentCiphertext.startsWith('v1.'))) {
    return { ok: false, error: 'The encrypted environment envelope is invalid.' };
  }
  let source: AppRuntimeJobPayload['source'] = null;
  if (value.source !== null) {
    if (!isRecord(value.source) || !onlyKeys(value.source, ['owner', 'repository', 'commit']) ||
        typeof value.source.owner !== 'string' || !/^[A-Za-z0-9_.-]{1,100}$/.test(value.source.owner) ||
        value.source.owner === '.' || value.source.owner === '..' ||
        typeof value.source.repository !== 'string' || !/^[A-Za-z0-9_.-]{1,100}$/.test(value.source.repository) ||
        value.source.repository === '.' || value.source.repository === '..' ||
        typeof value.source.commit !== 'string' || !/^[a-f0-9]{40}$/.test(value.source.commit)) {
      return { ok: false, error: 'Only a pinned github.com source is allowed.' };
    }
    source = { owner: value.source.owner, repository: value.source.repository, commit: value.source.commit };
  }
  const operation = value.operation as AppRuntimeOperation;
  const contract = value.contract === null ? null : validContract(value.contract) ? value.contract : undefined;
  if (contract === undefined) return { ok: false, error: 'The safe build contract is invalid.' };
  if ((operation === 'deploy' || operation === 'redeploy') && (!source || !contract || !artifactId)) {
    return { ok: false, error: 'Deploy operations require a pinned source, contract, and artifact.' };
  }
  if (operation === 'rollback' && !targetArtifactId) {
    return { ok: false, error: 'Rollback requires a verified target artifact.' };
  }
  if (operation !== 'rollback' && targetArtifactId !== null) {
    return { ok: false, error: 'Only rollback can select a target artifact.' };
  }
  if (['start', 'restart'].includes(operation) && (!artifactId || !contract)) {
    return { ok: false, error: 'Start and restart require a verified artifact contract.' };
  }
  if (operation === 'rollback' && !contract) {
    return { ok: false, error: 'Rollback requires the signed deployment contract.' };
  }
  if (!['deploy', 'redeploy'].includes(operation) && source !== null) {
    return { ok: false, error: 'Only deploy operations can acquire source.' };
  }
  return {
    ok: true,
    payload: {
      operation,
      deploymentId: value.deploymentId,
      projectId: value.projectId,
      actionId: value.actionId,
      artifactId,
      targetArtifactId,
      source,
      contract,
      environment: value.environment,
      environmentCiphertext: value.environmentCiphertext,
      port,
      healthPath: value.healthPath,
      memoryMb,
      diskQuotaBytes,
      retainArtifacts,
    },
  };
}

export function parseAppRuntimeCapabilities(value: unknown): AppRuntimeCapabilities | null {
  if (!isRecord(value)) return null;
  const nodeMajor = integer(value.nodeMajor, 1, 100);
  const activeDeployments = integer(value.activeDeployments, 0, APP_RUNTIME_LIMITS.maximumDeploymentsPerNode);
  const maxDeployments = integer(value.maxDeployments, 1, APP_RUNTIME_LIMITS.maximumDeploymentsPerNode);
  const managers = Array.isArray(value.packageManagers) ? value.packageManagers : null;
  if (typeof value.available !== 'boolean' || typeof value.nodeVersion !== 'string' || !nodeMajor ||
      typeof value.permissionModel !== 'boolean' || typeof value.networkGuard !== 'boolean' ||
      activeDeployments === null || maxDeployments === null || !managers ||
      !managers.every((item) => item === 'npm' || item === 'pnpm' || item === 'yarn')) return null;
  return {
    available: value.available && APP_RUNTIME_LIMITS.supportedNodeMajors.includes(nodeMajor) && value.permissionModel && value.networkGuard,
    nodeVersion: value.nodeVersion.slice(0, 32),
    nodeMajor,
    permissionModel: value.permissionModel,
    networkGuard: value.networkGuard,
    packageManagers: [...new Set(managers)] as AppPackageManager[],
    activeDeployments,
    maxDeployments,
  };
}

export function parseAppRuntimeSnapshots(value: unknown): AppRuntimeSnapshot[] | null {
  if (!Array.isArray(value) || value.length > APP_RUNTIME_LIMITS.maximumDeploymentsPerNode) return null;
  const snapshots: AppRuntimeSnapshot[] = [];
  for (const item of value) {
    if (!isRecord(item) || !validIdentifier(item.deploymentId, 'dpl') ||
        !validIdentifier(item.projectId, 'prj') ||
        !(item.artifactId === null || validIdentifier(item.artifactId, 'art')) ||
        !['running', 'stopped', 'crash_loop'].includes(String(item.state)) ||
        integer(item.port, APP_RUNTIME_LIMITS.portMinimum, APP_RUNTIME_LIMITS.portMaximum) === null ||
        !['127.0.0.1', '0.0.0.0', 'unknown'].includes(String(item.bind)) ||
        !(item.pid === null || integer(item.pid, 1, 2 ** 31 - 1) !== null) ||
        integer(item.uptimeSeconds, 0, Number.MAX_SAFE_INTEGER) === null ||
        integer(item.restartCount, 0, 1000) === null || typeof item.crashLoop !== 'boolean' ||
        !(item.memoryUsedBytes === null || integer(item.memoryUsedBytes, 0, Number.MAX_SAFE_INTEGER) !== null) ||
        integer(item.observedAt, 0, Number.MAX_SAFE_INTEGER) === null) return null;
    snapshots.push({
      deploymentId: item.deploymentId,
      projectId: item.projectId,
      artifactId: item.artifactId as string | null,
      state: item.state as AppRuntimeSnapshot['state'],
      port: item.port as number,
      bind: item.bind as AppRuntimeSnapshot['bind'],
      pid: item.pid as number | null,
      uptimeSeconds: item.uptimeSeconds as number,
      restartCount: item.restartCount as number,
      crashLoop: item.crashLoop,
      memoryUsedBytes: item.memoryUsedBytes as number | null,
      observedAt: item.observedAt as number,
    });
  }
  return snapshots;
}

export function appRuntimeLeaseDuration(operation: AppRuntimeOperation): number {
  return operation === 'deploy' || operation === 'redeploy' || operation === 'rollback'
    ? APP_RUNTIME_LIMITS.buildTimeoutMs + 2 * 60_000
    : APP_RUNTIME_LIMITS.actionTimeoutMs;
}

export function appCrashRecoveryDecision(recentRestarts: number): {
  restart: boolean;
  delayMs: number | null;
} {
  if (!Number.isSafeInteger(recentRestarts) || recentRestarts < 0 ||
      recentRestarts >= APP_RUNTIME_LIMITS.maximumRestarts) {
    return { restart: false, delayMs: null };
  }
  return {
    restart: true,
    delayMs: Math.min(10_000, 1_000 * 2 ** recentRestarts),
  };
}
