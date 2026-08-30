/**
 * Phase 5 Game Server contracts shared by the Worker and the local Node Agent.
 *
 * Cloudflare stores only workspace-scoped control-plane metadata. Every
 * executable contract below resolves to a fixed local handler; none accepts a
 * shell command, executable path, JVM argument, download URL, script, or paid
 * provider.
 */

export const GAME_SERVER_JOB_TYPES = [
  'game-server.lifecycle',
  'game-server.config',
  'game-server.player',
  'game-server.backup',
  'game-server.logs',
] as const;

export type GameServerJobType = (typeof GAME_SERVER_JOB_TYPES)[number];

export const MINECRAFT_MANIFEST_URL =
  'https://launchermeta.mojang.com/mc/game/version_manifest_v2.json';

/** Reviewed release ids. The agent resolves bytes only through Mojang metadata. */
export const MINECRAFT_VERSIONS = [
  { id: '26.2', label: '26.2', current: true },
  { id: '26.1.2', label: '26.1.2', current: false },
  { id: '1.21.11', label: '1.21.11', current: false },
] as const;

export const GAME_SERVER_LIMITS = {
  minimumRamMb: 1024,
  maximumRamMb: 32 * 1024,
  minimumCpuCores: 1,
  maximumCpuCores: 32,
  minimumDiskBytes: 2 * 1024 ** 3,
  maximumDiskBytes: 64 * 1024 ** 3,
  memoryReserveBytes: 768 * 1024 ** 2,
  diskReserveBytes: 1024 ** 3,
  maximumServersPerWorkspace: 25,
  maximumServersPerNode: 8,
  maximumBackupsPerServer: 10,
  maximumLogLines: 200,
  suspiciousActionsPerHour: 50,
  createLeaseMs: 20 * 60_000,
  backupLeaseMs: 10 * 60_000,
  lifecycleLeaseMs: 3 * 60_000,
  shortLeaseMs: 60_000,
} as const;

export const GAME_SERVER_STATUSES = [
  'provisioning',
  'stopped',
  'starting',
  'running',
  'stopping',
  'restarting',
  'crashed',
  'crash_loop',
  'error',
  'node_offline',
  'node_revoked',
  'deleted',
] as const;

export type GameServerStatus = (typeof GAME_SERVER_STATUSES)[number];

export function gameServerResourceEligible(input: {
  freeMemoryBytes: number;
  freeDiskBytes: number;
  ramMb: number;
  diskQuotaBytes: number;
  activeServers: number;
  maximumServers: number;
}): boolean {
  return (
    Number.isSafeInteger(input.ramMb) &&
    Number.isSafeInteger(input.diskQuotaBytes) &&
    input.ramMb >= GAME_SERVER_LIMITS.minimumRamMb &&
    input.ramMb <= GAME_SERVER_LIMITS.maximumRamMb &&
    input.diskQuotaBytes >= GAME_SERVER_LIMITS.minimumDiskBytes &&
    input.diskQuotaBytes <= GAME_SERVER_LIMITS.maximumDiskBytes &&
    input.activeServers >= 0 &&
    input.activeServers < input.maximumServers &&
    input.freeMemoryBytes >=
      input.ramMb * 1024 ** 2 + GAME_SERVER_LIMITS.memoryReserveBytes &&
    input.freeDiskBytes >=
      input.diskQuotaBytes + GAME_SERVER_LIMITS.diskReserveBytes
  );
}

export function crashRecoveryDecision(recentCrashes: number): {
  restart: boolean;
  delayMs: number | null;
} {
  if (!Number.isSafeInteger(recentCrashes) || recentCrashes < 1) {
    return { restart: false, delayMs: null };
  }
  if (recentCrashes >= 3) return { restart: false, delayMs: null };
  return {
    restart: true,
    delayMs: recentCrashes === 1 ? 5_000 : 15_000,
  };
}

export type GameServerCapabilities = {
  minecraftJavaAvailable: boolean;
  javaVersion: string | null;
  activeServers: number;
  maxConcurrentServers: number;
};

export type MinecraftProperties = {
  maxPlayers: number;
  difficulty: 'peaceful' | 'easy' | 'normal' | 'hard';
  gamemode: 'survival' | 'creative' | 'adventure' | 'spectator';
  onlineMode: boolean;
  whitelist: boolean;
  enforceWhitelist: boolean;
  motd: string;
  viewDistance: number;
  simulationDistance: number;
  pvp: boolean;
  hardcore: boolean;
  allowFlight: boolean;
  spawnProtection: number;
};

export const DEFAULT_MINECRAFT_PROPERTIES: MinecraftProperties = {
  maxPlayers: 20,
  difficulty: 'normal',
  gamemode: 'survival',
  onlineMode: true,
  whitelist: true,
  enforceWhitelist: true,
  motd: 'A YSD Zero Cloud Minecraft server',
  viewDistance: 10,
  simulationDistance: 10,
  pvp: true,
  hardcore: false,
  allowFlight: false,
  spawnProtection: 16,
};

export type GameServerSnapshot = {
  serverId: string;
  status: GameServerStatus;
  players: string[];
  playerCount: number;
  cpuLoadPercent: number | null;
  memoryUsedBytes: number | null;
  uptimeSeconds: number;
  exposure: 'private' | 'unexpected';
  binaryHash: string | null;
  binaryVerified: boolean;
  crashCount: number;
  crashLoop: boolean;
  logTail: string[];
  observedAt: number;
};

export type GameServerPayloadValidation =
  | { ok: true; payload: Record<string, unknown> }
  | { ok: false; code: string; error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
): boolean {
  const expected = new Set(required);
  return (
    Object.keys(value).length === expected.size &&
    Object.keys(value).every((key) => expected.has(key))
  );
}

function integer(value: unknown, minimum: number, maximum: number): number | null {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
    ? value
    : null;
}

function safeText(value: unknown, maximum: number): string | null {
  if (typeof value !== 'string') return null;
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 32 || code === 127) return null;
  }
  const clean = value.trim().replace(/\s+/g, ' ');
  return clean.length > 0 && clean.length <= maximum ? clean : null;
}

export function validGameServerId(value: unknown): value is string {
  return typeof value === 'string' && /^gsv_[a-f0-9]{24}$/.test(value);
}

export function validBackupId(value: unknown): value is string {
  return typeof value === 'string' && /^gbk_[a-f0-9]{24}$/.test(value);
}

export function minecraftVersionAllowed(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    MINECRAFT_VERSIONS.some((version) => version.id === value)
  );
}

export function parseGameServerCapabilities(
  value: unknown,
): GameServerCapabilities | null {
  if (!isRecord(value)) return null;
  if (typeof value.minecraftJavaAvailable !== 'boolean') return null;
  const javaVersion =
    value.javaVersion === null
      ? null
      : safeText(value.javaVersion, 80);
  const activeServers = integer(
    value.activeServers,
    0,
    GAME_SERVER_LIMITS.maximumServersPerNode,
  );
  const maxConcurrentServers = integer(
    value.maxConcurrentServers,
    1,
    GAME_SERVER_LIMITS.maximumServersPerNode,
  );
  if (
    javaVersion === null &&
    value.javaVersion !== null ||
    activeServers === null ||
    maxConcurrentServers === null ||
    activeServers > maxConcurrentServers
  ) {
    return null;
  }
  return {
    minecraftJavaAvailable: value.minecraftJavaAvailable,
    javaVersion,
    activeServers,
    maxConcurrentServers,
  };
}

export function validateMinecraftProperties(
  value: unknown,
): { ok: true; properties: MinecraftProperties } | { ok: false; error: string } {
  if (!isRecord(value)) {
    return { ok: false, error: 'Minecraft properties must be an object.' };
  }
  const keys = Object.keys(DEFAULT_MINECRAFT_PROPERTIES);
  if (!exactKeys(value, keys)) {
    return {
      ok: false,
      error: 'Only the reviewed Minecraft property keys are accepted.',
    };
  }
  const maxPlayers = integer(value.maxPlayers, 1, 500);
  const viewDistance = integer(value.viewDistance, 2, 32);
  const simulationDistance = integer(value.simulationDistance, 2, 32);
  const spawnProtection = integer(value.spawnProtection, 0, 100);
  const motd = safeText(value.motd, 100);
  const difficulties = ['peaceful', 'easy', 'normal', 'hard'] as const;
  const gamemodes = ['survival', 'creative', 'adventure', 'spectator'] as const;
  if (
    maxPlayers === null ||
    viewDistance === null ||
    simulationDistance === null ||
    spawnProtection === null ||
    !motd ||
    !difficulties.includes(value.difficulty as (typeof difficulties)[number]) ||
    !gamemodes.includes(value.gamemode as (typeof gamemodes)[number]) ||
    typeof value.onlineMode !== 'boolean' ||
    typeof value.whitelist !== 'boolean' ||
    typeof value.enforceWhitelist !== 'boolean' ||
    typeof value.pvp !== 'boolean' ||
    typeof value.hardcore !== 'boolean' ||
    typeof value.allowFlight !== 'boolean'
  ) {
    return { ok: false, error: 'One or more Minecraft properties are invalid.' };
  }
  return {
    ok: true,
    properties: {
      maxPlayers,
      difficulty: value.difficulty as MinecraftProperties['difficulty'],
      gamemode: value.gamemode as MinecraftProperties['gamemode'],
      onlineMode: value.onlineMode,
      whitelist: value.whitelist,
      enforceWhitelist: value.enforceWhitelist,
      motd,
      viewDistance,
      simulationDistance,
      pvp: value.pvp,
      hardcore: value.hardcore,
      allowFlight: value.allowFlight,
      spawnProtection,
    },
  };
}

function failure(code: string, error: string): GameServerPayloadValidation {
  return { ok: false, code, error };
}

function lifecyclePayload(value: Record<string, unknown>): GameServerPayloadValidation {
  const operation = value.operation;
  if (operation === 'create') {
    const required = [
      'operation', 'serverId', 'name', 'game', 'serverType', 'version',
      'ramMb', 'cpuCores', 'diskQuotaBytes', 'port', 'properties',
      'eulaAccepted', 'provider', 'zeroMode', 'exposure',
    ];
    if (!exactKeys(value, required)) {
      return failure('fields', 'Create accepts only the fixed Vanilla contract.');
    }
    const name = safeText(value.name, 64);
    const ramMb = integer(
      value.ramMb,
      GAME_SERVER_LIMITS.minimumRamMb,
      GAME_SERVER_LIMITS.maximumRamMb,
    );
    const cpuCores = integer(
      value.cpuCores,
      GAME_SERVER_LIMITS.minimumCpuCores,
      GAME_SERVER_LIMITS.maximumCpuCores,
    );
    const diskQuotaBytes = integer(
      value.diskQuotaBytes,
      GAME_SERVER_LIMITS.minimumDiskBytes,
      GAME_SERVER_LIMITS.maximumDiskBytes,
    );
    const port = integer(value.port, 1024, 65_535);
    const properties = validateMinecraftProperties(value.properties);
    if (
      !validGameServerId(value.serverId) ||
      !name ||
      value.game !== 'minecraft-java' ||
      value.serverType !== 'vanilla' ||
      !minecraftVersionAllowed(value.version) ||
      ramMb === null ||
      cpuCores === null ||
      diskQuotaBytes === null ||
      port === null ||
      !properties.ok ||
      value.eulaAccepted !== true ||
      value.provider !== 'local-node' ||
      value.zeroMode !== true ||
      value.exposure !== 'private'
    ) {
      return failure(
        'create',
        'Create requires an approved Vanilla release, EULA acceptance, private exposure, and local-node Zero Mode.',
      );
    }
    return {
      ok: true,
      payload: {
        operation,
        serverId: value.serverId,
        name,
        game: 'minecraft-java',
        serverType: 'vanilla',
        version: value.version,
        ramMb,
        cpuCores,
        diskQuotaBytes,
        port,
        properties: properties.properties,
        eulaAccepted: true,
        provider: 'local-node',
        zeroMode: true,
        exposure: 'private',
      },
    };
  }
  if (['start', 'stop', 'restart', 'status'].includes(String(operation))) {
    if (!exactKeys(value, ['operation', 'serverId']) || !validGameServerId(value.serverId)) {
      return failure('lifecycle', 'Lifecycle payload is invalid.');
    }
    return { ok: true, payload: { operation, serverId: value.serverId } };
  }
  if (operation === 'delete') {
    if (
      !exactKeys(value, ['operation', 'serverId', 'confirmDelete']) ||
      !validGameServerId(value.serverId) ||
      value.confirmDelete !== true
    ) {
      return failure('delete', 'Delete requires explicit confirmation.');
    }
    return { ok: true, payload: { operation, serverId: value.serverId, confirmDelete: true } };
  }
  return failure('operation', 'Choose a supported lifecycle operation.');
}

function configPayload(value: Record<string, unknown>): GameServerPayloadValidation {
  const port = integer(value.port, 1024, 65_535);
  if (
    !exactKeys(value, ['operation', 'serverId', 'port', 'properties']) ||
    value.operation !== 'update' ||
    !validGameServerId(value.serverId) ||
    port === null
  ) {
    return failure('config', 'Configuration payload is invalid.');
  }
  const properties = validateMinecraftProperties(value.properties);
  return properties.ok
    ? { ok: true, payload: { operation: 'update', serverId: value.serverId, port, properties: properties.properties } }
    : failure('properties', properties.error);
}

function playerPayload(value: Record<string, unknown>): GameServerPayloadValidation {
  const operation = value.operation;
  if (operation === 'list') {
    return exactKeys(value, ['operation', 'serverId']) && validGameServerId(value.serverId)
      ? { ok: true, payload: { operation, serverId: value.serverId } }
      : failure('player', 'Player list payload is invalid.');
  }
  if (!['kick', 'whitelist-add', 'whitelist-remove', 'op', 'deop'].includes(String(operation))) {
    return failure('player', 'Choose a supported player operation.');
  }
  if (!exactKeys(value, ['operation', 'serverId', 'player']) || !validGameServerId(value.serverId)) {
    return failure('player', 'Player action payload is invalid.');
  }
  const player = typeof value.player === 'string' && /^[A-Za-z0-9_]{1,16}$/.test(value.player)
    ? value.player
    : null;
  return player
    ? { ok: true, payload: { operation, serverId: value.serverId, player } }
    : failure('player', 'Minecraft player names use 1-16 letters, digits, or underscores.');
}

function backupPayload(value: Record<string, unknown>): GameServerPayloadValidation {
  const operation = value.operation;
  if (operation === 'list') {
    return exactKeys(value, ['operation', 'serverId']) && validGameServerId(value.serverId)
      ? { ok: true, payload: { operation, serverId: value.serverId } }
      : failure('backup', 'Backup list payload is invalid.');
  }
  if (operation === 'create') {
    const name = safeText(value.name, 64);
    if (
      !exactKeys(value, ['operation', 'serverId', 'backupId', 'name']) ||
      !validGameServerId(value.serverId) ||
      !validBackupId(value.backupId) ||
      !name
    ) {
      return failure('backup', 'Backup create payload is invalid.');
    }
    return { ok: true, payload: { operation, serverId: value.serverId, backupId: value.backupId, name } };
  }
  if (operation === 'restore' || operation === 'delete') {
    const confirmation = operation === 'restore' ? 'confirmRestore' : 'confirmDelete';
    if (
      !exactKeys(value, ['operation', 'serverId', 'backupId', confirmation]) ||
      !validGameServerId(value.serverId) ||
      !validBackupId(value.backupId) ||
      value[confirmation] !== true
    ) {
      return failure('backup', `Backup ${operation} requires explicit confirmation.`);
    }
    return { ok: true, payload: { operation, serverId: value.serverId, backupId: value.backupId, [confirmation]: true } };
  }
  return failure('backup', 'Choose a supported backup operation.');
}

export function validateGameServerJobPayload(
  type: string,
  value: unknown,
): GameServerPayloadValidation {
  if (!isRecord(value)) return failure('payload', 'Game Server payload must be an object.');
  if (containsGameServerAbuse(value)) {
    return failure('boundary', 'Executable paths, URLs, commands, JVM arguments, scripts, tunnels, and paid providers are forbidden.');
  }
  if (type === 'game-server.lifecycle') return lifecyclePayload(value);
  if (type === 'game-server.config') return configPayload(value);
  if (type === 'game-server.player') return playerPayload(value);
  if (type === 'game-server.backup') return backupPayload(value);
  if (type === 'game-server.logs') {
    const lines = integer(value.lines, 1, GAME_SERVER_LIMITS.maximumLogLines);
    return exactKeys(value, ['operation', 'serverId', 'lines']) &&
      value.operation === 'tail' &&
      validGameServerId(value.serverId) &&
      lines !== null
      ? { ok: true, payload: { operation: 'tail', serverId: value.serverId, lines } }
      : failure('logs', 'Log tail payload is invalid.');
  }
  return failure('type', 'The Game Server job type is not allowlisted.');
}

export function containsGameServerAbuse(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const forbiddenKeys = /^(?:shell|command|console|script|eval|executable|executablePath|path|workingDirectory|jvmArgs|args|url|downloadUrl|providerUrl|tunnel|upnp|rconPassword)$/i;
  if (Object.keys(value).some((key) => forbiddenKeys.test(key))) return true;
  const serialized = JSON.stringify(value);
  return /(?:workers-ai|paid-provider|spectrum|cloudflare[- ]?tunnel|argo|ngrok|playit\.gg|tailscale funnel|\bupnp\b|file:\/\/|\.\.\/|\.\.\\)/i.test(serialized);
}

export function gameServerLeaseDuration(
  type: string,
  payload: Record<string, unknown>,
): number {
  if (type === 'game-server.lifecycle' && payload.operation === 'create') {
    return GAME_SERVER_LIMITS.createLeaseMs;
  }
  if (type === 'game-server.backup') return GAME_SERVER_LIMITS.backupLeaseMs;
  if (type === 'game-server.lifecycle') return GAME_SERVER_LIMITS.lifecycleLeaseMs;
  return GAME_SERVER_LIMITS.shortLeaseMs;
}

export function redactGameLogLine(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  let printable = '';
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    printable += code < 32 || code === 127 ? ' ' : character;
  }
  let line = printable.trim().slice(0, 500);
  if (!line) return null;
  line = line
    .replace(/(authorization|bearer|token|secret|password|rcon(?:\.password)?)(\s*[:=]\s*)\S+/gi, '$1$2[REDACTED]')
    .replace(/\bnode_[a-f0-9]{24}\.[A-Za-z0-9_-]+\b/g, '[REDACTED_NODE_CREDENTIAL]');
  return line;
}

export function parseGameServerSnapshots(value: unknown): GameServerSnapshot[] | null {
  if (!Array.isArray(value) || value.length > GAME_SERVER_LIMITS.maximumServersPerWorkspace) {
    return null;
  }
  const snapshots: GameServerSnapshot[] = [];
  const seen = new Set<string>();
  for (const candidate of value) {
    if (!isRecord(candidate) || !validGameServerId(candidate.serverId) || seen.has(candidate.serverId)) {
      return null;
    }
    const status = GAME_SERVER_STATUSES.includes(candidate.status as GameServerStatus)
      ? (candidate.status as GameServerStatus)
      : null;
    const candidatePlayers = Array.isArray(candidate.players) ? candidate.players : null;
    const players = candidatePlayers && candidatePlayers.length <= 500
      ? candidatePlayers.filter((player): player is string => typeof player === 'string' && /^[A-Za-z0-9_]{1,16}$/.test(player))
      : null;
    const playerCount = integer(candidate.playerCount, 0, 500);
    const uptimeSeconds = integer(candidate.uptimeSeconds, 0, Number.MAX_SAFE_INTEGER);
    const crashCount = integer(candidate.crashCount, 0, 1_000_000);
    const cpuLoadPercent = candidate.cpuLoadPercent === null
      ? null
      : typeof candidate.cpuLoadPercent === 'number' && Number.isFinite(candidate.cpuLoadPercent) && candidate.cpuLoadPercent >= 0 && candidate.cpuLoadPercent <= 100
        ? candidate.cpuLoadPercent
        : undefined;
    const memoryUsedBytes = candidate.memoryUsedBytes === null
      ? null
      : integer(candidate.memoryUsedBytes, 0, Number.MAX_SAFE_INTEGER) ?? undefined;
    const binaryHash = candidate.binaryHash === null
      ? null
      : typeof candidate.binaryHash === 'string' && /^sha256:[a-f0-9]{64}$/.test(candidate.binaryHash)
        ? candidate.binaryHash
        : undefined;
    const logTail = Array.isArray(candidate.logTail) && candidate.logTail.length <= 20
      ? candidate.logTail.map(redactGameLogLine).filter((line): line is string => Boolean(line))
      : null;
    const observedAt = integer(candidate.observedAt, 1, Number.MAX_SAFE_INTEGER);
    if (
      !status || !players || !candidatePlayers || players.length !== candidatePlayers.length ||
      playerCount === null || playerCount !== players.length ||
      uptimeSeconds === null || crashCount === null || cpuLoadPercent === undefined ||
      memoryUsedBytes === undefined || binaryHash === undefined || !logTail ||
      observedAt === null ||
      (candidate.exposure !== 'private' && candidate.exposure !== 'unexpected') ||
      typeof candidate.binaryVerified !== 'boolean' ||
      typeof candidate.crashLoop !== 'boolean'
    ) {
      return null;
    }
    seen.add(candidate.serverId);
    snapshots.push({
      serverId: candidate.serverId,
      status,
      players,
      playerCount,
      cpuLoadPercent,
      memoryUsedBytes,
      uptimeSeconds,
      exposure: candidate.exposure,
      binaryHash,
      binaryVerified: candidate.binaryVerified,
      crashCount,
      crashLoop: candidate.crashLoop,
      logTail,
      observedAt,
    });
  }
  return snapshots;
}
