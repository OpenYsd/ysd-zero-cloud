/**
 * The portable artifact backup format.
 *
 * Everything here is pure: the manifest shape, the path rules, and the
 * decisions a backup or a restore has to make. The agent module streams bytes;
 * this module decides what is allowed to exist.
 *
 * ONE DESIGN CHOICE EXPLAINS MOST OF THIS FILE.
 *
 * A tar entry name is the classic attack surface: traversal, absolute paths,
 * drive letters, PAX overrides, duplicate entries, and a 100/255-character
 * limit that real `node_modules` trees blow straight through. So the archive
 * does not carry paths at all. Entries are numbered -- `payload/000001` -- and
 * the *manifest* maps each index to a relative path that has already survived
 * {@link canonicalBackupPath}. Extraction resolves its destination from the
 * validated manifest, never from the archive. A hostile archive can therefore
 * lie about its own byte count and be caught, but it cannot name a file.
 *
 * WHAT A BACKUP IS NOT. The manifest is a description, not a credential. It
 * carries no signature that anyone but the writer could have produced, so
 * verifying a backup proves it is internally consistent and uncorrupted -- not
 * that YSD produced it. The runtime manifest a node actually trusts is signed
 * with that node's own token and is deliberately *excluded* from the payload
 * and rebuilt at restore time.
 */

/** Bundle extension. One artifact per bundle. */
export const BACKUP_EXTENSION = '.ysdbak';

/** Bumped only for an incompatible container or manifest change. */
export const BACKUP_FORMAT_VERSION = 1;

/** The archive member holding the manifest, always first. */
export const BACKUP_MANIFEST_ENTRY = 'manifest.json';

/** Prefix for numbered payload members. */
export const BACKUP_PAYLOAD_PREFIX = 'payload/';

/** The runtime manifest, never carried in a backup. See the file header. */
export const RUNTIME_MANIFEST_NAME = '.ysd-artifact.json';

export const BACKUP_LIMITS = {
  /** Manifest JSON, parsed into memory, so it is bounded hard. */
  manifestBytes: 8 * 1024 * 1024,
  /** Matches the runtime's own installed-file ceiling. */
  fileCount: 48_000,
  /** A single relative path, in UTF-8 bytes. */
  pathBytes: 1_024,
  /** Total payload, aligned with the App Runtime disk maximum. */
  payloadBytes: 2 * 1024 ** 3,
  /** Free space required beyond the payload before writing anything. */
  reserveBytes: 256 * 1024 ** 2,
} as const;

export const BACKUP_REASON_CODES = [
  'artifact_not_found',
  'artifact_unverified',
  'artifact_corrupted',
  'destination_invalid',
  'destination_overlap',
  'destination_unwritable',
  'already_exists',
  'low_disk',
  'bundle_unreadable',
  'bundle_truncated',
  'bundle_malformed',
  'manifest_invalid',
  'manifest_unsupported',
  'payload_mismatch',
  'path_unsafe',
  'path_collision',
  'entry_unsupported',
  'identity_mismatch',
  'wrong_node',
  'incompatible_platform',
  'incompatible_runtime',
  'already_restored',
  'artifact_conflict',
  'restore_busy',
  'preflight_unavailable',
  'confirmation_unavailable',
  'source_changed',
  'not_transferred',
  'source_node_live',
] as const;
export type BackupReasonCode = (typeof BACKUP_REASON_CODES)[number];

export type BackupFileRecord = {
  /** Forward-slash relative path inside the artifact. */
  path: string;
  size: number;
  sha256: string;
  /** `true` when the file is executable on POSIX. Windows ignores it. */
  executable: boolean;
};

export type BackupManifest = {
  formatVersion: typeof BACKUP_FORMAT_VERSION;
  artifactId: string;
  deploymentId: string;
  projectId: string;
  workspaceId: string;
  /** The runtime checksum, `sha256:<hex>`, recomputed on verify. */
  artifactChecksum: string;
  artifactSizeBytes: number;
  fileCount: number;
  files: BackupFileRecord[];
  createdAt: number;
  createdByAgentVersion: string;
  platform: string;
  arch: string;
  nodeMajor: number;
  entrypoint: string;
  commit: string;
  /**
   * The unsigned half of the runtime manifest this artifact was built with.
   *
   * Carried as data, never as authority: the runtime manifest's signature is
   * an HMAC over the *source* node's token and is deliberately not included.
   * Restore rebuilds and re-signs the runtime manifest with the restoring
   * node's own token, after the payload checksum and the authoritative
   * identity have both been checked independently.
   */
  runtime: {
    contract: Record<string, unknown>;
    createdAt: number;
    verifiedAt: number;
  };
};

const IDENTIFIERS: Record<string, RegExp> = {
  artifactId: /^art_[a-f0-9]{24}$/u,
  deploymentId: /^dpl_[a-f0-9]{24}$/u,
  projectId: /^prj_[a-f0-9]{24}$/u,
  workspaceId: /^ws_[a-f0-9]{24}$/u,
};

/**
 * Windows reserved device names. These are not filenames: opening `NUL` opens
 * the null device wherever it appears, extension or not, so an archive that
 * contains one is rejected rather than written.
 */
const RESERVED_DEVICE = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/iu;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Normalises one relative artifact path, or returns `null` if it is not one.
 *
 * Applied on the way in (building a backup) and on the way out (restoring one),
 * so a path that could not have been produced also cannot be consumed.
 */
export function canonicalBackupPath(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  if (Buffer.byteLength(raw, 'utf8') > BACKUP_LIMITS.pathBytes) return null;
  // Control characters, and the colon that carries both drive letters and
  // NTFS alternate data streams. Checked by code point rather than by regex:
  // a control character inside a pattern is unreadable and easy to break.
  for (const character of raw) {
    const code = character.codePointAt(0)!;
    if (code < 0x20 || code === 0x7f || character === ':') return null;
  }
  const normalized = raw.replace(/\\/gu, '/');
  // Absolute, UNC (`//server`), and NT device (`//?/`) forms.
  if (normalized.startsWith('/')) return null;
  const segments = normalized.split('/');
  for (const segment of segments) {
    if (!segment || segment === '.' || segment === '..') return null;
    // Windows silently strips these, so `foo.` and `foo` are the same file.
    if (/[ .]$/u.test(segment)) return null;
    if (RESERVED_DEVICE.test(segment)) return null;
  }
  return segments.join('/');
}

/**
 * The key a case-insensitive filesystem would collapse two paths onto.
 *
 * Windows treats `Foo.js` and `foo.js` as one file, so a bundle containing
 * both would silently lose one on restore. Backslash and forward slash are
 * already unified by {@link canonicalBackupPath}.
 */
export function pathCollisionKey(path: string): string {
  return path.toLowerCase();
}

export function findPathCollisions(paths: readonly string[]): string[] {
  const seen = new Map<string, string>();
  const collisions: string[] = [];
  for (const path of paths) {
    const key = pathCollisionKey(path);
    const first = seen.get(key);
    if (first === undefined) seen.set(key, path);
    else collisions.push(path);
  }
  return collisions;
}

/** The numbered archive member for a payload index. */
export function payloadEntryName(index: number): string {
  return `${BACKUP_PAYLOAD_PREFIX}${String(index).padStart(6, '0')}`;
}

export function validateBackupManifest(value: unknown): BackupManifest | null {
  if (!isRecord(value)) return null;
  const expected = [
    'arch', 'artifactChecksum', 'artifactId', 'artifactSizeBytes', 'commit',
    'createdAt', 'createdByAgentVersion', 'deploymentId', 'entrypoint',
    'fileCount', 'files', 'formatVersion', 'nodeMajor', 'platform',
    'projectId', 'runtime', 'workspaceId',
  ];
  if (Object.keys(value).sort().join('\0') !== expected.sort().join('\0')) return null;
  if (value.formatVersion !== BACKUP_FORMAT_VERSION) return null;
  for (const [key, pattern] of Object.entries(IDENTIFIERS)) {
    if (typeof value[key] !== 'string' || !pattern.test(value[key] as string)) return null;
  }
  if (
    typeof value.artifactChecksum !== 'string' || !/^sha256:[a-f0-9]{64}$/u.test(value.artifactChecksum) ||
    !Number.isSafeInteger(value.artifactSizeBytes) || Number(value.artifactSizeBytes) < 0 ||
    Number(value.artifactSizeBytes) > BACKUP_LIMITS.payloadBytes ||
    !Number.isSafeInteger(value.createdAt) || Number(value.createdAt) < 0 ||
    typeof value.createdByAgentVersion !== 'string' || !/^\d+\.\d+\.\d+$/u.test(value.createdByAgentVersion) ||
    typeof value.platform !== 'string' || !/^[a-z0-9]{1,16}$/u.test(value.platform) ||
    typeof value.arch !== 'string' || !/^[a-z0-9]{1,16}$/u.test(value.arch) ||
    !Number.isSafeInteger(value.nodeMajor) || Number(value.nodeMajor) < 1 || Number(value.nodeMajor) > 999 ||
    typeof value.commit !== 'string' || !/^[a-f0-9]{7,64}$/u.test(value.commit) ||
    !Array.isArray(value.files) ||
    !Number.isSafeInteger(value.fileCount) || value.fileCount !== value.files.length ||
    value.files.length > BACKUP_LIMITS.fileCount
  ) return null;

  if (canonicalBackupPath(value.entrypoint) !== value.entrypoint) return null;

  const runtime = value.runtime;
  if (
    !isRecord(runtime) ||
    Object.keys(runtime).sort().join('\u0000') !== ['contract', 'createdAt', 'verifiedAt'].join('\u0000') ||
    !isRecord(runtime.contract) ||
    JSON.stringify(runtime.contract).length > 16 * 1024 ||
    !Number.isSafeInteger(runtime.createdAt) || Number(runtime.createdAt) < 0 ||
    !Number.isSafeInteger(runtime.verifiedAt) || Number(runtime.verifiedAt) < 0
  ) return null;

  let total = 0;
  const paths: string[] = [];
  for (const entry of value.files) {
    if (!isRecord(entry)) return null;
    if (Object.keys(entry).sort().join('\0') !== ['executable', 'path', 'sha256', 'size'].join('\0')) return null;
    if (canonicalBackupPath(entry.path) !== entry.path) return null;
    if (entry.path === RUNTIME_MANIFEST_NAME) return null;
    if (typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(entry.sha256)) return null;
    if (!Number.isSafeInteger(entry.size) || Number(entry.size) < 0) return null;
    if (typeof entry.executable !== 'boolean') return null;
    total += Number(entry.size);
    if (total > BACKUP_LIMITS.payloadBytes) return null;
    paths.push(entry.path as string);
  }
  if (total !== value.artifactSizeBytes) return null;
  if (findPathCollisions(paths).length > 0) return null;
  // Canonical ordering, so the same artifact always describes itself the same
  // way and two backups of it are byte-identical.
  for (let index = 1; index < paths.length; index += 1) {
    if (paths[index - 1]! >= paths[index]!) return null;
  }
  return value as unknown as BackupManifest;
}

export type BackupCompatibility = {
  compatible: boolean;
  reason: BackupReasonCode | null;
};

/**
 * Whether a bundle can run where it is being restored.
 *
 * Builds run with `--ignore-scripts`, so nothing is compiled on the node, but
 * a dependency may still ship prebuilt binaries chosen by platform and
 * architecture. Restoring across either is refused rather than discovered at
 * start time, and there is no rebuild fallback -- rebuilding is exactly what
 * this feature exists to avoid.
 */
export function evaluateBackupCompatibility(input: {
  manifest: Pick<BackupManifest, 'platform' | 'arch' | 'nodeMajor'>;
  platform: string;
  arch: string;
  nodeMajor: number;
  supportedNodeMajors: readonly number[];
}): BackupCompatibility {
  if (input.manifest.platform !== input.platform || input.manifest.arch !== input.arch) {
    return { compatible: false, reason: 'incompatible_platform' };
  }
  if (!input.supportedNodeMajors.includes(input.nodeMajor)) {
    return { compatible: false, reason: 'incompatible_runtime' };
  }
  if (!input.supportedNodeMajors.includes(input.manifest.nodeMajor)) {
    return { compatible: false, reason: 'incompatible_runtime' };
  }
  return { compatible: true, reason: null };
}

/**
 * What the control plane says about a deployment that has been transferred to a
 * replacement node and is waiting for its backup.
 *
 * `sourceArtifactId` is still `deployment.currentArtifactId` at this point: the
 * transfer moved ownership, not bytes. `replacementArtifactId` is the row the
 * control plane allocated for the imported copy, and `checksum` is read from
 * the immutable source row -- never from the node.
 */
export type ImportIdentity = {
  workspaceId: string;
  projectId: string;
  deploymentId: string;
  nodeId: string;
  sourceArtifactId: string;
  replacementArtifactId: string;
  checksum: string;
  desiredRevision: number;
  sourceNodeRevoked: boolean;
  awaitingImport: boolean;
};

/**
 * The import identity gate. Deliberately separate from `evaluateRestoreIdentity`.
 *
 * Ordinary restore is and stays same-node: a bundle may only rehydrate the
 * artifact the authenticated node already owns. Import is the narrow disaster
 * path, and it is narrow in a different way -- the bundle must match the
 * *source* artifact of a deployment that has already been transferred to the
 * authenticated node, whose old node is permanently revoked. Neither gate
 * loosens the other; a bundle that fails restore does not become importable,
 * and a bundle that fails import cannot be restored.
 */
export function evaluateImportIdentity(input: {
  manifest: Pick<BackupManifest, 'workspaceId' | 'projectId' | 'deploymentId' | 'artifactId' | 'artifactChecksum'>;
  authoritative: ImportIdentity;
  authenticatedNodeId: string;
  expectedDesiredRevision: number;
}): { allowed: boolean; reason: BackupReasonCode | null } {
  if (input.authoritative.nodeId !== input.authenticatedNodeId) {
    return { allowed: false, reason: 'wrong_node' };
  }
  if (!input.authoritative.sourceNodeRevoked) {
    return { allowed: false, reason: 'source_node_live' };
  }
  if (!input.authoritative.awaitingImport) {
    return { allowed: false, reason: 'not_transferred' };
  }
  if (input.authoritative.desiredRevision !== input.expectedDesiredRevision) {
    return { allowed: false, reason: 'source_changed' };
  }
  if (
    input.manifest.workspaceId !== input.authoritative.workspaceId ||
    input.manifest.projectId !== input.authoritative.projectId ||
    input.manifest.deploymentId !== input.authoritative.deploymentId ||
    // The bundle names the artifact it was taken from, which is the source row
    // the transfer left in place -- never the replacement row.
    input.manifest.artifactId !== input.authoritative.sourceArtifactId ||
    input.manifest.artifactChecksum !== input.authoritative.checksum
  ) {
    return { allowed: false, reason: 'identity_mismatch' };
  }
  return { allowed: true, reason: null };
}

export type RestoreIdentity = {
  workspaceId: string;
  projectId: string;
  deploymentId: string;
  nodeId: string;
  currentArtifactId: string;
  checksum: string;
};

/**
 * The restore identity gate.
 *
 * A backup may only rehydrate the artifact the control plane already believes
 * is current for this deployment, on the node that already owns it. There is
 * no override: an artifact restored anywhere else would be a different
 * deployment's bytes wearing the right name.
 */
export function evaluateRestoreIdentity(input: {
  manifest: Pick<BackupManifest, 'workspaceId' | 'projectId' | 'deploymentId' | 'artifactId' | 'artifactChecksum'>;
  authoritative: RestoreIdentity;
  authenticatedNodeId: string;
}): { allowed: boolean; reason: BackupReasonCode | null } {
  if (input.authoritative.nodeId !== input.authenticatedNodeId) {
    return { allowed: false, reason: 'wrong_node' };
  }
  if (
    input.manifest.workspaceId !== input.authoritative.workspaceId ||
    input.manifest.projectId !== input.authoritative.projectId ||
    input.manifest.deploymentId !== input.authoritative.deploymentId ||
    input.manifest.artifactId !== input.authoritative.currentArtifactId ||
    input.manifest.artifactChecksum !== input.authoritative.checksum
  ) {
    return { allowed: false, reason: 'identity_mismatch' };
  }
  return { allowed: true, reason: null };
}

/**
 * What to do when the artifact directory already exists.
 *
 * Identical bytes are a no-op, which makes restore safely repeatable. Different
 * bytes are a hard stop: an artifact id names one exact set of bytes, and
 * quietly replacing them would break the immutability every other phase relies
 * on. There is deliberately no force flag.
 */
export function evaluateArtifactCollision(input: {
  existingChecksum: string | null;
  bundleChecksum: string;
}): { action: 'restore' | 'already_restored' | 'refuse'; reason: BackupReasonCode | null } {
  if (input.existingChecksum === null) return { action: 'restore', reason: null };
  if (input.existingChecksum === input.bundleChecksum) {
    return { action: 'already_restored', reason: 'already_restored' };
  }
  return { action: 'refuse', reason: 'artifact_conflict' };
}

/** Bundle filename, built only from identifiers the node already trusts. */
export function backupFileName(artifactId: string, checksum: string): string {
  if (!IDENTIFIERS.artifactId!.test(artifactId) || !/^sha256:[a-f0-9]{64}$/u.test(checksum)) {
    throw new Error('backup name inputs are invalid');
  }
  return `ysd-artifact-${artifactId}-${checksum.slice(7, 19)}${BACKUP_EXTENSION}`;
}

export function backupReasonMessage(code: BackupReasonCode): string {
  const messages: Record<BackupReasonCode, string> = {
    not_transferred: 'This deployment has not been transferred to this Compute Node for recovery.',
    source_node_live: 'The Compute Node this backup came from is not declared lost.',
    artifact_not_found: 'That artifact is not present on this Compute Node.',
    artifact_unverified: 'The artifact does not carry a valid runtime manifest for this node.',
    artifact_corrupted: 'The artifact failed its integrity check, so it was not backed up.',
    destination_invalid: 'The backup destination must be an existing absolute directory.',
    destination_overlap: 'The backup destination cannot sit inside the Agent or artifact storage.',
    destination_unwritable: 'The backup destination is not writable.',
    already_exists: 'A backup of this artifact already exists at that destination.',
    low_disk: 'There is not enough free space for this operation.',
    bundle_unreadable: 'The backup file could not be read.',
    bundle_truncated: 'The backup file ends part-way through its contents.',
    bundle_malformed: 'The backup file is not a valid YSD artifact backup.',
    manifest_invalid: 'The backup manifest is missing required fields or is out of bounds.',
    manifest_unsupported: 'This backup was written in a format this Agent does not understand.',
    payload_mismatch: 'The backup contents do not match the checksums in its manifest.',
    path_unsafe: 'The backup describes a file path that is not safe to write.',
    path_collision: 'The backup describes two files that would collide on this filesystem.',
    entry_unsupported: 'The backup contains an archive entry type that is not allowed.',
    identity_mismatch: 'This backup belongs to a different deployment or artifact.',
    wrong_node: 'This deployment belongs to a different Compute Node.',
    incompatible_platform: 'This backup was made on a different platform or architecture.',
    incompatible_runtime: 'This backup needs a Node.js runtime this node does not have.',
    already_restored: 'That artifact is already present and matches this backup.',
    artifact_conflict: 'An artifact with that id already exists with different contents.',
    restore_busy: 'Another restore for this artifact is already running.',
    preflight_unavailable: 'The control plane could not confirm what this deployment expects.',
    confirmation_unavailable:
      'The artifact was restored and verified locally, but the control plane could not be told, so automatic recovery still sees it as missing.',
    source_changed: 'The artifact changed while the backup was being written.',
  };
  return messages[code];
}
