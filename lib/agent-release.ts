import { CURRENT_AGENT_VERSION, NODE_PROTOCOL_VERSION } from './nodes.ts';

/**
 * The Compute Node agent release contract.
 *
 * Phase 16 replaces "clone the repository and run a TypeScript file with an
 * experimental flag" with a single self-contained JavaScript bundle the control
 * plane serves from its own origin. The agent imports nothing but `node:*`
 * built-ins -- verified across its whole transitive graph -- so one file with no
 * `node_modules` is the honest shape for it, not a packaging trick.
 *
 * INTEGRITY, STATED PLAINLY. What this model gives you:
 *
 *   * the download URL pins an exact version, never "latest"
 *   * the expected SHA-256 is published by the same authenticated control plane
 *   * the install command verifies the digest and refuses to run on mismatch
 *   * transport is HTTPS
 *
 * What it does NOT give you, and must never be described as giving you:
 *
 *   * a code-signed binary, an Authenticode signature, or a notarized bundle
 *   * protection against a compromised control plane -- an attacker who could
 *     replace the artifact could replace the published digest with it
 *
 * Signing needs a Windows code-signing certificate and an Apple Developer
 * identity. Neither exists for this project, and inventing a "signed release"
 * badge over a plain checksum would be worse than the honest smaller claim.
 */

/** Node.js floor for the agent, matching the repository `engines` field. */
export const MINIMUM_NODE_VERSION = '22.13.0';

/** Where the built artifact is served from, relative to the control-plane origin. */
export const AGENT_DOWNLOAD_DIRECTORY = '/agent';

export type AgentPlatform = 'windows' | 'linux' | 'macos';

export const AGENT_PLATFORMS = ['windows', 'linux', 'macos'] as const;

export const AGENT_PLATFORM_LABELS: Record<AgentPlatform, string> = {
  windows: 'Windows',
  linux: 'Linux',
  macos: 'macOS',
};

/** The release description the build emits and the UI reads. */
export type AgentManifest = {
  version: string;
  protocolVersion: number;
  minimumNodeVersion: string;
  filename: string;
  downloadPath: string;
  sha256: string;
  size: number;
};

export function agentArtifactName(version = CURRENT_AGENT_VERSION): string {
  return `ysd-node-agent-${version}.mjs`;
}

export function agentDownloadPath(version = CURRENT_AGENT_VERSION): string {
  return `${AGENT_DOWNLOAD_DIRECTORY}/${agentArtifactName(version)}`;
}

export function agentChecksumPath(version = CURRENT_AGENT_VERSION): string {
  return `${agentDownloadPath(version)}.sha256`;
}

export function agentManifestPath(): string {
  return `${AGENT_DOWNLOAD_DIRECTORY}/manifest.json`;
}

/** A SHA-256 digest as the build writes it: 64 lowercase hex characters. */
export function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

export function parseAgentManifest(value: unknown): AgentManifest | null {
  if (!value || typeof value !== 'object') return null;
  const row = value as Record<string, unknown>;
  if (typeof row.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(row.version)) return null;
  if (row.protocolVersion !== NODE_PROTOCOL_VERSION) return null;
  if (typeof row.minimumNodeVersion !== 'string') return null;
  if (row.filename !== agentArtifactName(row.version)) return null;
  if (row.downloadPath !== agentDownloadPath(row.version)) return null;
  if (!isSha256(row.sha256)) return null;
  if (typeof row.size !== 'number' || !Number.isSafeInteger(row.size) || row.size <= 0) return null;
  return {
    version: row.version,
    protocolVersion: row.protocolVersion,
    minimumNodeVersion: row.minimumNodeVersion,
    filename: row.filename,
    downloadPath: row.downloadPath,
    sha256: row.sha256,
    size: row.size,
  };
}

// ---------------------------------------------------------------------------
// Install commands.
// ---------------------------------------------------------------------------

/**
 * Every value that reaches a generated command is server-controlled: an origin
 * the control plane resolved, a version and filename from the release contract,
 * and a hex digest. The pairing code is deliberately NOT among them -- it is
 * typed into a prompt instead, so it never lands in a shell history file, a
 * process list, or a screen-share of somebody's terminal scrollback.
 *
 * These quoting helpers exist anyway. "The inputs are trusted today" is exactly
 * the assumption that rots, and a command builder that only works while nobody
 * changes its callers is not a safe one.
 */

/** Single-quoted PowerShell literal: the only escape inside is a doubled quote. */
export function powerShellLiteral(value: string): string {
  return `'${stripControl(value).replace(/'/g, "''")}'`;
}

/** Single-quoted POSIX literal: close, escape, reopen. */
export function shellLiteral(value: string): string {
  return `'${stripControl(value).replace(/'/g, "'\\''")}'`;
}

/**
 * Removes anything that could end a line or move a cursor. A newline inside a
 * generated command is the difference between one command and two.
 */
function stripControl(value: string): string {
  let out = '';
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 32 || (code >= 127 && code <= 159)) continue;
    out += character;
  }
  return out;
}

export type InstallCommandInput = {
  origin: string;
  manifest: AgentManifest;
  platform: AgentPlatform;
};

export type InstallCommand = {
  platform: AgentPlatform;
  label: string;
  /** What the user pastes. Multi-line, no pairing secret. */
  script: string;
  /** The one-liner shown as "check your Node version first". */
  nodeCheck: string;
};

/**
 * Builds the install script for one platform.
 *
 * Deliberately NOT a `irm … | iex` one-liner. That pattern executes whatever
 * the origin returns before anyone can look at it, which defeats the checksum
 * the rest of this design is built around. The script downloads, hashes,
 * compares, and only then runs -- and it stops on a mismatch rather than
 * warning and continuing.
 */
export function buildInstallCommand(input: InstallCommandInput): InstallCommand {
  const { origin, manifest, platform } = input;
  const url = `${origin}${manifest.downloadPath}`;
  const file = manifest.filename;
  const digest = manifest.sha256;

  if (platform === 'windows') {
    return {
      platform,
      label: AGENT_PLATFORM_LABELS[platform],
      nodeCheck: 'node --version',
      script: [
        `$ErrorActionPreference = 'Stop'`,
        `$url = ${powerShellLiteral(url)}`,
        `$file = ${powerShellLiteral(file)}`,
        `$expected = ${powerShellLiteral(digest)}`,
        `Invoke-WebRequest -Uri $url -OutFile $file`,
        `$actual = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLower()`,
        `if ($actual -ne $expected) { Remove-Item $file -Force; throw "Checksum mismatch. The download was discarded." }`,
        `node $file pair --url ${powerShellLiteral(origin)}`,
      ].join('\n'),
    };
  }

  const hasher = platform === 'macos' ? 'shasum -a 256' : 'sha256sum';
  return {
    platform,
    label: AGENT_PLATFORM_LABELS[platform],
    nodeCheck: 'node --version',
    script: [
      `set -eu`,
      `url=${shellLiteral(url)}`,
      `file=${shellLiteral(file)}`,
      `expected=${shellLiteral(digest)}`,
      `curl -fsSL "$url" -o "$file"`,
      `actual=$(${hasher} "$file" | cut -d' ' -f1)`,
      `[ "$actual" = "$expected" ] || { rm -f "$file"; echo 'Checksum mismatch. The download was discarded.' >&2; exit 1; }`,
      `node "$file" pair --url ${shellLiteral(origin)}`,
    ].join('\n'),
  };
}

export function buildInstallCommands(
  origin: string,
  manifest: AgentManifest,
): InstallCommand[] {
  return AGENT_PLATFORMS.map((platform) =>
    buildInstallCommand({ origin, manifest, platform }),
  );
}

/** Compares dotted versions. Shared with the agent-compatibility evaluator. */
export function meetsMinimumNodeVersion(
  reported: string,
  minimum = MINIMUM_NODE_VERSION,
): boolean {
  const clean = reported.trim().replace(/^v/, '');
  if (!/^\d+\.\d+\.\d+/.test(clean)) return false;
  const a = clean.split('.').map((part) => Number.parseInt(part, 10));
  const b = minimum.split('.').map((part) => Number.parseInt(part, 10));
  for (let index = 0; index < 3; index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference > 0;
  }
  return true;
}
