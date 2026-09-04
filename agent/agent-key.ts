import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

/**
 * Where the agent keeps its local encryption key and its encrypted credential.
 *
 * Until 0.16.0 the user had to invent a passphrase of at least 16 characters
 * and set it in an environment variable before every command. That asked a
 * person to be a random number generator, and a hand-typed passphrase is
 * almost always weaker than the 256-bit key we can just generate.
 *
 * So by default the agent generates 32 random bytes once and stores them in a
 * user-private file with 0600 permissions, outside the working directory.
 *
 * The honest tradeoff, because it matters: a passphrase held only in someone's
 * head (or in an OS secret manager) protects the credential from an attacker
 * who can read files as that user. A generated key file sitting next to the
 * credential does not -- anyone who can read one can read the other. What it
 * does buy is real: no weak human-chosen secret, no passphrase in shell
 * history, and no credential written into the repository working directory.
 * `YSD_NODE_AGENT_KEY` still overrides everything, so anyone who wants the
 * stronger separation keeps it.
 */

const DIRECTORY_NAME = 'ysd-node-agent';

/** A per-user directory. Never the working directory, never the repository. */
export function agentHomeDirectory(): string {
  if (process.platform === 'win32') {
    const base = process.env.LOCALAPPDATA
      ?? process.env.APPDATA
      ?? path.join(os.homedir(), 'AppData', 'Local');
    return path.join(base, DIRECTORY_NAME);
  }
  const base = process.env.XDG_DATA_HOME ?? path.join(os.homedir(), '.local', 'share');
  return path.join(base, DIRECTORY_NAME);
}

export function defaultCredentialPath(): string {
  return path.join(agentHomeDirectory(), 'credentials.json');
}

function agentKeyPath(): string {
  return path.join(agentHomeDirectory(), 'agent.key');
}

async function restrict(target: string): Promise<void> {
  // POSIX only. Windows inherits the ACL of the per-user LOCALAPPDATA
  // directory, which is already restricted to the account; chmod there is a
  // no-op that would only create a false sense of having done something.
  if (process.platform === 'win32') return;
  try {
    await chmod(target, 0o600);
  } catch {
    // A filesystem without POSIX modes is not a reason to refuse to run.
  }
}

/**
 * Returns the local encryption key, generating and storing one on first use.
 *
 * An explicit `YSD_NODE_AGENT_KEY` always wins and is never written to disk.
 */
export async function resolveAgentKey(): Promise<string> {
  const supplied = process.env.YSD_NODE_AGENT_KEY?.trim() ?? '';
  if (supplied.length >= 16) return supplied;
  if (supplied.length > 0) {
    throw new Error(
      'YSD_NODE_AGENT_KEY is set but shorter than 16 characters. '
      + 'Unset it to let the agent generate a strong key, or supply a longer one.',
    );
  }

  const file = agentKeyPath();
  try {
    const existing = (await readFile(file, 'utf8')).trim();
    if (existing.length >= 16) return existing;
  } catch {
    // First run on this machine.
  }

  const generated = Buffer.from(randomBytes(32)).toString('base64url');
  await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  await writeFile(file, `${generated}\n`, { encoding: 'utf8', mode: 0o600 });
  await restrict(file);
  return generated;
}
