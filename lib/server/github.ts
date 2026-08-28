import type { RepositorySignals } from '@/lib/smart-deploy';

/**
 * Read-only repository inspection for Smart Deploy.
 *
 * Only two endpoints are used, both GET, both public: the root tree listing
 * and `package.json`. Nothing is written back to GitHub and no repository
 * content is stored — the call returns the framework signals and nothing else.
 *
 * A failure here is not an error. The planner falls back to name-based
 * inference and reports the plan as `inferred` rather than `inspected`.
 */

const API = 'https://api.github.com';
const TIMEOUT_MS = 4000;

export type RepositoryRef = { owner: string; repo: string };

/** Accepts `owner/repo`, a full GitHub URL, or a `.git` suffix. */
export function parseRepository(input: string): RepositoryRef | null {
  const trimmed = input.trim().replace(/\.git$/, '');
  const withoutHost = trimmed.replace(/^https?:\/\/(www\.)?github\.com\//i, '');
  const parts = withoutHost.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  const [owner, repo] = parts;
  if (!owner || !repo) return null;
  if (!/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(repo)) return null;
  return { owner, repo };
}

function headers(token?: string): HeadersInit {
  return {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'ysd-zero-cloud',
    'X-GitHub-Api-Version': '2022-11-28',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function getJson<T>(url: string, token?: string): Promise<T | null> {
  try {
    const response = await fetch(url, {
      headers: headers(token),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) return null;
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

type ContentEntry = { name: string; type: string };
type FileContent = { content?: string; encoding?: string };

function decodeBase64(value: string): string {
  return atob(value.replace(/\n/g, ''));
}

/**
 * Collects framework signals from a repository.
 *
 * @returns `null` when the repository could not be read, so the caller can
 * tell "no signals" apart from "no dependencies".
 */
export async function inspectRepository(
  repository: string,
  token?: string,
): Promise<RepositorySignals | null> {
  const ref = parseRepository(repository);
  if (!ref) return null;

  const base = `${API}/repos/${ref.owner}/${ref.repo}`;
  const entries = await getJson<ContentEntry[]>(`${base}/contents/`, token);
  if (!Array.isArray(entries)) return null;

  const files = entries.filter((entry) => entry.type === 'file').map((entry) => entry.name);

  let dependencies: string[] = [];
  if (files.includes('package.json')) {
    const manifest = await getJson<FileContent>(`${base}/contents/package.json`, token);
    if (manifest?.content && manifest.encoding === 'base64') {
      try {
        const parsed = JSON.parse(decodeBase64(manifest.content)) as {
          dependencies?: Record<string, string>;
          devDependencies?: Record<string, string>;
        };
        dependencies = [
          ...Object.keys(parsed.dependencies ?? {}),
          ...Object.keys(parsed.devDependencies ?? {}),
        ];
      } catch {
        // A manifest we cannot parse is the same as one we never found.
      }
    }
  }

  return { files, dependencies };
}

/** The default branch head, used as the recorded commit for a deployment. */
export async function latestCommit(repository: string, token?: string): Promise<string | null> {
  const ref = parseRepository(repository);
  if (!ref) return null;
  const commits = await getJson<{ sha: string }[]>(
    `${API}/repos/${ref.owner}/${ref.repo}/commits?per_page=1`,
    token,
  );
  return commits?.[0]?.sha?.slice(0, 7) ?? null;
}
