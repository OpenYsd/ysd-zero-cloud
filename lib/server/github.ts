import { analyzeNodeRepository, type RepositoryAnalysis } from '../app-runtime.ts';
import type { RepositorySource } from '../smart-deploy.ts';

/** Read-only, bounded github.com source inspection for App Runtime. */

const API = 'https://api.github.com';
const TIMEOUT_MS = 8_000;
const MAX_API_BYTES = 12 * 1024 * 1024;

export type RepositoryRef = { owner: string; repo: string };

export function parseRepository(input: string): RepositoryRef | null {
  const trimmed = input.trim().replace(/\.git$/i, '');
  let path = trimmed;
  if (/^https?:\/\//i.test(trimmed)) {
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      return null;
    }
    if (url.protocol !== 'https:' || !['github.com', 'www.github.com'].includes(url.hostname) ||
        url.username || url.password || url.search || url.hash) return null;
    path = url.pathname.replace(/^\//, '');
  } else if (trimmed.includes(':') || trimmed.includes('@')) {
    return null;
  }
  const parts = path.split('/');
  if (parts.length !== 2 || parts.some((part) => !/^[A-Za-z0-9_.-]{1,100}$/.test(part))) return null;
  if (parts.some((part) => part === '.' || part === '..')) return null;
  return { owner: parts[0]!, repo: parts[1]! };
}

export function validGithubRef(value: string): boolean {
  return value.length >= 1 && value.length <= 128 &&
    !value.startsWith('/') && !value.endsWith('/') && !value.includes('..') &&
    !value.includes('\\') && !value.includes('@{') &&
    value.split('/').every((part) => /^[A-Za-z0-9_.-]+$/.test(part) && part !== '.' && part !== '..');
}

function headers(
  token?: string,
  accept = 'application/vnd.github+json',
): HeadersInit {
  return {
    Accept: accept,
    'User-Agent': 'ysd-zero-cloud',
    'X-GitHub-Api-Version': '2022-11-28',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function boundedText(response: Response, maximum = MAX_API_BYTES): Promise<string | null> {
  const length = Number(response.headers.get('content-length') ?? 0);
  if (length > maximum) return null;
  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximum) {
      await reader.cancel('bounded-response');
      return null;
    }
    chunks.push(value);
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(combined);
}

async function getJson<T>(url: string, token?: string, maximum?: number): Promise<T | null> {
  try {
    const response = await fetch(url, {
      headers: headers(token),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) return null;
    const text = await boundedText(response, maximum);
    return text === null ? null : JSON.parse(text) as T;
  } catch {
    return null;
  }
}

type RepositoryBlob = {
  path?: string;
  type?: 'blob' | 'tree' | 'commit';
  size?: number;
  sha?: string;
};

type BlobMetadata = {
  content?: string;
  encoding?: string;
  size?: number;
  sha?: string;
};

async function getPublicFile(
  ref: RepositoryRef,
  blob: RepositoryBlob | undefined,
  maximum: number,
  token?: string,
): Promise<string | null> {
  if (!blob || blob.type !== 'blob' || !/^[a-f0-9]{40}$/i.test(blob.sha ?? '')) return null;
  if (typeof blob.size === 'number' && (!Number.isSafeInteger(blob.size) || blob.size < 0 || blob.size > maximum)) return null;
  const encodedCeiling = Math.ceil(maximum / 3) * 4 + 8_192;
  const responseCeiling = Math.min(MAX_API_BYTES, encodedCeiling + 64 * 1024);
  const value = await getJson<BlobMetadata>(
    `${API}/repos/${encodeURIComponent(ref.owner)}/${encodeURIComponent(ref.repo)}/git/blobs/${blob.sha}`,
    token,
    responseCeiling,
  );
  if (!value || value.encoding !== 'base64' || value.sha?.toLowerCase() !== blob.sha!.toLowerCase() ||
      typeof value.content !== 'string' || value.content.length > encodedCeiling ||
      (typeof value.size === 'number' && value.size > maximum)) return null;
  try {
    const encoded = value.content.replace(/\s+/gu, '');
    if (encoded.length > encodedCeiling) return null;
    const binary = atob(encoded);
    if (binary.length > maximum) return null;
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

type RepositoryMetadata = { default_branch?: string; private?: boolean; archived?: boolean; disabled?: boolean };
type CommitMetadata = { sha?: string };
type TreeMetadata = {
  truncated?: boolean;
  tree?: RepositoryBlob[];
};

export type InspectedRepository = {
  source: RepositorySource;
  analysis: RepositoryAnalysis;
};

export type RepositoryInspection =
  | { ok: true; value: InspectedRepository }
  | { ok: false; status: number; error: string };

export async function inspectRepositoryForDeploy(input: {
  repository: string;
  branch?: string | null;
  commit?: string | null;
  token?: string;
}): Promise<RepositoryInspection> {
  const ref = parseRepository(input.repository);
  if (!ref) return { ok: false, status: 400, error: 'Use owner/repository or an https://github.com URL.' };
  const metadata = await getJson<RepositoryMetadata>(`${API}/repos/${ref.owner}/${ref.repo}`, input.token, 256 * 1024);
  if (!metadata) return { ok: false, status: 404, error: 'The GitHub repository could not be inspected.' };
  if (metadata.private) return { ok: false, status: 409, error: 'App Runtime v1 acquires public GitHub archives only; private source is not copied through the control plane.' };
  if (metadata.archived || metadata.disabled) return { ok: false, status: 409, error: 'Archived or disabled repositories cannot be deployed.' };

  const branch = input.branch?.trim() || metadata.default_branch || 'main';
  if (!validGithubRef(branch)) return { ok: false, status: 400, error: 'The GitHub branch name is invalid.' };
  const requested = input.commit?.trim() || branch;
  if (input.commit && !/^[a-f0-9]{40}$/i.test(input.commit.trim())) {
    return { ok: false, status: 400, error: 'A pinned commit must be a full 40-character SHA.' };
  }
  const commitMetadata = await getJson<CommitMetadata>(
    `${API}/repos/${ref.owner}/${ref.repo}/commits/${encodeURIComponent(requested)}`,
    input.token,
    512 * 1024,
  );
  const commit = commitMetadata?.sha?.toLowerCase() ?? '';
  if (!/^[a-f0-9]{40}$/.test(commit)) return { ok: false, status: 404, error: 'The branch or commit could not be resolved.' };
  if (input.commit && commit !== input.commit.trim().toLowerCase()) {
    return { ok: false, status: 409, error: 'GitHub did not resolve the exact requested commit.' };
  }

  const tree = await getJson<TreeMetadata>(
    `${API}/repos/${ref.owner}/${ref.repo}/git/trees/${commit}?recursive=1`,
    input.token,
  );
  if (!tree?.tree || tree.truncated || tree.tree.length > 12_000) {
    return { ok: false, status: 409, error: 'The repository tree is unavailable, truncated, or exceeds the App Runtime file ceiling.' };
  }
  const blobs = tree.tree.filter((entry) => entry.type === 'blob' && typeof entry.path === 'string');
  const files = blobs.map((entry) => entry.path!);
  const blobFor = (file: string) => blobs.find((entry) => entry.path === file);
  const sourceRisk: string[] = [];
  if (tree.tree.some((entry) => entry.type === 'commit') || files.includes('.gitmodules')) {
    sourceRisk.push('Git submodules are not allowed.');
  }
  if (files.includes('.lfsconfig') || files.includes('.git/lfs')) sourceRisk.push('Git LFS repository configuration is not allowed.');
  if (!files.includes('package.json')) sourceRisk.push('package.json is required at the repository root.');

  const packageJson = files.includes('package.json')
    ? await getPublicFile(ref, blobFor('package.json'), 256 * 1024, input.token)
    : null;
  const lockfile = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'].find((name) => files.includes(name)) ?? null;
  const [nvmrc, envExample, lockfileContent, attributes] = await Promise.all([
    files.includes('.nvmrc') ? getPublicFile(ref, blobFor('.nvmrc'), 1024, input.token) : null,
    files.includes('.env.example') ? getPublicFile(ref, blobFor('.env.example'), 64 * 1024, input.token) : null,
    lockfile ? getPublicFile(ref, blobFor(lockfile), 8 * 1024 * 1024, input.token) : null,
    files.includes('.gitattributes') ? getPublicFile(ref, blobFor('.gitattributes'), 64 * 1024, input.token) : null,
  ]);
  if (attributes && /filter\s*=\s*lfs/i.test(attributes)) sourceRisk.push('Git LFS objects are not allowed.');
  for (const [name, content] of [['package.json', packageJson], [lockfile ?? 'lockfile', lockfileContent]] as const) {
    if (content?.startsWith('version https://git-lfs.github.com/spec/v1')) sourceRisk.push(`${name} is an unresolved Git LFS pointer.`);
  }
  const analysis = analyzeNodeRepository({ packageJson, files, nvmrc, envExample, lockfileContent });
  analysis.blockedReasons = [...new Set([...sourceRisk, ...analysis.blockedReasons])];
  if (analysis.blockedReasons.length > 0) analysis.contract = null;
  return {
    ok: true,
    value: {
      source: {
        owner: ref.owner,
        repository: ref.repo,
        branch,
        commit,
        visibility: 'public',
      },
      analysis,
    },
  };
}
