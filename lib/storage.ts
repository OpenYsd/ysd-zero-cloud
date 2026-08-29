/**
 * R2 limits enforced by YSD Zero Cloud.
 *
 * Cloudflare currently includes 10 GB-month, 1 million Class A operations,
 * and 10 million Class B operations in R2 Standard's monthly free tier. The
 * account-wide guards below deliberately use no more than ten percent of any
 * allowance, leaving room for maintenance and measurement drift. There is no
 * paid fallback: the operation is refused at the ceiling.
 */
export const STORAGE_LIMITS = {
  accountBytes: 1024 * 1024 * 1024,
  workspaceBytes: 256 * 1024 * 1024,
  objectBytes: 10 * 1024 * 1024,
  accountObjects: 5_000,
  workspaceObjects: 500,
  accountClassA: 50_000,
  workspaceClassA: 5_000,
  accountClassB: 500_000,
  workspaceClassB: 50_000,
} as const;

export type StorageQuota = {
  bytesUsed: number;
  bytesReserved: number;
  objectCount: number;
  classAWrites: number;
  classBReads: number;
};

export type StorageQuotaDecision =
  | { ok: true }
  | { ok: false; code: 'size' | 'objects' | 'writes' | 'reads'; error: string };

export function storagePeriod(now = new Date()): string {
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
}

export function safeObjectName(input: string): string {
  const cleaned = Array.from(input.normalize('NFKC'))
    .map((character) => {
      const code = character.codePointAt(0) ?? 0;
      return character === '/' ||
        character === '\\' ||
        code <= 31 ||
        code === 127
        ? '-'
        : character;
    })
    .join('')
    .replace(/-+/g, '-')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 180);
  return cleaned.replace(/[.\- ]/g, '') ? cleaned : 'file';
}

export function validateObject(
  name: string,
  size: number,
): StorageQuotaDecision {
  if (!name.trim())
    return { ok: false, code: 'size', error: 'Choose a file to upload.' };
  if (!Number.isFinite(size) || size <= 0) {
    return { ok: false, code: 'size', error: 'Empty files are not stored.' };
  }
  if (size > STORAGE_LIMITS.objectBytes) {
    return {
      ok: false,
      code: 'size',
      error: 'This file exceeds the 10 MB Zero Mode object limit.',
    };
  }
  return { ok: true };
}

export function canReserveUpload(
  account: StorageQuota,
  workspace: StorageQuota,
  size: number,
): StorageQuotaDecision {
  if (
    account.bytesUsed + account.bytesReserved + size >
    STORAGE_LIMITS.accountBytes
  ) {
    return {
      ok: false,
      code: 'size',
      error: 'The account storage guard has reached 1 GB.',
    };
  }
  if (
    workspace.bytesUsed + workspace.bytesReserved + size >
    STORAGE_LIMITS.workspaceBytes
  ) {
    return {
      ok: false,
      code: 'size',
      error: 'This workspace has reached its 256 MB storage guard.',
    };
  }
  if (account.objectCount >= STORAGE_LIMITS.accountObjects) {
    return {
      ok: false,
      code: 'objects',
      error: 'The account object-count guard has been reached.',
    };
  }
  if (workspace.objectCount >= STORAGE_LIMITS.workspaceObjects) {
    return {
      ok: false,
      code: 'objects',
      error: 'This workspace has reached 500 objects.',
    };
  }
  if (
    account.classAWrites >= STORAGE_LIMITS.accountClassA ||
    workspace.classAWrites >= STORAGE_LIMITS.workspaceClassA
  ) {
    return {
      ok: false,
      code: 'writes',
      error: 'The monthly storage write guard has been reached.',
    };
  }
  return { ok: true };
}

export function canRead(
  account: StorageQuota,
  workspace: StorageQuota,
): StorageQuotaDecision {
  if (
    account.classBReads >= STORAGE_LIMITS.accountClassB ||
    workspace.classBReads >= STORAGE_LIMITS.workspaceClassB
  ) {
    return {
      ok: false,
      code: 'reads',
      error: 'The monthly storage read guard has been reached.',
    };
  }
  return { ok: true };
}
