import { createId } from '@/lib/crypto';
import type { StorageObject, StorageState, StorageUsage } from '@/lib/domain';
import {
  STORAGE_LIMITS,
  safeObjectName,
  storagePeriod,
  validateObject,
} from '@/lib/storage';
import { db, execute, query, queryOne } from './db';
import { runtimeEnv } from './env';
import { writeLog } from './logs';
import { assertResourceCapacity } from './organization-limits';

type MeterRow = StorageUsage & { scope: string; workspaceId: string | null };

const GLOBAL_SCOPE = 'global';

function workspaceScope(workspaceId: string): string {
  return `workspace:${workspaceId}`;
}

export function storageAvailable(): boolean {
  return Boolean(runtimeEnv.STORAGE);
}

function bucket(): R2Bucket | null {
  return runtimeEnv.STORAGE ?? null;
}

async function ensureMeters(workspaceId: string): Promise<void> {
  const now = Date.now();
  const period = storagePeriod();
  const database = await db();
  await database.batch([
    database
      .prepare(
        `INSERT OR IGNORE INTO storage_meter
         (scope, workspaceId, bytesUsed, bytesReserved, objectCount, period, classAWrites, classBReads, updatedAt)
         VALUES (?, NULL, 0, 0, 0, ?, 0, 0, ?)`,
      )
      .bind(GLOBAL_SCOPE, period, now),
    database
      .prepare(
        `INSERT OR IGNORE INTO storage_meter
         (scope, workspaceId, bytesUsed, bytesReserved, objectCount, period, classAWrites, classBReads, updatedAt)
         VALUES (?, ?, 0, 0, 0, ?, 0, 0, ?)`,
      )
      .bind(workspaceScope(workspaceId), workspaceId, period, now),
    database
      .prepare(
        `UPDATE storage_meter SET period = ?, classAWrites = 0, classBReads = 0, updatedAt = ?
         WHERE scope IN (?, ?) AND period <> ?`,
      )
      .bind(period, now, GLOBAL_SCOPE, workspaceScope(workspaceId), period),
  ]);
}

async function meter(scope: string): Promise<MeterRow> {
  const row = await queryOne<MeterRow>(
    `SELECT scope, workspaceId, bytesUsed, bytesReserved, objectCount,
            period, classAWrites, classBReads, updatedAt
     FROM storage_meter WHERE scope = ?`,
    scope,
  );
  if (!row) throw new Error(`Storage meter ${scope} was not initialized.`);
  return row;
}

function changed(result: D1Result): boolean {
  return (result.meta.changes ?? 0) > 0;
}

async function reserveUpload(
  workspaceId: string,
  size: number,
): Promise<string | null> {
  await ensureMeters(workspaceId);
  const now = Date.now();
  const workspace = workspaceScope(workspaceId);

  const globalResult = await execute(
    `UPDATE storage_meter
     SET bytesReserved = bytesReserved + ?, classAWrites = classAWrites + 1, updatedAt = ?
     WHERE scope = ?
       AND bytesUsed + bytesReserved + ? <= ?
       AND objectCount < ?
       AND classAWrites < ?`,
    size,
    now,
    GLOBAL_SCOPE,
    size,
    STORAGE_LIMITS.accountBytes,
    STORAGE_LIMITS.accountObjects,
    STORAGE_LIMITS.accountClassA,
  );
  if (!changed(globalResult))
    return 'The account R2 free-tier guard refused this upload.';

  const workspaceResult = await execute(
    `UPDATE storage_meter
     SET bytesReserved = bytesReserved + ?, classAWrites = classAWrites + 1, updatedAt = ?
     WHERE scope = ?
       AND bytesUsed + bytesReserved + ? <= ?
       AND objectCount < ?
       AND classAWrites < ?`,
    size,
    now,
    workspace,
    size,
    STORAGE_LIMITS.workspaceBytes,
    STORAGE_LIMITS.workspaceObjects,
    STORAGE_LIMITS.workspaceClassA,
  );
  if (changed(workspaceResult)) return null;

  await execute(
    `UPDATE storage_meter
     SET bytesReserved = MAX(0, bytesReserved - ?), classAWrites = MAX(0, classAWrites - 1), updatedAt = ?
     WHERE scope = ?`,
    size,
    Date.now(),
    GLOBAL_SCOPE,
  );
  return 'This workspace R2 free-tier guard refused this upload.';
}

async function releaseUpload(
  workspaceId: string,
  size: number,
  undoOperation: boolean,
): Promise<void> {
  const operation = undoOperation
    ? ', classAWrites = MAX(0, classAWrites - 1)'
    : '';
  await execute(
    `UPDATE storage_meter
     SET bytesReserved = MAX(0, bytesReserved - ?), updatedAt = ?${operation}
     WHERE scope IN (?, ?)`,
    size,
    Date.now(),
    GLOBAL_SCOPE,
    workspaceScope(workspaceId),
  );
}

export async function listStorage(workspaceId: string): Promise<StorageState> {
  await ensureMeters(workspaceId);
  const [objects, usage] = await Promise.all([
    query<StorageObject>(
      `SELECT id, name, contentType, size, etag, uploadedBy, createdAt
       FROM storage_object WHERE workspaceId = ? ORDER BY createdAt DESC`,
      workspaceId,
    ),
    meter(workspaceScope(workspaceId)),
  ]);

  return {
    available: storageAvailable(),
    bucket: storageAvailable() ? 'ysd-zero-cloud-storage' : null,
    access: 'private',
    objects,
    usage: {
      bytesUsed: usage.bytesUsed,
      bytesReserved: usage.bytesReserved,
      objectCount: usage.objectCount,
      period: usage.period,
      classAWrites: usage.classAWrites,
      classBReads: usage.classBReads,
      updatedAt: usage.updatedAt,
    },
    limits: STORAGE_LIMITS,
  };
}

export type UploadResult =
  | { ok: true; object: StorageObject }
  | { ok: false; status: number; error: string };

export async function uploadObject(input: {
  workspaceId: string;
  actor: string;
  file: File;
}): Promise<UploadResult> {
  const target = bucket();
  if (!target) {
    return {
      ok: false,
      status: 503,
      error:
        'R2 is implementation-ready but is not enabled for this Cloudflare account.',
    };
  }

  const validation = validateObject(input.file.name, input.file.size);
  if (!validation.ok)
    return { ok: false, status: 400, error: validation.error };

  const capacity = await assertResourceCapacity(input.workspaceId, 'storageMetadata');
  if (!capacity.ok) return { ok: false, status: 409, error: capacity.error };

  const refusal = await reserveUpload(input.workspaceId, input.file.size);
  if (refusal) return { ok: false, status: 409, error: refusal };

  const id = createId('obj');
  const name = safeObjectName(input.file.name);
  const key = `${input.workspaceId}/${id}/${encodeURIComponent(name)}`;
  let stored: R2Object;

  try {
    stored = await target.put(key, input.file.stream(), {
      httpMetadata: {
        contentType: input.file.type || 'application/octet-stream',
        contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
        cacheControl: 'private, no-store',
      },
      customMetadata: { workspaceId: input.workspaceId, objectId: id },
      storageClass: 'Standard',
    });
  } catch {
    await releaseUpload(input.workspaceId, input.file.size, true);
    return { ok: false, status: 502, error: 'R2 did not accept the upload.' };
  }

  const object: StorageObject = {
    id,
    name,
    contentType: input.file.type || 'application/octet-stream',
    size: stored.size,
    etag: stored.etag,
    uploadedBy: input.actor,
    createdAt: stored.uploaded.getTime(),
  };

  try {
    const database = await db();
    await database.batch([
      database
        .prepare(
          `INSERT INTO storage_object
           (id, workspaceId, r2Key, name, contentType, size, etag, uploadedBy, createdAt)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          object.id,
          input.workspaceId,
          key,
          object.name,
          object.contentType,
          object.size,
          object.etag,
          object.uploadedBy,
          object.createdAt,
        ),
      database
        .prepare(
          `UPDATE storage_meter
           SET bytesReserved = MAX(0, bytesReserved - ?), bytesUsed = bytesUsed + ?,
               objectCount = objectCount + 1, updatedAt = ?
           WHERE scope IN (?, ?)`,
        )
        .bind(
          input.file.size,
          object.size,
          Date.now(),
          GLOBAL_SCOPE,
          workspaceScope(input.workspaceId),
        ),
    ]);
  } catch {
    await target.delete(key).catch(() => undefined);
    await releaseUpload(input.workspaceId, input.file.size, true);
    return {
      ok: false,
      status: 500,
      error: 'The upload metadata could not be committed.',
    };
  }

  await writeLog({
    workspaceId: input.workspaceId,
    source: 'storage',
    message: `Stored ${object.name} (${object.size.toLocaleString('en-US')} bytes)`,
    actor: input.actor,
    resource: object.id,
  });
  return { ok: true, object };
}

type StoredObject = StorageObject & { r2Key: string; workspaceId: string };

async function storedObject(
  workspaceId: string,
  id: string,
): Promise<StoredObject | null> {
  return queryOne<StoredObject>(
    `SELECT id, workspaceId, r2Key, name, contentType, size, etag, uploadedBy, createdAt
     FROM storage_object WHERE workspaceId = ? AND id = ?`,
    workspaceId,
    id,
  );
}

async function reserveOperation(
  workspaceId: string,
  kind: 'read' | 'write',
): Promise<boolean> {
  await ensureMeters(workspaceId);
  const column = kind === 'read' ? 'classBReads' : 'classAWrites';
  const accountLimit =
    kind === 'read'
      ? STORAGE_LIMITS.accountClassB
      : STORAGE_LIMITS.accountClassA;
  const workspaceLimit =
    kind === 'read'
      ? STORAGE_LIMITS.workspaceClassB
      : STORAGE_LIMITS.workspaceClassA;
  const now = Date.now();

  const global = await execute(
    `UPDATE storage_meter SET ${column} = ${column} + 1, updatedAt = ?
     WHERE scope = ? AND ${column} < ?`,
    now,
    GLOBAL_SCOPE,
    accountLimit,
  );
  if (!changed(global)) return false;

  const local = await execute(
    `UPDATE storage_meter SET ${column} = ${column} + 1, updatedAt = ?
     WHERE scope = ? AND ${column} < ?`,
    now,
    workspaceScope(workspaceId),
    workspaceLimit,
  );
  if (changed(local)) return true;

  await execute(
    `UPDATE storage_meter SET ${column} = MAX(0, ${column} - 1), updatedAt = ? WHERE scope = ?`,
    Date.now(),
    GLOBAL_SCOPE,
  );
  return false;
}

export type DownloadResult =
  | { ok: true; object: StorageObject; body: R2ObjectBody }
  | { ok: false; status: number; error: string };

export async function downloadObject(
  workspaceId: string,
  id: string,
): Promise<DownloadResult> {
  const target = bucket();
  if (!target) return { ok: false, status: 503, error: 'R2 is not enabled.' };
  const metadata = await storedObject(workspaceId, id);
  if (!metadata) return { ok: false, status: 404, error: 'Object not found.' };
  if (!(await reserveOperation(workspaceId, 'read'))) {
    return {
      ok: false,
      status: 429,
      error: 'The monthly storage read guard has been reached.',
    };
  }
  const body = await target.get(metadata.r2Key);
  if (!body)
    return { ok: false, status: 404, error: 'Object content is missing.' };
  return { ok: true, object: metadata, body };
}

export async function deleteObject(input: {
  workspaceId: string;
  id: string;
  actor: string;
}): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  const target = bucket();
  if (!target) return { ok: false, status: 503, error: 'R2 is not enabled.' };
  const object = await storedObject(input.workspaceId, input.id);
  if (!object) return { ok: false, status: 404, error: 'Object not found.' };
  if (!(await reserveOperation(input.workspaceId, 'write'))) {
    return {
      ok: false,
      status: 429,
      error: 'The monthly storage write guard has been reached.',
    };
  }

  await target.delete(object.r2Key);
  const database = await db();
  await database.batch([
    database
      .prepare('DELETE FROM storage_object WHERE workspaceId = ? AND id = ?')
      .bind(input.workspaceId, input.id),
    database
      .prepare(
        `UPDATE storage_meter
         SET bytesUsed = MAX(0, bytesUsed - ?), objectCount = MAX(0, objectCount - 1), updatedAt = ?
         WHERE scope IN (?, ?)`,
      )
      .bind(
        object.size,
        Date.now(),
        GLOBAL_SCOPE,
        workspaceScope(input.workspaceId),
      ),
  ]);

  await writeLog({
    workspaceId: input.workspaceId,
    source: 'storage',
    level: 'WARN',
    message: `Deleted ${object.name}`,
    actor: input.actor,
    resource: object.id,
  });
  return { ok: true };
}

export async function storageShieldState(workspaceId: string): Promise<{
  available: boolean;
  private: true;
  usage: StorageUsage;
}> {
  const state = await listStorage(workspaceId);
  return { available: state.available, private: true, usage: state.usage };
}
