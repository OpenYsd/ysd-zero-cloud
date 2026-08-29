import assert from 'node:assert/strict';
import test from 'node:test';
import {
  STORAGE_LIMITS,
  canRead,
  canReserveUpload,
  safeObjectName,
  storagePeriod,
  validateObject,
  type StorageQuota,
} from '../lib/storage.ts';

const EMPTY: StorageQuota = {
  bytesUsed: 0,
  bytesReserved: 0,
  objectCount: 0,
  classAWrites: 0,
  classBReads: 0,
};

void test('object names are path-safe and bounded', () => {
  assert.equal(safeObjectName('../private\\token.txt'), '..-private-token.txt');
  assert.equal(safeObjectName('\u0000\n'), 'file');
  assert.ok(safeObjectName('x'.repeat(500)).length <= 180);
});

void test('individual uploads stop at the 10 MB Zero Mode ceiling', () => {
  assert.deepEqual(validateObject('empty.txt', 0), {
    ok: false,
    code: 'size',
    error: 'Empty files are not stored.',
  });
  assert.equal(validateObject('ok.bin', STORAGE_LIMITS.objectBytes).ok, true);
  assert.equal(
    validateObject('large.bin', STORAGE_LIMITS.objectBytes + 1).ok,
    false,
  );
});

void test('account and workspace byte guards include in-flight reservations', () => {
  assert.equal(
    canReserveUpload(
      {
        ...EMPTY,
        bytesUsed: STORAGE_LIMITS.accountBytes - 5,
        bytesReserved: 4,
      },
      EMPTY,
      2,
    ).ok,
    false,
  );
  assert.equal(
    canReserveUpload(
      EMPTY,
      { ...EMPTY, bytesUsed: STORAGE_LIMITS.workspaceBytes - 1 },
      2,
    ).ok,
    false,
  );
});

void test('object and operation ceilings have no paid overflow path', () => {
  assert.equal(
    canReserveUpload(
      EMPTY,
      { ...EMPTY, objectCount: STORAGE_LIMITS.workspaceObjects },
      1,
    ).ok,
    false,
  );
  assert.equal(
    canReserveUpload(
      { ...EMPTY, classAWrites: STORAGE_LIMITS.accountClassA },
      EMPTY,
      1,
    ).ok,
    false,
  );
  assert.equal(
    canRead(EMPTY, { ...EMPTY, classBReads: STORAGE_LIMITS.workspaceClassB })
      .ok,
    false,
  );
});

void test('monthly periods are UTC and deterministic', () => {
  assert.equal(storagePeriod(new Date('2026-08-29T23:59:00Z')), '2026-08');
});
