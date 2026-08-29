import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isLiveSection,
  isLogLevel,
  isLogSource,
  isSecretEnvironment,
  isSection,
  isWorkspaceSetting,
  LIVE_SECTIONS,
  SECTIONS,
} from '../lib/domain.ts';

void test('section guards accept only real sections', () => {
  assert.equal(isSection('shield'), true);
  assert.equal(isSection('databases'), true);
  assert.equal(isSection('not-a-section'), false);
  assert.equal(isSection(''), false);
  assert.equal(isSection('__proto__'), false);
});

void test('every live section is a real section', () => {
  for (const section of LIVE_SECTIONS) {
    assert.ok(
      SECTIONS.includes(section),
      `${section} is not in the section catalog`,
    );
    assert.equal(isLiveSection(section), true);
  }
});

void test('preview sections are not reported as live', () => {
  for (const section of ['ai', 'game-servers'] as const) {
    assert.equal(
      isLiveSection(section),
      false,
      `${section} should be a preview`,
    );
  }
});

void test('storage, networking, and nodes are live surfaces', () => {
  assert.equal(isLiveSection('storage'), true);
  assert.equal(isLiveSection('networking'), true);
  assert.equal(isLiveSection('nodes'), true);
});

void test('log guards reject anything outside the catalog', () => {
  assert.equal(isLogLevel('WARN'), true);
  assert.equal(isLogLevel('warn'), false);
  assert.equal(isLogSource('shield'), true);
  assert.equal(isLogSource('storage'), true);
  assert.equal(isLogSource('networking'), true);
  assert.equal(isLogSource('node'), true);
  assert.equal(isLogSource('anything-else'), false);
});

void test('workspace setting guard gates the column name used in SQL', () => {
  assert.equal(isWorkspaceSetting('zeroMode'), true);
  assert.equal(isWorkspaceSetting('previewDeployments'), true);
  // This value reaches an UPDATE statement, so the guard is the injection
  // boundary rather than a convenience.
  assert.equal(isWorkspaceSetting('zeroMode = 0, name'), false);
  assert.equal(isWorkspaceSetting('ownerUserId'), false);
});

void test('secret environment guard rejects unknown environments', () => {
  assert.equal(isSecretEnvironment('Production'), true);
  assert.equal(isSecretEnvironment('production'), false);
  assert.equal(isSecretEnvironment('Staging'), false);
});
