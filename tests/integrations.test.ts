import assert from 'node:assert/strict';
import test from 'node:test';
import {
  getIntegrationCatalog,
  hasCloudflareApi,
  hasGithubOAuth,
  hasGithubToken,
} from '../lib/integrations.ts';
import { parseRepository } from '../lib/server/github.ts';

void test('an empty environment leaves every integration in mock mode', () => {
  const catalog = getIntegrationCatalog({});
  assert.ok(catalog.length > 0);
  assert.ok(catalog.every((entry) => entry.status === 'mock'));
});

void test('a binding marks its integration as bound', () => {
  const catalog = getIntegrationCatalog({ DB: {}, STORAGE: {} });
  const d1 = catalog.find((entry) => entry.id === 'cloudflare-d1');
  assert.equal(d1?.status, 'bound');
  assert.equal(d1?.binding, 'DB');
  assert.equal(
    catalog.find((entry) => entry.id === 'cloudflare-r2')?.status,
    'bound',
  );
});

void test('email can be deliberately gated until an owned domain exists', () => {
  const catalog = getIntegrationCatalog({
    YSD_EMAIL_VERIFICATION_MODE: 'disabled-no-domain',
  });
  assert.equal(catalog.find((entry) => entry.id === 'email')?.status, 'gated');
});

void test('an integration needs every key before it counts as configured', () => {
  const partial = getIntegrationCatalog({ CLOUDFLARE_API_TOKEN: 'token' });
  assert.equal(
    partial.find((entry) => entry.id === 'cloudflare')?.status,
    'mock',
  );

  const complete = getIntegrationCatalog({
    CLOUDFLARE_API_TOKEN: 'token',
    CLOUDFLARE_ACCOUNT_ID: 'account',
  });
  assert.equal(
    complete.find((entry) => entry.id === 'cloudflare')?.status,
    'configured',
  );
});

void test('blank strings do not count as configuration', () => {
  const catalog = getIntegrationCatalog({ GITHUB_TOKEN: '   ' });
  assert.equal(catalog.find((entry) => entry.id === 'github')?.status, 'mock');
  assert.equal(hasGithubToken({ GITHUB_TOKEN: '   ' }), false);
});

void test('every integration is declared free-tier only', () => {
  for (const entry of getIntegrationCatalog({})) {
    assert.equal(
      entry.freeTierOnly,
      true,
      `${entry.id} must be free-tier only`,
    );
  }
});

void test('capability helpers agree with the catalog', () => {
  assert.equal(
    hasGithubOAuth({ GITHUB_CLIENT_ID: 'id', GITHUB_CLIENT_SECRET: 'secret' }),
    true,
  );
  assert.equal(hasGithubOAuth({ GITHUB_CLIENT_ID: 'id' }), false);
  assert.equal(
    hasCloudflareApi({ CLOUDFLARE_API_TOKEN: 't', CLOUDFLARE_ACCOUNT_ID: 'a' }),
    true,
  );
  assert.equal(hasCloudflareApi({}), false);
});

void test('repository references are parsed from the shapes an operator types', () => {
  const expected = { owner: 'OpenYsd', repo: 'ysd-zero-cloud' };
  assert.deepEqual(parseRepository('OpenYsd/ysd-zero-cloud'), expected);
  assert.deepEqual(parseRepository('  OpenYsd/ysd-zero-cloud  '), expected);
  assert.deepEqual(
    parseRepository('https://github.com/OpenYsd/ysd-zero-cloud'),
    expected,
  );
  assert.deepEqual(
    parseRepository('https://github.com/OpenYsd/ysd-zero-cloud.git'),
    expected,
  );
  // Branches and commits travel in separate validated fields; deep links are
  // never silently truncated into a different source identity.
  assert.equal(
    parseRepository('https://github.com/OpenYsd/ysd-zero-cloud/tree/main'),
    null,
  );
});

void test('a repository reference that could reshape a URL is refused', () => {
  assert.equal(parseRepository('not-a-repository'), null);
  assert.equal(parseRepository(''), null);
  assert.equal(parseRepository('owner/re?po'), null);
  assert.equal(parseRepository('ow ner/repo'), null);
  assert.equal(parseRepository('owner/repo#fragment'), null);
});
