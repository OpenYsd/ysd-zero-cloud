import { readFile } from 'node:fs/promises';
import { inspectDeploymentConfig } from '../lib/deploy-guard.ts';

const path = 'dist/server/wrangler.json';
const config = JSON.parse(await readFile(path, 'utf8')) as Record<
  string,
  unknown
>;
const estimatedMonthlyCost = Number(
  process.env.YSD_ESTIMATED_MONTHLY_COST ?? 'NaN',
);
const expectedD1DatabaseId = process.env.YSD_D1_DATABASE_ID?.trim() ?? '';

const decision = inspectDeploymentConfig(config, {
  freeTierVerified: process.env.YSD_FREE_TIER_VERIFIED === 'true',
  estimatedMonthlyCost,
  expectedD1DatabaseId,
});

if (!decision.allowed) {
  throw new Error(`ZERO_MODE_BLOCKED: ${decision.reasons.join(' ')}`);
}

console.log('Zero Mode verified the generated deployment at $0.00/month.');
