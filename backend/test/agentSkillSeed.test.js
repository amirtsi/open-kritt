import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';

const seedSql = fs.readFileSync(new URL('../../database/init/014_seed_agent_skills.sql', import.meta.url), 'utf8');
const cloudflareUpdateSql = fs.readFileSync(
  new URL('../../database/init/034_update_cloudflare_security_audit_skill.sql', import.meta.url),
  'utf8'
);

test('agent skill seed declares every bundled skill idempotently', () => {
  const slugs = [...seedSql.matchAll(/INSERT INTO public\.agent_skills[\s\S]*?\nSELECT\s*\n\s*'([^']+)'/g)].map(
    (match) => match[1]
  );
  const guards = seedSql.match(/WHERE NOT EXISTS \(SELECT 1 FROM public\.agent_skills WHERE slug = '[^']+'\);/g) || [];

  assert.equal(slugs.length, 30);
  assert.equal(new Set(slugs).size, 30);
  assert.equal(guards.length, slugs.length);
  assert.ok(slugs.includes('cloudflare-security-audit'));
  assert.ok(slugs.includes('trail-of-bits-solana-scanner'));
  assert.ok(slugs.includes('trail-of-bits-zeroize-audit'));
});

test('cloudflare security-audit skill is upgraded idempotently with the full methodology', () => {
  // Forward-only, keyed by slug: applying it twice yields the same row.
  assert.match(cloudflareUpdateSql, /UPDATE public\.agent_skills/);
  assert.match(cloudflareUpdateSql, /WHERE slug = 'cloudflare-security-audit';/);
  assert.ok(!/INSERT INTO/.test(cloudflareUpdateSql), 'should update the existing row, not insert a duplicate');

  // The imported methodology is present (not the old thin bridge text).
  for (const marker of [
    'Attack classes',
    'Business logic',
    'Evidence discipline',
    'Target-type companions',
    'Validation discipline',
    'Anti-patterns',
  ]) {
    assert.ok(cloudflareUpdateSql.includes(marker), `missing methodology section: ${marker}`);
  }

  // Orchestration is intentionally excluded (Open-Kritt provides it).
  assert.match(cloudflareUpdateSql, /orchestration[\s\S]*omitted|omitted[\s\S]*orchestration/i);

  // Upstream attribution/license preserved.
  assert.match(cloudflareUpdateSql, /github\.com\/cloudflare\/security-audit-skill/);
  assert.match(cloudflareUpdateSql, /license_spdx = 'MIT'/);
});
