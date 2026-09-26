import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { api } from '../api/client.js';
import { LiveActivity, LiveDropouts, LiveFunnel } from './ScanLive.jsx';

const html = (node) => renderToStaticMarkup(<MemoryRouter>{node}</MemoryRouter>);
const stage = (id, label, count, extra = {}) => ({
  id,
  label,
  count,
  status: 'counted',
  pending: 0,
  dropped: {},
  ...extra,
});

describe('LiveFunnel', () => {
  it('shows each verified stage with its count and dropped reasons', () => {
    const out = html(
      <LiveFunnel
        funnel={[
          stage('raw', 'Raw', 13),
          stage('canonical', 'Canonical', 9),
          stage('d3_kept', 'D3 kept', 2, { dropped: { false_positive: 5, out_of_scope: 2 } }),
        ]}
      />
    );
    expect(out).toContain('D3 kept');
    expect(out).toContain('>2<');
    expect(out).toContain('false_positive 5');
    expect(out).toContain('out_of_scope 2');
  });

  it('says waiting instead of zero before a stage has run', () => {
    const out = html(
      <LiveFunnel
        funnel={[stage('raw', 'Raw', 18), stage('canonical', 'Canonical', 0, { status: 'waiting', pending: 18 })]}
      />
    );
    expect(out).toContain('waiting');
    expect(out).toContain('18 pending');
  });
});

describe('scan live requests', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('loads the live view of a scan', async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ funnel: [] }), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    await api.scanLive('26');
    expect(new URL(fetch.mock.calls[0][0], 'http://localhost').pathname).toMatch(/\/scans\/26\/live$/);
  });
});

describe('LiveActivity', () => {
  it('marks a job that runs slower than usual and lists recent errors', () => {
    const out = html(
      <LiveActivity
        activity={{
          jobs: [
            {
              metadataId: '4',
              title: 'D4 · Local PoC',
              phaseLabel: 'Running harness',
              model: 'claude-opus-5',
              elapsedMs: 600_000,
              medianMs: 120_000,
              slow: true,
            },
            {
              metadataId: '5',
              title: 'D2 · Investigate',
              phaseLabel: 'Running harness',
              model: 'gpt-6-sol',
              elapsedMs: 30_000,
              medianMs: null,
              slow: false,
            },
          ],
          recentErrors: [
            {
              metadataId: '9',
              stage: 'step:281',
              status: 'failed',
              message: 'boom',
              at: '2026-09-26T12:00:00Z',
              recovered: true,
            },
          ],
        }}
      />
    );
    expect(out).toContain('D4 · Local PoC');
    expect(out).toContain('10m');
    expect(out.match(/slower than usual/g)).toHaveLength(1);
    expect(out).toContain('boom');
    expect(out).toContain('retried');
  });

  it('says so when nothing is running', () => {
    expect(html(<LiveActivity activity={{ jobs: [], recentErrors: [] }} />)).toContain('No active jobs');
  });
});

describe('LiveDropouts', () => {
  const section = (groups, more = 0) => ({ groups, more });
  const group = (key, count, entries, more = 0) => ({
    key,
    label: key,
    count,
    example: entries[0]?.detail || '',
    entries,
    more,
  });

  it('lists D3 rejections with links to findings and shows overflow counts', () => {
    const out = html(
      <LiveDropouts
        scanId="21"
        dropouts={{
          stubs: section([], 3),
          d3: section([
            group('false_positive', 2, [{ id: '1600', summary: 'Fee rounding', detail: 'guard holds' }], 1),
          ]),
          blockers: section([
            group('novelty is not verified', 1, [{ id: '1606', summary: 'Oracle leaf', detail: 'novelty' }]),
          ]),
        }}
      />
    );
    expect(out).toContain('false_positive');
    expect(out).toContain('href="/scans/21/vulnerabilities/1600"');
    expect(out).toContain('+1 more');
    expect(out).toContain('+3 more groups');
    expect(out).toContain('novelty is not verified');
  });

  it('renders model text as plain text', () => {
    const out = html(
      <LiveDropouts
        scanId="21"
        dropouts={{
          stubs: section([]),
          d3: section([
            group('false_positive', 1, [
              { id: '1', summary: '<img src=x onerror=alert(1)>', detail: '<script>x</script>' },
            ]),
          ]),
          blockers: section([]),
        }}
      />
    );
    expect(out).not.toContain('<script>');
    expect(out).not.toContain('<img');
    expect(out).toContain('&lt;script&gt;');
  });
});
