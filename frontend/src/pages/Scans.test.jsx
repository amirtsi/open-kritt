import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { api } from '../api/client.js';
import { ResearchScopeBar } from './Scans.jsx';

const research = { anchorScanId: '26', label: 'Immunefi Enzyme Onyx', requestedFound: true, scanCount: 4 };

function render(props) {
  return renderToStaticMarkup(
    <MemoryRouter>
      <ResearchScopeBar {...props} />
    </MemoryRouter>
  );
}

describe('ResearchScopeBar', () => {
  it('names the research in scope and offers every scan', () => {
    const html = render({ research, showAll: false });
    expect(html).toContain('Immunefi Enzyme Onyx');
    expect(html).toContain('4 scans');
    expect(html).toContain('href="/scans?all=1"');
  });

  it('offers a way back to the research when showing every scan', () => {
    const html = render({ research, showAll: true });
    expect(html).toContain('All scans');
    expect(html).toContain('href="/scans"');
  });

  it('still offers a way back when every scan is shown before a research was loaded', () => {
    const html = render({ research: null, showAll: true });
    expect(html).toContain('Back to the selected research');
    expect(html).toContain('href="/scans"');
  });

  it('renders nothing before the research is known', () => {
    expect(render({ research: null, showAll: false })).toBe('');
  });
});

describe('scan page requests', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('sends the research scope with the page query', async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ items: [] }), { status: 200 }));
    vi.stubGlobal('fetch', fetch);

    await api.scanPage({ status: 'running', page: 2, pageSize: 6, research: 'current' });

    const url = new URL(fetch.mock.calls[0][0], 'http://localhost');
    expect(url.pathname).toMatch(/\/scans$/);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      page: '2',
      pageSize: '6',
      status: 'running',
      research: 'current',
    });
  });
});
