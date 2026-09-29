import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { ScanCard } from './Scans.jsx';

describe('ScanCard counts', () => {
  it('shows D3-kept findings instead of the D2 exploitable claim', () => {
    const out = renderToStaticMarkup(
      <MemoryRouter>
        <ScanCard
          scan={{
            id: '21',
            status: 'completed',
            repoFull: 'ssv-network',
            rawCandidates: 13,
            findings: 9,
            exploitable: 7,
            keptFindings: 2,
            age: '1d',
          }}
          to="/scans/21"
          busy={false}
          errorExpanded={false}
          onResume={() => {}}
          onToggleError={() => {}}
          onDelete={() => {}}
        />
      </MemoryRouter>
    );
    expect(out).toContain('D3 kept');
    expect(out).not.toContain('>exploitable<');
  });
});
