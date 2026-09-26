import { describe, expect, it } from 'vitest';

import { overviewKpis } from './Overview.jsx';

describe('overview KPIs', () => {
  it('report engine-verified counts for the selected research', () => {
    const kpis = overviewKpis({
      focusScan: { id: '26', repoFull: 'enzyme-onyx', status: 'running', progressLabel: '40%' },
      keptCount: 3,
      impactProvenCount: 1,
      exploitableCount: 7,
    });
    expect(kpis.map((kpi) => [kpi.label, kpi.value])).toEqual([
      ['Latest run', '#26'],
      ['Status', 'running'],
      ['D3 kept', 3],
      ['Impact proven', 1],
    ]);
  });

  it('shows zero verified counts when the backend has none yet', () => {
    const kpis = overviewKpis({ focusScan: null });
    expect(kpis.slice(2).map((kpi) => kpi.value)).toEqual([0, 0]);
  });
});
