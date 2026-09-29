import { describe, expect, it } from 'vitest';

import {
  SELECTED_RESEARCH_KEY,
  clearSelectedResearch,
  readSelectedResearch,
  researchOptionLabel,
  scanListResearch,
  writeSelectedResearch,
} from './researchSelection.js';

function memoryStorage() {
  const values = new Map();
  return {
    getItem: (key) => (values.has(key) ? values.get(key) : null),
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  };
}

const throwingStorage = {
  getItem: () => {
    throw new Error('blocked');
  },
  setItem: () => {
    throw new Error('blocked');
  },
  removeItem: () => {
    throw new Error('blocked');
  },
};

describe('selected research storage', () => {
  it('round-trips a numeric scan id under a stable key', () => {
    const storage = memoryStorage();
    writeSelectedResearch(26, storage);
    expect(storage.getItem(SELECTED_RESEARCH_KEY)).toBe('26');
    expect(readSelectedResearch(storage)).toBe('26');
    clearSelectedResearch(storage);
    expect(readSelectedResearch(storage)).toBe('');
  });

  it('ignores malformed stored values and unavailable storage', () => {
    const storage = memoryStorage();
    storage.setItem(SELECTED_RESEARCH_KEY, 'not-a-scan');
    expect(readSelectedResearch(storage)).toBe('');
    expect(readSelectedResearch(throwingStorage)).toBe('');
    expect(() => writeSelectedResearch('26', throwingStorage)).not.toThrow();
    expect(() => clearSelectedResearch(throwingStorage)).not.toThrow();
    expect(readSelectedResearch(undefined)).toBe('');
  });
});

describe('scan list research scope', () => {
  it('prefers an explicit link, then the stored selection, then the current research', () => {
    expect(scanListResearch({ urlResearch: '22', stored: '26' })).toBe('22');
    expect(scanListResearch({ stored: '26' })).toBe('26');
    expect(scanListResearch({})).toBe('current');
  });

  it('is unscoped when all scans are requested', () => {
    expect(scanListResearch({ urlResearch: '22', stored: '26', showAll: true })).toBe(null);
  });
});

describe('research option labels', () => {
  it('names the research and identifies its latest scan', () => {
    expect(
      researchOptionLabel({
        id: '26',
        status: 'running',
        repoFull: 'enzyme-onyx',
        configuration: { program: 'Immunefi Enzyme Onyx' },
      })
    ).toBe('Immunefi Enzyme Onyx · latest #26 · running');
  });

  it('falls back to the research id and then the repository', () => {
    expect(researchOptionLabel({ id: '5', status: 'completed', configuration: { research_id: 'somnia-2025' } })).toBe(
      'somnia-2025 · latest #5 · completed'
    );
    expect(researchOptionLabel({ id: '7', status: 'failed', repoDisplay: 'owner/repo' })).toBe(
      'owner/repo · latest #7 · failed'
    );
  });
});
