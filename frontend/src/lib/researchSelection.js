// The research chosen on the Overview page, remembered per browser so the Scans
// page can default to it. A research is identified by any of its scans (the
// backend groups scans by research_id, program, or repository).

export const SELECTED_RESEARCH_KEY = 'open-kritt.selectedResearch';

const SCAN_ID = /^\d+$/;

function defaultStorage() {
  try {
    return typeof window === 'undefined' ? undefined : window.localStorage;
  } catch {
    return undefined;
  }
}

export function readSelectedResearch(storage = defaultStorage()) {
  try {
    const value = storage?.getItem(SELECTED_RESEARCH_KEY) || '';
    return SCAN_ID.test(value) ? value : '';
  } catch {
    return '';
  }
}

export function writeSelectedResearch(scanId, storage = defaultStorage()) {
  try {
    if (SCAN_ID.test(`${scanId}`)) storage?.setItem(SELECTED_RESEARCH_KEY, `${scanId}`);
  } catch {
    // Storage can be unavailable (private mode, blocked site data); the page still works.
  }
}

export function clearSelectedResearch(storage = defaultStorage()) {
  try {
    storage?.removeItem(SELECTED_RESEARCH_KEY);
  } catch {
    // See writeSelectedResearch.
  }
}

// The research the scan list should show: an explicit link wins, then the
// selection made on Overview, then the current research. null means all scans.
export function scanListResearch({ urlResearch = '', stored = '', showAll = false } = {}) {
  if (showAll) return null;
  return urlResearch || stored || 'current';
}

export function researchName(scan) {
  const configuration =
    scan?.configuration && typeof scan.configuration === 'object' && !Array.isArray(scan.configuration)
      ? scan.configuration
      : {};
  return (
    configuration.program || configuration.research_id || scan?.repoDisplay || scan?.repoFull || `Scan ${scan?.id}`
  );
}

export function researchOptionLabel(scan) {
  return `${researchName(scan)} · latest #${scan.id} · ${scan.status}`;
}
