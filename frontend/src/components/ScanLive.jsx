import { Link } from 'react-router-dom';
import { api } from '../api/client.js';
import { useFetch } from '../lib/useFetch.js';
import { ErrorState, Spinner } from './ui.jsx';

// Live view of one scan: engine-verified funnel, current activity, and grouped
// dropout reasons. Model-written text is always rendered as plain text.

const LIVE_POLL_MS = 5000;

const box = {
  border: '1px solid var(--border)',
  borderRadius: 10,
  background: 'var(--surface)',
  padding: '12px 14px',
};
const heading = { fontSize: 13, fontWeight: 600, marginBottom: 8 };
const muted = { color: 'var(--text-2)', fontSize: 12.5 };

function duration(ms) {
  if (ms === null || ms === undefined) return '—';
  const minutes = Math.floor(ms / 60_000);
  if (minutes >= 60) return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
  if (minutes >= 1) return `${minutes}m`;
  return `${Math.max(0, Math.round(ms / 1000))}s`;
}

export function LiveFunnel({ funnel }) {
  return (
    <div
      style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.max(1, funnel.length)}, minmax(0, 1fr))`, gap: 8 }}
    >
      {funnel.map((stage) => {
        const dropped = Object.entries(stage.dropped || {});
        return (
          <div key={stage.id} style={{ ...box, padding: '10px 12px' }}>
            <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', textTransform: 'uppercase' }}>
              {stage.label}
            </div>
            <div style={{ fontSize: 22, fontWeight: 600, margin: '2px 0' }}>
              {stage.status === 'waiting' ? (
                <span style={{ fontSize: 14, color: 'var(--text-2)' }}>waiting</span>
              ) : (
                stage.count
              )}
            </div>
            {stage.pending > 0 && <div style={muted}>{stage.pending} pending</div>}
            {dropped.map(([reason, count]) => (
              <div key={reason} style={{ ...muted, color: 'var(--fail)' }}>
                {reason} {count}
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}

export function LiveActivity({ activity }) {
  const { jobs = [], recentErrors = [] } = activity || {};
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
      <div style={box}>
        <div style={heading}>Active jobs</div>
        {jobs.length === 0 && <div style={muted}>No active jobs.</div>}
        {jobs.map((job) => (
          <div
            key={job.metadataId}
            style={{ display: 'flex', justifyContent: 'space-between', gap: 8, padding: '3px 0' }}
          >
            <span style={{ fontSize: 12.5 }}>
              {job.title} <span style={muted}>· {job.phaseLabel}</span>
            </span>
            <span style={{ fontSize: 12.5, whiteSpace: 'nowrap' }}>
              {duration(job.elapsedMs)}
              {job.slow && (
                <span style={{ color: 'var(--fail)' }} title={`Median ${duration(job.medianMs)}`}>
                  {' '}
                  · slower than usual
                </span>
              )}
            </span>
          </div>
        ))}
      </div>
      <div style={box}>
        <div style={heading}>Recent errors</div>
        {recentErrors.length === 0 && <div style={muted}>No recent errors.</div>}
        {recentErrors.map((row) => (
          <div key={row.metadataId} style={{ fontSize: 12.5, padding: '3px 0' }}>
            <span style={{ color: row.recovered ? 'var(--text-2)' : 'var(--fail)' }}>
              {row.status}
              {row.recovered ? ' · retried' : ''}
            </span>{' '}
            <span style={muted}>{row.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DropoutSection({ title, section, scanId, linkFindings }) {
  const groups = section?.groups || [];
  return (
    <div style={box}>
      <div style={heading}>{title}</div>
      {groups.length === 0 && !section?.more && <div style={muted}>None yet.</div>}
      {groups.map((group) => (
        <details key={group.key} style={{ padding: '3px 0' }}>
          <summary style={{ fontSize: 12.5, cursor: 'pointer' }}>
            {group.label} <span style={muted}>· {group.count}</span>
          </summary>
          {!linkFindings && group.example && <div style={{ ...muted, margin: '4px 0 4px 12px' }}>{group.example}</div>}
          {linkFindings &&
            group.entries.map((entry) => (
              <div key={entry.id} style={{ margin: '4px 0 4px 12px', fontSize: 12.5 }}>
                <Link to={`/scans/${scanId}/vulnerabilities/${entry.id}`} style={{ color: 'var(--accent)' }}>
                  #{entry.id} {entry.summary}
                </Link>
                {entry.detail && <div style={muted}>{entry.detail}</div>}
              </div>
            ))}
          {group.more > 0 && <div style={{ ...muted, marginLeft: 12 }}>+{group.more} more</div>}
        </details>
      ))}
      {section?.more > 0 && <div style={muted}>+{section.more} more groups</div>}
    </div>
  );
}

export function LiveDropouts({ dropouts, scanId }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 8 }}>
      <DropoutSection title="Closed as stubs" section={dropouts?.stubs} scanId={scanId} linkFindings={false} />
      <DropoutSection title="Rejected by D3" section={dropouts?.d3} scanId={scanId} linkFindings />
      <DropoutSection title="Blocked at the readiness gate" section={dropouts?.blockers} scanId={scanId} linkFindings />
    </div>
  );
}

export default function ScanLivePanel({ scanId, active = false }) {
  const { data, loading, error, reload } = useFetch(() => api.scanLive(scanId), [scanId], {
    pollMs: active ? LIVE_POLL_MS : 0,
  });
  return (
    <details open style={{ ...box, padding: '12px 14px', marginBottom: 16 }}>
      <summary style={{ fontSize: 15, fontWeight: 600, cursor: 'pointer' }}>Live tracking</summary>
      {loading && !data && <Spinner />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <div style={{ display: 'grid', gap: 10, marginTop: 10 }}>
          <LiveFunnel funnel={data.funnel || []} />
          <LiveActivity activity={data.activity} />
          <LiveDropouts dropouts={data.dropouts} scanId={scanId} />
        </div>
      )}
    </details>
  );
}
