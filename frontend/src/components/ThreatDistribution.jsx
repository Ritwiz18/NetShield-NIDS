import React from 'react';
import { AlertTriangleIcon, CheckCircleIcon } from './Icons';

export function ThreatDistribution({ threatsData }) {
  const attackBreakdown = threatsData?.threats_by_type || {};
  const entries = Object.entries(attackBreakdown);
  const totalThreats = entries.reduce((sum, [_, count]) => sum + count, 0);

  if (entries.length === 0 || totalThreats === 0) {
    return (
      <div className="soc-card" style={{ height: '100%', minHeight: '260px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <CheckCircleIcon size={36} color="#10B981" />
        <p style={{ marginTop: '0.75rem', color: '#10B981', fontWeight: 700, fontSize: '0.9rem' }}>
          Zero Cyber Threats Detected
        </p>
        <p style={{ color: '#64748B', fontSize: '0.75rem', marginTop: '0.25rem', textAlign: 'center' }}>
          All active network flows are currently classified as BENIGN.
        </p>
      </div>
    );
  }

  // Pre-defined color palette for attack types
  const colors = ['#EF4444', '#F59E0B', '#A855F7', '#EC4899', '#6366F1', '#14B8A6', '#F97316'];

  return (
    <div className="soc-card">
      <div className="soc-card-header">
        <div className="soc-card-title">
          <AlertTriangleIcon size={18} color="#EF4444" />
          <span>ATTACK TYPE DISTRIBUTION</span>
        </div>
        <span className="badge badge-threat">
          {totalThreats} Threat(s)
        </span>
      </div>

      {/* Horizontal Bar Breakdown */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', marginTop: '0.5rem' }}>
        {entries.map(([attackType, count], idx) => {
          const pct = ((count / totalThreats) * 100).toFixed(1);
          const barColor = colors[idx % colors.length];

          return (
            <div key={attackType}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', fontWeight: 600, color: '#E2E8F0', marginBottom: '0.25rem' }}>
                <span>{attackType}</span>
                <span style={{ color: barColor }}>{count} ({pct}%)</span>
              </div>
              <div style={{ width: '100%', height: '8px', backgroundColor: '#1E293B', borderRadius: '4px', overflow: 'hidden' }}>
                <div
                  style={{
                    width: `${pct}%`,
                    height: '100%',
                    backgroundColor: barColor,
                    borderRadius: '4px',
                    transition: 'width 0.4s ease'
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
