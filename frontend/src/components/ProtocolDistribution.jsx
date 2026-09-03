import React from 'react';
import { BarChartIcon } from './Icons';

export function ProtocolDistribution({ dashboardData }) {
  const protoMap = dashboardData?.protocol_breakdown || { TCP: 0, UDP: 0, ICMP: 0, Other: 0 };
  const total = Object.values(protoMap).reduce((a, b) => a + b, 0);

  const protos = [
    { name: 'TCP', count: protoMap.TCP || 0, color: '#38BDF8' },
    { name: 'UDP', count: protoMap.UDP || 0, color: '#A855F7' },
    { name: 'ICMP', count: protoMap.ICMP || 0, color: '#F59E0B' },
    { name: 'Other', count: protoMap.Other || 0, color: '#64748B' },
  ];

  return (
    <div className="soc-card">
      <div className="soc-card-header">
        <div className="soc-card-title">
          <BarChartIcon size={18} color="#38BDF8" />
          <span>PROTOCOL DISTRIBUTION</span>
        </div>
        <span className="soc-card-subtitle">{total} Total Flows</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', marginTop: '0.5rem' }}>
        {protos.map((p) => {
          const pct = total > 0 ? ((p.count / total) * 100).toFixed(1) : 0;
          return (
            <div key={p.name}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', fontWeight: 600, color: '#E2E8F0', marginBottom: '0.25rem' }}>
                <span>{p.name}</span>
                <span style={{ color: p.color }}>{p.count} ({pct}%)</span>
              </div>
              <div style={{ width: '100%', height: '8px', backgroundColor: '#1E293B', borderRadius: '4px', overflow: 'hidden' }}>
                <div
                  style={{
                    width: `${pct}%`,
                    height: '100%',
                    backgroundColor: p.color,
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
