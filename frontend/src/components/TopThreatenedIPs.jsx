import React from 'react';
import { CrosshairIcon, ShieldIcon } from './Icons';

export function TopThreatenedIPs({ dashboardData }) {
  const topIPs = dashboardData?.top_source_ips || [];

  return (
    <div className="soc-card">
      <div className="soc-card-header">
        <div className="soc-card-title">
          <CrosshairIcon size={18} color="#06B6D4" />
          <span>TOP ACTIVE & THREATENED SOURCE IPS</span>
        </div>
        <span className="soc-card-subtitle">Real-time IP intelligence</span>
      </div>

      {topIPs.length === 0 ? (
        <div style={{ padding: '2rem', textAlign: 'center', color: '#64748B', fontSize: '0.85rem' }}>
          No source IP activity recorded yet.
        </div>
      ) : (
        <div className="soc-table-container">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Rank</th>
                <th>Source IP</th>
                <th>Total Flows</th>
                <th>Threat Flows</th>
                <th>Threat Rate</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {topIPs.map((item, idx) => {
                const isThreat = item.threat_flows > 0;
                return (
                  <tr key={item.ip || idx}>
                    <td style={{ fontWeight: 700, color: '#94A3B8' }}>#{idx + 1}</td>
                    <td style={{ fontWeight: 600, color: '#F1F5F9', fontFamily: 'monospace' }}>{item.ip}</td>
                    <td>{item.total_flows}</td>
                    <td style={{ fontWeight: 600, color: isThreat ? '#EF4444' : '#10B981' }}>{item.threat_flows}</td>
                    <td>{item.threat_rate}%</td>
                    <td>
                      <span className={`badge ${isThreat ? 'badge-threat' : 'badge-benign'}`}>
                        {isThreat ? 'SUSPECT' : 'BENIGN'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
