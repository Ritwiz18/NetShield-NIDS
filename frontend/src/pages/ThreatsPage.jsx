import React from 'react';
import { ThreatDistribution } from '../components/ThreatDistribution';
import { AlertTriangleIcon, ShieldIcon } from '../components/Icons';

export function ThreatsPage({ threatsData, dashboardData }) {
  const totalThreats = threatsData?.total_threats ?? 0;
  const confirmed = threatsData?.confirmed_threats ?? 0;
  const review = threatsData?.review_threats ?? 0;
  const uncertain = threatsData?.uncertain_threats ?? 0;
  const sevDist = threatsData?.severity_distribution || { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  const threatEvents = threatsData?.recent_threat_events || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Threat Summary Grid */}
      <div className="grid-cols-4">
        <div className="soc-card">
          <span style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 700 }}>TOTAL THREATS</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#EF4444' }}>{totalThreats}</div>
          <span style={{ fontSize: '0.7rem', color: '#64748B' }}>Confirmed & Review Anomalies</span>
        </div>
        <div className="soc-card">
          <span style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 700 }}>CONFIRMED ATTACKS</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#EF4444' }}>{confirmed}</div>
          <span style={{ fontSize: '0.7rem', color: '#64748B' }}>High Confidence Malicious</span>
        </div>
        <div className="soc-card">
          <span style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 700 }}>UNDER REVIEW</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#F59E0B' }}>{review}</div>
          <span style={{ fontSize: '0.7rem', color: '#64748B' }}>Medium Confidence Probes</span>
        </div>
        <div className="soc-card">
          <span style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 700 }}>CRITICAL SEVERITY</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#A855F7' }}>{sevDist.CRITICAL || 0}</div>
          <span style={{ fontSize: '0.7rem', color: '#64748B' }}>Bot, Sql Injection, Heartbleed</span>
        </div>
      </div>

      <div className="grid-cols-2">
        <ThreatDistribution threatsData={threatsData} />

        {/* Severity Breakdown Card */}
        <div className="soc-card">
          <div className="soc-card-header">
            <div className="soc-card-title">
              <ShieldIcon size={18} color="#A855F7" />
              <span>SEVERITY DISTRIBUTION</span>
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', marginTop: '0.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="badge badge-critical">CRITICAL</span>
              <span style={{ fontWeight: 800, color: '#A855F7' }}>{sevDist.CRITICAL || 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="badge badge-high">HIGH</span>
              <span style={{ fontWeight: 800, color: '#EF4444' }}>{sevDist.HIGH || 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="badge badge-medium">MEDIUM</span>
              <span style={{ fontWeight: 800, color: '#F59E0B' }}>{sevDist.MEDIUM || 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="badge badge-low">LOW</span>
              <span style={{ fontWeight: 800, color: '#10B981' }}>{sevDist.LOW || 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Threat Events Log */}
      <div className="soc-card">
        <div className="soc-card-header">
          <div className="soc-card-title">
            <AlertTriangleIcon size={18} color="#EF4444" />
            <span>RECENT CLASSIFIED ATTACK EVENTS ({threatEvents.length})</span>
          </div>
        </div>

        {threatEvents.length === 0 ? (
          <div style={{ padding: '2.5rem', textAlign: 'center', color: '#64748B' }}>
            No attack events detected in the current monitoring session.
          </div>
        ) : (
          <div className="soc-table-container">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Attack Type</th>
                  <th>Confidence</th>
                  <th>Severity</th>
                  <th>Explanation</th>
                </tr>
              </thead>
              <tbody>
                {threatEvents.map((t, idx) => (
                  <tr key={idx}>
                    <td style={{ fontFamily: 'monospace', color: '#94A3B8' }}>{t.Timestamp}</td>
                    <td style={{ fontFamily: 'monospace' }}>{t.Source}:{t['Source Port']}</td>
                    <td style={{ fontFamily: 'monospace' }}>{t.Destination}:{t['Destination Port']}</td>
                    <td style={{ fontWeight: 700, color: '#EF4444' }}>{t.Prediction}</td>
                    <td>{t.Confidence}</td>
                    <td><span className="badge badge-high">{t.Severity}</span></td>
                    <td style={{ fontSize: '0.75rem', color: '#94A3B8', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {t.Explanation}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
