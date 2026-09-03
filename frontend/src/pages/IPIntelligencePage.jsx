import React from 'react';
import { TopThreatenedIPs } from '../components/TopThreatenedIPs';
import { CrosshairIcon, ShieldIcon } from '../components/Icons';

export function IPIntelligencePage({ dashboardData }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="soc-card">
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F8FAFC' }}>IP Threat Intelligence</h3>
        <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Top active source IP address tracking and threat risk scoring.</p>
      </div>

      <TopThreatenedIPs dashboardData={dashboardData} />
    </div>
  );
}
