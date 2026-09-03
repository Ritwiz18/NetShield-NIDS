import React from 'react';
import { TrafficChart } from '../components/TrafficChart';
import { ProtocolDistribution } from '../components/ProtocolDistribution';

export function TrafficAnalysisPage({ dashboardData, trafficData }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="soc-card">
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F8FAFC' }}>Traffic Protocol & Volume Analysis</h3>
        <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Detailed network protocol distribution and traffic rate analysis.</p>
      </div>

      <div className="grid-cols-3">
        <div style={{ gridColumn: 'span 2' }}>
          <TrafficChart trafficData={trafficData} />
        </div>
        <div>
          <ProtocolDistribution dashboardData={dashboardData} />
        </div>
      </div>
    </div>
  );
}
