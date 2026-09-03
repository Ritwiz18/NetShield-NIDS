import React from 'react';
import { SummaryCards } from '../components/SummaryCards';
import { TrafficChart } from '../components/TrafficChart';
import { ThreatDistribution } from '../components/ThreatDistribution';
import { ProtocolDistribution } from '../components/ProtocolDistribution';
import { TopThreatenedIPs } from '../components/TopThreatenedIPs';
import { AlertsTable } from '../components/AlertsTable';
import { SystemHealth } from '../components/SystemHealth';
import { AlertTriangleIcon, ActivityIcon } from '../components/Icons';

export function DashboardPage({
  statusData,
  dashboardData,
  trafficData,
  currentRate,
  threatsData,
  alertsData,
  error
}) {
  const isRunning = statusData?.monitoring_running ?? false;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Network / Connection Error Banner */}
      {error && (
        <div style={{
          backgroundColor: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          borderRadius: '8px',
          padding: '0.85rem 1.25rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          color: '#EF4444'
        }}>
          <AlertTriangleIcon size={20} />
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>API Connectivity Warning</div>
            <div style={{ fontSize: '0.75rem', color: '#FCA5A5' }}>{error} — Verify FastAPI server is running (`uvicorn backend.api:app --port 8000`).</div>
          </div>
        </div>
      )}

      {/* Monitoring Idle Notice Banner */}
      {!isRunning && !error && (
        <div style={{
          backgroundColor: 'rgba(6, 182, 212, 0.12)',
          border: '1px solid rgba(6, 182, 212, 0.3)',
          borderRadius: '8px',
          padding: '0.85rem 1.25rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          color: '#38BDF8'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <ActivityIcon size={20} />
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>Monitoring Idle</div>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8' }}>
                Click 'START MONITORING' in the top right header to initialize Scapy packet capture on your network adapter.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 1. Summary Cards */}
      <SummaryCards dashboardData={dashboardData} currentRate={currentRate} />

      {/* 2. Traffic Throughput Chart & Protocol Distribution */}
      <div className="grid-cols-3">
        <div style={{ gridColumn: 'span 2' }}>
          <TrafficChart trafficData={trafficData} />
        </div>
        <div>
          <ProtocolDistribution dashboardData={dashboardData} />
        </div>
      </div>

      {/* 3. Threat Distribution & Top Threatened IPs */}
      <div className="grid-cols-2">
        <ThreatDistribution threatsData={threatsData} />
        <TopThreatenedIPs dashboardData={dashboardData} />
      </div>

      {/* 4. Recent Security Alerts Table */}
      <AlertsTable alerts={alertsData} />

      {/* 5. System Health */}
      <SystemHealth statusData={statusData} />
    </div>
  );
}
