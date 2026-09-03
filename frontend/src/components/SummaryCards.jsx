import React from 'react';
import { MetricCard } from './MetricCard';
import { LayersIcon, ActivityIcon, AlertTriangleIcon, ShieldIcon, CheckCircleIcon, ClockIcon, InfoIcon } from './Icons';

export function SummaryCards({ dashboardData, currentRate }) {
  const pkts = dashboardData?.packets_captured ?? 0;
  const activeFlows = dashboardData?.active_flows ?? 0;
  const completedFlows = dashboardData?.completed_flows ?? 0;
  const classifiedFlows = dashboardData?.classified_flows ?? 0;
  const normalCount = dashboardData?.normal_count ?? 0;
  const threatCount = dashboardData?.threat_count ?? 0;
  const reviewCount = dashboardData?.review_count ?? 0;
  const uncertainCount = dashboardData?.uncertain_count ?? 0;
  const highRiskCount = dashboardData?.high_risk_threat_count ?? 0;
  const attackRate = dashboardData?.attack_rate ?? 0.0;

  const pps = currentRate?.packets_per_sec ?? 0;
  const bps = currentRate?.bytes_per_sec ?? 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* 4 Primary SOC Summary Cards */}
      <div className="grid-cols-4">
        <MetricCard
          title="Total Packets"
          value={pkts}
          subtitle={`${pps} pkts/s • ${bps > 1024 ? (bps/1024).toFixed(1) + ' KB/s' : bps + ' B/s'}`}
          icon={LayersIcon}
          color="cyan"
        />

        <MetricCard
          title="Active Flows"
          value={activeFlows}
          subtitle={`Completed: ${completedFlows} • Classified: ${classifiedFlows}`}
          icon={ActivityIcon}
          color="cyan"
        />

        <MetricCard
          title="Threats Detected"
          value={threatCount}
          subtitle={`Attack Rate: ${attackRate}% of classified`}
          icon={AlertTriangleIcon}
          color="red"
          trend={threatCount > 0 ? `${threatCount} Threat(s)` : '0 Threats'}
        />

        <MetricCard
          title="High-Risk Alerts"
          value={highRiskCount}
          subtitle="HIGH & CRITICAL Severity Detections"
          icon={ShieldIcon}
          color="purple"
          trend={highRiskCount > 0 ? 'Action Required' : 'Status Clear'}
        />
      </div>

      {/* 3 Secondary Operational Verdict Cards */}
      <div className="grid-cols-3">
        <div className="soc-card" style={{ display: 'flex', alignItems: 'center', gap: '1rem', borderLeft: '4px solid #10B981' }}>
          <div style={{ width: '40px', height: '40px', borderRadius: '50%', backgroundColor: 'rgba(16, 185, 129, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <CheckCircleIcon size={22} color="#10B981" />
          </div>
          <div>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#94A3B8', textTransform: 'uppercase' }}>Normal Flows</span>
            <div style={{ fontSize: '1.3rem', fontWeight: 800, color: '#10B981' }}>{normalCount.toLocaleString()}</div>
            <span style={{ fontSize: '0.7rem', color: '#64748B' }}>Verified Benign Traffic</span>
          </div>
        </div>

        <div className="soc-card" style={{ display: 'flex', alignItems: 'center', gap: '1rem', borderLeft: '4px solid #F59E0B' }}>
          <div style={{ width: '40px', height: '40px', borderRadius: '50%', backgroundColor: 'rgba(245, 158, 11, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ClockIcon size={22} color="#F59E0B" />
          </div>
          <div>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#94A3B8', textTransform: 'uppercase' }}>Under Review</span>
            <div style={{ fontSize: '1.3rem', fontWeight: 800, color: '#F59E0B' }}>{reviewCount.toLocaleString()}</div>
            <span style={{ fontSize: '0.7rem', color: '#64748B' }}>Medium Confidence Anomalies</span>
          </div>
        </div>

        <div className="soc-card" style={{ display: 'flex', alignItems: 'center', gap: '1rem', borderLeft: '4px solid #64748B' }}>
          <div style={{ width: '40px', height: '40px', borderRadius: '50%', backgroundColor: 'rgba(100, 116, 139, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <InfoIcon size={22} color="#94A3B8" />
          </div>
          <div>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#94A3B8', textTransform: 'uppercase' }}>Uncertain Flows</span>
            <div style={{ fontSize: '1.3rem', fontWeight: 800, color: '#94A3B8' }}>{uncertainCount.toLocaleString()}</div>
            <span style={{ fontSize: '0.7rem', color: '#64748B' }}>Low Confidence Verdicts</span>
          </div>
        </div>
      </div>
    </div>
  );
}
