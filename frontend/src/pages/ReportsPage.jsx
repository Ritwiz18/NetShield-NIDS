import React from 'react';
import { FileTextIcon, ShieldIcon, CheckCircleIcon } from '../components/Icons';

export function ReportsPage({ dashboardData, statusData }) {
  const pkts = dashboardData?.packets_captured ?? 0;
  const totalFlows = dashboardData?.completed_flows ?? 0;
  const threats = dashboardData?.threat_count ?? 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="soc-card">
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F8FAFC' }}>Security Audit & Executive Report Summary</h3>
        <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Automated session evaluation summary for compliance and security teams.</p>
      </div>

      <div className="soc-card">
        <div className="soc-card-header">
          <div className="soc-card-title">
            <FileTextIcon size={18} color="#06B6D4" />
            <span>SESSION COMPLIANCE REPORT</span>
          </div>
          <span className="badge badge-info">Generated Now</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', color: '#E2E8F0', fontSize: '0.85rem' }}>
          <div style={{ backgroundColor: '#0F172A', padding: '1rem', borderRadius: '8px', border: '1px solid #1E293B' }}>
            <div style={{ fontWeight: 700, color: '#F8FAFC', marginBottom: '0.5rem' }}>Executive Overview</div>
            <p style={{ color: '#94A3B8', fontSize: '0.8rem', lineHeight: '1.6' }}>
              The NetShield NIDS ML continuous monitoring engine has inspected <strong>{pkts.toLocaleString()}</strong> raw packet records across <strong>{totalFlows}</strong> aggregated 53-feature network flow records. A total of <strong>{threats}</strong> malicious attack vectors were identified and logged with 99.87% classifier accuracy.
            </p>
          </div>

          <div className="grid-cols-3">
            <div style={{ backgroundColor: '#0F172A', padding: '0.85rem', borderRadius: '8px', border: '1px solid #1E293B' }}>
              <span style={{ fontSize: '0.75rem', color: '#64748B' }}>Primary Classifier</span>
              <div style={{ fontWeight: 700, color: '#38BDF8', marginTop: '0.2rem' }}>Extra Trees (100 Estimators)</div>
            </div>
            <div style={{ backgroundColor: '#0F172A', padding: '0.85rem', borderRadius: '8px', border: '1px solid #1E293B' }}>
              <span style={{ fontSize: '0.75rem', color: '#64748B' }}>Preprocessing Scaler</span>
              <div style={{ fontWeight: 700, color: '#38BDF8', marginTop: '0.2rem' }}>StandardScaler (Z-Score)</div>
            </div>
            <div style={{ backgroundColor: '#0F172A', padding: '0.85rem', borderRadius: '8px', border: '1px solid #1E293B' }}>
              <span style={{ fontSize: '0.75rem', color: '#64748B' }}>Target Classes</span>
              <div style={{ fontWeight: 700, color: '#38BDF8', marginTop: '0.2rem' }}>15 (1 Benign + 14 Malicious)</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
