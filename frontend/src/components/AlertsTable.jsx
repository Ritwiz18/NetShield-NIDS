import React, { useState } from 'react';
import { AlertTriangleIcon, InfoIcon, ShieldIcon } from './Icons';

export function AlertsTable({ alerts = [] }) {
  const [selectedAlert, setSelectedAlert] = useState(null);

  const getSeverityBadgeClass = (severity) => {
    switch (String(severity).toUpperCase()) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      default: return 'badge-low';
    }
  };

  return (
    <div className="soc-card">
      <div className="soc-card-header">
        <div className="soc-card-title">
          <AlertTriangleIcon size={18} color="#EF4444" />
          <span>RECENT SECURITY INCIDENT ALERTS</span>
        </div>
        <span className="badge badge-threat">{alerts.length} Alert(s) Logged</span>
      </div>

      {alerts.length === 0 ? (
        <div style={{ padding: '3rem 1rem', textAlign: 'center', color: '#64748B' }}>
          <ShieldIcon size={40} color="#1E293B" />
          <p style={{ marginTop: '0.75rem', fontWeight: 600, color: '#94A3B8' }}>
            No security incident alerts logged.
          </p>
          <p style={{ fontSize: '0.75rem', marginTop: '0.25rem' }}>
            System will automatically record incident alerts when malicious activity is classified.
          </p>
        </div>
      ) : (
        <div className="soc-table-container">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP : Port</th>
                <th>Destination IP : Port</th>
                <th>Protocol</th>
                <th>Attack Verdict</th>
                <th>Confidence</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert, idx) => (
                <tr key={alert.id || idx}>
                  <td style={{ color: '#94A3B8', fontFamily: 'monospace' }}>{alert.timestamp}</td>
                  <td style={{ fontFamily: 'monospace', color: '#F1F5F9' }}>
                    {alert.source_ip}:{alert.source_port}
                  </td>
                  <td style={{ fontFamily: 'monospace', color: '#F1F5F9' }}>
                    {alert.destination_ip}:{alert.destination_port}
                  </td>
                  <td>
                    <span className="badge badge-info">{alert.protocol}</span>
                  </td>
                  <td style={{ fontWeight: 700, color: '#EF4444' }}>{alert.attack_type}</td>
                  <td style={{ fontWeight: 600, color: '#F8FAFC' }}>
                    {alert.confidence} ({alert.confidence_level})
                  </td>
                  <td>
                    <span className={`badge ${getSeverityBadgeClass(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 600 }}>
                      {alert.status || 'New'}
                    </span>
                  </td>
                  <td>
                    <button
                      onClick={() => setSelectedAlert(alert)}
                      className="btn btn-outline"
                      style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Incident Detail Modal */}
      {selectedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #1E293B', paddingBottom: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <AlertTriangleIcon size={22} color="#EF4444" />
                <h3 style={{ margin: 0, fontSize: '1.1rem', color: '#F8FAFC' }}>
                  Incident Inspection: {selectedAlert.id}
                </h3>
              </div>
              <button onClick={() => setSelectedAlert(null)} style={{ background: 'none', border: 'none', color: '#94A3B8', fontSize: '1.2rem', cursor: 'pointer' }}>
                ✕
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ backgroundColor: '#0F172A', padding: '1rem', borderRadius: '8px', border: '1px solid #1E293B' }}>
                <div style={{ fontSize: '0.8rem', color: '#94A3B8', textTransform: 'uppercase', fontWeight: 700, marginBottom: '0.5rem' }}>
                  Threat Explanation
                </div>
                <p style={{ color: '#E2E8F0', fontSize: '0.85rem', lineHeight: '1.5' }}>
                  {selectedAlert.explanation || 'Anomalous traffic flow pattern classified by Extra Trees model.'}
                </p>
              </div>

              <div className="grid-cols-2">
                <div>
                  <span style={{ fontSize: '0.75rem', color: '#64748B' }}>5-Tuple Network Flow</span>
                  <div style={{ fontSize: '0.85rem', color: '#F8FAFC', fontFamily: 'monospace', marginTop: '0.25rem' }}>
                    {selectedAlert.source_ip}:{selectedAlert.source_port} → {selectedAlert.destination_ip}:{selectedAlert.destination_port} ({selectedAlert.protocol})
                  </div>
                </div>

                <div>
                  <span style={{ fontSize: '0.75rem', color: '#64748B' }}>Attack Vector & Confidence</span>
                  <div style={{ fontSize: '0.85rem', color: '#EF4444', fontWeight: 700, marginTop: '0.25rem' }}>
                    {selectedAlert.attack_type} ({selectedAlert.confidence})
                  </div>
                </div>
              </div>

              <div className="grid-cols-3">
                <div>
                  <span style={{ fontSize: '0.75rem', color: '#64748B' }}>Severity</span>
                  <div><span className={`badge ${getSeverityBadgeClass(selectedAlert.severity)}`}>{selectedAlert.severity}</span></div>
                </div>
                <div>
                  <span style={{ fontSize: '0.75rem', color: '#64748B' }}>Flow Duration</span>
                  <div style={{ fontSize: '0.85rem', color: '#E2E8F0', fontWeight: 600 }}>{selectedAlert.flow_duration_sec}s</div>
                </div>
                <div>
                  <span style={{ fontSize: '0.75rem', color: '#64748B' }}>Packets / Volume</span>
                  <div style={{ fontSize: '0.85rem', color: '#E2E8F0', fontWeight: 600 }}>{selectedAlert.packets} pkts ({selectedAlert.bytes} B)</div>
                </div>
              </div>
            </div>

            <div style={{ marginTop: '1.5rem', display: 'flex', justifyContent: 'flex-end' }}>
              <button onClick={() => setSelectedAlert(null)} className="btn btn-outline">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
