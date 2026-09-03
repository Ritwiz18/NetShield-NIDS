import React from 'react';
import { SettingsIcon, WifiIcon, ServerIcon } from '../components/Icons';

export function SettingsPage({ interfaces, statusData, onReset }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="soc-card">
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F8FAFC' }}>System Configuration & Network Adapters</h3>
        <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Configure live network capture interfaces and reset session metrics.</p>
      </div>

      <div className="soc-card">
        <div className="soc-card-header">
          <div className="soc-card-title">
            <WifiIcon size={18} color="#06B6D4" />
            <span>DISCOVERED HOST NETWORK ADAPTERS ({interfaces.length})</span>
          </div>
        </div>

        <div className="soc-table-container">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Adapter Name</th>
                <th>Description</th>
                <th>IP Address</th>
                <th>Default</th>
              </tr>
            </thead>
            <tbody>
              {interfaces.map((iface, idx) => (
                <tr key={idx}>
                  <td style={{ fontWeight: 600, color: '#F1F5F9' }}>{iface.name}</td>
                  <td style={{ color: '#94A3B8' }}>{iface.description}</td>
                  <td style={{ fontFamily: 'monospace', color: '#38BDF8' }}>{iface.ip_address || 'Unassigned'}</td>
                  <td>
                    {iface.is_default ? (
                      <span className="badge badge-benign">DEFAULT ACTIVE</span>
                    ) : (
                      <span style={{ fontSize: '0.75rem', color: '#64748B' }}>Secondary</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="soc-card" style={{ borderLeft: '4px solid #EF4444' }}>
        <h4 style={{ fontSize: '0.95rem', color: '#F8FAFC', marginBottom: '0.5rem' }}>Reset Session Metrics</h4>
        <p style={{ fontSize: '0.8rem', color: '#94A3B8', marginBottom: '1rem' }}>
          Clears captured packet totals, active/completed flows, and stored detection incident logs.
        </p>
        <button onClick={onReset} className="btn btn-danger">
          RESET SESSION HISTORY
        </button>
      </div>
    </div>
  );
}
