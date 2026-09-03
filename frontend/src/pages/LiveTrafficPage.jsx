import React from 'react';
import { TrafficChart } from '../components/TrafficChart';
import { ActivityIcon, LayersIcon } from '../components/Icons';

export function LiveTrafficPage({ dashboardData, trafficData, currentRate }) {
  const detections = dashboardData?.recent_detections || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="soc-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F8FAFC' }}>Live Traffic Inspection Stream</h3>
          <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Continuous packet-flow metrics and feature vector extraction stream.</p>
        </div>
        <div style={{ display: 'flex', gap: '1rem' }}>
          <div style={{ textAlign: 'right' }}>
            <span style={{ fontSize: '0.7rem', color: '#64748B' }}>PACKETS/SEC</span>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#38BDF8' }}>{currentRate?.packets_per_sec || 0}</div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <span style={{ fontSize: '0.7rem', color: '#64748B' }}>BYTES/SEC</span>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#06B6D4' }}>{currentRate?.bytes_per_sec || 0}</div>
          </div>
        </div>
      </div>

      <TrafficChart trafficData={trafficData} />

      <div className="soc-card">
        <div className="soc-card-header">
          <div className="soc-card-title">
            <LayersIcon size={18} color="#06B6D4" />
            <span>REAL-TIME COMPLETED FLOW STREAM ({detections.length})</span>
          </div>
        </div>

        {detections.length === 0 ? (
          <div style={{ padding: '2.5rem', textAlign: 'center', color: '#64748B' }}>
            No live traffic flows inspected yet. Start monitoring to capture live traffic.
          </div>
        ) : (
          <div className="soc-table-container">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Proto</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                  <th>Duration</th>
                  <th>Prediction</th>
                  <th>Confidence</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {detections.map((det, idx) => (
                  <tr key={idx}>
                    <td style={{ fontFamily: 'monospace', color: '#94A3B8' }}>{det.Timestamp}</td>
                    <td style={{ fontFamily: 'monospace' }}>{det.Source}:{det['Source Port']}</td>
                    <td style={{ fontFamily: 'monospace' }}>{det.Destination}:{det['Destination Port']}</td>
                    <td><span className="badge badge-info">{det.Protocol}</span></td>
                    <td>{det.Packets}</td>
                    <td>{det.Bytes}</td>
                    <td>{det['Duration (s)']}s</td>
                    <td style={{ fontWeight: 700, color: det.Is_Benign ? '#10B981' : '#EF4444' }}>{det.Prediction}</td>
                    <td>{det.Confidence}</td>
                    <td>
                      <span className={`badge ${det.Is_Benign ? 'badge-benign' : 'badge-threat'}`}>
                        {det['Operational Status']}
                      </span>
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
