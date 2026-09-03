import React from 'react';
import { InfoIcon, ShieldIcon, CpuIcon, LayersIcon } from '../components/Icons';

export function AboutPage() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="soc-card">
        <div className="soc-card-header">
          <div className="soc-card-title">
            <ShieldIcon size={20} color="#06B6D4" />
            <span>NETSHIELD-NIDS ARCHITECTURE & SPECIFICATIONS</span>
          </div>
        </div>
        <p style={{ color: '#94A3B8', fontSize: '0.85rem', lineHeight: '1.6' }}>
          NetShield-NIDS is a production-ready, end-to-end Machine Learning Network Intrusion Detection System designed to classify live TCP/IP network traffic flows into BENIGN activity or 14 distinct cyberattack vectors with 99.87% detection accuracy.
        </p>
      </div>

      <div className="soc-card">
        <h4 style={{ color: '#F8FAFC', fontSize: '0.95rem', marginBottom: '1rem' }}>End-to-End Pipeline Architecture</h4>
        <div style={{ backgroundColor: '#0F172A', padding: '1.25rem', borderRadius: '8px', border: '1px solid #1E293B', fontFamily: 'monospace', fontSize: '0.8rem', color: '#38BDF8', lineHeight: '1.8' }}>
          Network Packets<br />
          &nbsp;&nbsp;↓ (Scapy capture.py)<br />
          FlowManager (flow_manager.py: 5s active / 3s inactive timeout)<br />
          &nbsp;&nbsp;↓<br />
          53-Feature Extractor (feature_extractor.py: strict vector ordering)<br />
          &nbsp;&nbsp;↓<br />
          LiveDetector (detector.py: StandardScaler + Extra Trees Classifier)<br />
          &nbsp;&nbsp;↓<br />
          RealtimeMonitorEngine (monitor.py: Thread-safe metrics snapshot)<br />
          &nbsp;&nbsp;↓<br />
          FastAPI REST API (backend/api.py: CORS, endpoints, JSON responses)<br />
          &nbsp;&nbsp;↓<br />
          React Web Dashboard (:5173)
        </div>
      </div>

      <div className="grid-cols-2">
        <div className="soc-card">
          <h4 style={{ color: '#F8FAFC', fontSize: '0.95rem', marginBottom: '0.75rem' }}>Model Performance Highlights</h4>
          <ul style={{ color: '#94A3B8', fontSize: '0.8rem', lineHeight: '1.8', paddingLeft: '1.25rem' }}>
            <li><strong>Accuracy:</strong> 99.87% (held-out 504,159 test samples)</li>
            <li><strong>Weighted Precision:</strong> 99.88%</li>
            <li><strong>Weighted Recall:</strong> 99.87%</li>
            <li><strong>Weighted F1-Score:</strong> 99.87%</li>
            <li><strong>Classifier:</strong> Extra Trees (Extremely Randomized Trees)</li>
          </ul>
        </div>

        <div className="soc-card">
          <h4 style={{ color: '#F8FAFC', fontSize: '0.95rem', marginBottom: '0.75rem' }}>Attack Categories (15 Total)</h4>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
            {['BENIGN', 'DDoS', 'PortScan', 'DoS Hulk', 'DoS GoldenEye', 'DoS slowloris', 'DoS Slowhttptest', 'FTP-Patator', 'SSH-Patator', 'Bot', 'Web Attack - Brute Force', 'Web Attack - XSS', 'Web Attack - SQLi', 'Infiltration', 'Heartbleed'].map((c, i) => (
              <span key={i} className={`badge ${c === 'BENIGN' ? 'badge-benign' : 'badge-threat'}`}>
                {c}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
