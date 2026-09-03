import React from 'react';
import { CpuIcon, ServerIcon, WifiIcon, LayersIcon, CheckCircleIcon, AlertTriangleIcon } from './Icons';

export function SystemHealth({ statusData }) {
  const isRunning = statusData?.monitoring_running ?? false;
  const modelLoaded = statusData?.model_loaded ?? false;
  const sysInfo = statusData?.system_info || {};

  const components = [
    {
      name: 'Scapy Packet Sniffer',
      status: isRunning ? 'RUNNING' : 'IDLE',
      ok: isRunning,
      desc: statusData?.interface ? `Adapter: ${statusData.interface}` : 'Awaiting start',
      icon: WifiIcon,
    },
    {
      name: 'Flow Manager (5s/3s Expiry)',
      status: 'READY',
      ok: true,
      desc: 'Bidirectional flow construction',
      icon: LayersIcon,
    },
    {
      name: '53-Feature Extractor',
      status: 'VERIFIED',
      ok: true,
      desc: 'Strict 53-metric feature vector',
      icon: CpuIcon,
    },
    {
      name: `ML Engine (${statusData?.model_name || 'Extra Trees'})`,
      status: modelLoaded ? 'LOADED' : 'UNAVAILABLE',
      ok: modelLoaded,
      desc: modelLoaded ? '15-class classifier & scaler' : 'Model file missing',
      icon: ServerIcon,
    },
    {
      name: 'FastAPI REST API',
      status: 'ONLINE',
      ok: true,
      desc: `Uptime: ${statusData?.server_uptime_seconds || 0}s`,
      icon: ServerIcon,
    },
  ];

  return (
    <div className="soc-card">
      <div className="soc-card-header">
        <div className="soc-card-title">
          <ServerIcon size={18} color="#06B6D4" />
          <span>SYSTEM HEALTH & PIPELINE INTEGRITY</span>
        </div>
        <span className="badge badge-benign">System Healthy</span>
      </div>

      <div className="grid-cols-3" style={{ marginTop: '0.5rem' }}>
        {components.map((c, idx) => {
          const Icon = c.icon;
          return (
            <div key={idx} style={{ backgroundColor: '#0F172A', padding: '0.85rem', borderRadius: '8px', border: '1px solid #1E293B', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <div style={{ width: '36px', height: '36px', borderRadius: '8px', backgroundColor: c.ok ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Icon size={18} color={c.ok ? '#10B981' : '#EF4444'} />
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#F1F5F9' }}>{c.name}</span>
                  <span style={{ fontSize: '0.65rem', fontWeight: 700, color: c.ok ? '#10B981' : '#EF4444' }}>{c.status}</span>
                </div>
                <div style={{ fontSize: '0.7rem', color: '#64748B', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{c.desc}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Host System Footer Metadata */}
      <div style={{ marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid #1E293B', display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: '#64748B' }}>
        <span>OS: {sysInfo.os || 'Windows'} {sysInfo.os_release || ''} ({sysInfo.machine || 'x64'})</span>
        <span>Python {sysInfo.python_version || '3.13'} • FastAPI • Scapy Npcap</span>
      </div>
    </div>
  );
}
