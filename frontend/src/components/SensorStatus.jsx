import React from 'react';
import { WifiIcon, ServerIcon } from './Icons';

/**
 * SensorStatus — NetShield NIDS
 * Displays a live sensor health card with ONLINE/OFFLINE badge and
 * key counters sourced from GET /api/sensors.
 */
export function SensorStatus({ sensorsData }) {
  const sensors = sensorsData?.sensors || [];
  const hasSensors = sensors.length > 0;

  return (
    <div className="soc-card">
      <div className="soc-card-header">
        <div className="soc-card-title">
          <WifiIcon size={18} color="#06B6D4" />
          <span>SENSOR HEALTH</span>
        </div>
        <span className="badge" style={{ backgroundColor: hasSensors ? 'rgba(16,185,129,0.15)' : 'rgba(100,116,139,0.15)', color: hasSensors ? '#10B981' : '#64748B', border: `1px solid ${hasSensors ? 'rgba(16,185,129,0.35)' : 'rgba(100,116,139,0.3)'}` }}>
          {hasSensors ? `${sensors.filter(s => s.status === 'ONLINE').length} ONLINE` : 'NO SENSORS'}
        </span>
      </div>

      {!hasSensors ? (
        <div style={{ textAlign: 'center', padding: '1.5rem 1rem', color: '#64748B', fontSize: '0.8rem' }}>
          <div style={{ marginTop: '0.5rem' }}>No sensors registered.</div>
          <div style={{ marginTop: '0.25rem', fontSize: '0.7rem' }}>Run <code style={{ color: '#38BDF8', backgroundColor: '#0F172A', padding: '1px 5px', borderRadius: '4px' }}>python run_sensor.py</code> on the Windows host.</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', marginTop: '0.5rem' }}>
          {sensors.map((sensor) => {
            const isOnline = sensor.status === 'ONLINE';
            return (
              <div
                key={sensor.sensor_id}
                style={{
                  backgroundColor: '#0F172A',
                  border: `1px solid ${isOnline ? 'rgba(16,185,129,0.3)' : 'rgba(100,116,139,0.2)'}`,
                  borderRadius: '8px',
                  padding: '0.75rem 1rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.85rem',
                }}
              >
                {/* Status dot */}
                <div style={{
                  width: '10px',
                  height: '10px',
                  borderRadius: '50%',
                  flexShrink: 0,
                  backgroundColor: isOnline ? '#10B981' : '#64748B',
                  boxShadow: isOnline ? '0 0 8px 2px rgba(16,185,129,0.6)' : 'none',
                }} />

                {/* Sensor info */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#F1F5F9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {sensor.name || sensor.sensor_id}
                    </span>
                    <span style={{
                      fontSize: '0.62rem',
                      fontWeight: 800,
                      letterSpacing: '0.05em',
                      color: isOnline ? '#10B981' : '#64748B',
                      flexShrink: 0,
                      marginLeft: '0.5rem',
                    }}>
                      {isOnline ? '● ONLINE' : '○ OFFLINE'}
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: '0.6rem', marginTop: '0.3rem', flexWrap: 'wrap' }}>
                    <Pill label="Pkts" value={sensor.packets_captured?.toLocaleString() ?? 0} />
                    <Pill label="Flows" value={sensor.active_flows ?? 0} />
                    <Pill label="Threats" value={sensor.threat_count ?? 0} color={sensor.threat_count > 0 ? '#F59E0B' : undefined} />
                    {sensor.last_seen && (
                      <Pill label="Last seen" value={formatRelative(sensor.last_seen)} />
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function Pill({ label, value, color }) {
  return (
    <span style={{ fontSize: '0.65rem', color: color || '#64748B', backgroundColor: '#1E293B', borderRadius: '4px', padding: '1px 6px', whiteSpace: 'nowrap' }}>
      {label}: <span style={{ color: color || '#94A3B8', fontWeight: 600 }}>{value}</span>
    </span>
  );
}

function formatRelative(isoString) {
  try {
    const delta = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
    if (delta < 5) return 'just now';
    if (delta < 60) return `${delta}s ago`;
    if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
    return `${Math.floor(delta / 3600)}h ago`;
  } catch {
    return '';
  }
}
