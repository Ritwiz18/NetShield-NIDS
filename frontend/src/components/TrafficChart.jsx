import React, { useState } from 'react';
import { ActivityIcon } from './Icons';

export function TrafficChart({ trafficData = [] }) {
  const [metricKey, setMetricKey] = useState('packets_per_sec'); // packets_per_sec | bytes_per_sec | active_flows

  if (!trafficData || trafficData.length === 0) {
    return (
      <div className="soc-card" style={{ height: '320px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <ActivityIcon size={40} color="#334155" />
        <p style={{ marginTop: '1rem', color: '#94A3B8', fontSize: '0.9rem', fontWeight: 600 }}>
          Waiting for network traffic time-series...
        </p>
        <p style={{ color: '#64748B', fontSize: '0.75rem', marginTop: '0.25rem' }}>
          Start monitoring to observe real-time packet throughput and flow trends.
        </p>
      </div>
    );
  }

  const values = trafficData.map((d) => d[metricKey] || 0);
  const maxVal = Math.max(1, ...values);
  const width = 800;
  const height = 220;
  const padding = 25;

  const points = trafficData.map((d, idx) => {
    const x = padding + (idx / Math.max(1, trafficData.length - 1)) * (width - 2 * padding);
    const val = d[metricKey] || 0;
    const y = height - padding - (val / maxVal) * (height - 2 * padding);
    return { x, y, val, time: d.timestamp };
  });

  const pathD = points.length > 1
    ? points.reduce((acc, pt, i) => `${acc} ${i === 0 ? 'M' : 'L'} ${pt.x} ${pt.y}`, '')
    : `M ${padding} ${height - padding} L ${width - padding} ${height - padding}`;

  const areaD = `${pathD} L ${points[points.length - 1]?.x || (width - padding)} ${height - padding} L ${padding} ${height - padding} Z`;

  const getMetricLabel = () => {
    switch (metricKey) {
      case 'bytes_per_sec': return 'Bytes / sec';
      case 'active_flows': return 'Active Flows';
      default: return 'Packets / sec';
    }
  };

  return (
    <div className="soc-card">
      <div className="soc-card-header">
        <div>
          <div className="soc-card-title">
            <ActivityIcon size={18} color="#06B6D4" />
            <span>TRAFFIC THROUGHPUT OVER TIME</span>
          </div>
          <div className="soc-card-subtitle">
            Real-time time-series sampling ({trafficData.length} data points)
          </div>
        </div>

        {/* Metric Selector Toggle */}
        <div style={{ display: 'flex', gap: '0.25rem', backgroundColor: '#0F172A', padding: '0.2rem', borderRadius: '6px', border: '1px solid #1E293B' }}>
          <button
            onClick={() => setMetricKey('packets_per_sec')}
            style={{
              padding: '0.25rem 0.6rem',
              borderRadius: '4px',
              fontSize: '0.75rem',
              fontWeight: 600,
              border: 'none',
              cursor: 'pointer',
              backgroundColor: metricKey === 'packets_per_sec' ? 'rgba(6, 182, 212, 0.2)' : 'transparent',
              color: metricKey === 'packets_per_sec' ? '#38BDF8' : '#64748B'
            }}
          >
            Packets/s
          </button>
          <button
            onClick={() => setMetricKey('bytes_per_sec')}
            style={{
              padding: '0.25rem 0.6rem',
              borderRadius: '4px',
              fontSize: '0.75rem',
              fontWeight: 600,
              border: 'none',
              cursor: 'pointer',
              backgroundColor: metricKey === 'bytes_per_sec' ? 'rgba(6, 182, 212, 0.2)' : 'transparent',
              color: metricKey === 'bytes_per_sec' ? '#38BDF8' : '#64748B'
            }}
          >
            Bytes/s
          </button>
          <button
            onClick={() => setMetricKey('active_flows')}
            style={{
              padding: '0.25rem 0.6rem',
              borderRadius: '4px',
              fontSize: '0.75rem',
              fontWeight: 600,
              border: 'none',
              cursor: 'pointer',
              backgroundColor: metricKey === 'active_flows' ? 'rgba(6, 182, 212, 0.2)' : 'transparent',
              color: metricKey === 'active_flows' ? '#38BDF8' : '#64748B'
            }}
          >
            Flows
          </button>
        </div>
      </div>

      {/* Vector SVG Chart */}
      <div style={{ width: '100%', overflowX: 'auto' }}>
        <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: 'auto', display: 'block' }}>
          <defs>
            <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#06B6D4" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#06B6D4" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="#1E293B" strokeDasharray="3 3" />
          <line x1={padding} y1={height / 2} x2={width - padding} y2={height / 2} stroke="#1E293B" strokeDasharray="3 3" />
          <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="#1E293B" />

          {/* Fill Area */}
          <path d={areaD} fill="url(#trafficGradient)" />

          {/* Line Path */}
          <path d={pathD} fill="none" stroke="#38BDF8" strokeWidth="2.5" strokeLinecap="round" />

          {/* Data Points */}
          {points.map((pt, idx) => (
            <circle
              key={idx}
              cx={pt.x}
              cy={pt.y}
              r="3.5"
              fill="#06B6D4"
              stroke="#0B0F19"
              strokeWidth="1.5"
            >
              <title>{`${pt.time}: ${pt.val} ${getMetricLabel()}`}</title>
            </circle>
          ))}
        </svg>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#64748B', marginTop: '0.5rem' }}>
        <span>{points[0]?.time || 'Start'}</span>
        <span>Peak: {maxVal} {getMetricLabel()}</span>
        <span>{points[points.length - 1]?.time || 'Latest'}</span>
      </div>
    </div>
  );
}
