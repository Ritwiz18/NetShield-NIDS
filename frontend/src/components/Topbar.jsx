import React, { useState, useEffect } from 'react';
import { PlayIcon, SquareIcon, RefreshIcon, WifiIcon, ActivityIcon, AlertTriangleIcon } from './Icons';

export function Topbar({
  activeTab,
  statusData,
  interfaces,
  actionLoading,
  onStart,
  onStop,
  onRefresh,
  lastUpdated
}) {
  const [selectedIface, setSelectedIface] = useState('');
  const [clockStr, setClockStr] = useState('');

  const isRunning = statusData?.monitoring_running ?? false;

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setClockStr(now.toLocaleTimeString() + ' - ' + now.toLocaleDateString());
    };
    updateClock();
    const timer = setInterval(updateClock, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (interfaces && interfaces.length > 0 && !selectedIface) {
      setSelectedIface(interfaces[0].display_name);
    }
  }, [interfaces, selectedIface]);

  const handleStartStopToggle = async () => {
    if (actionLoading) return;
    if (isRunning) {
      await onStop();
    } else {
      await onStart(selectedIface);
    }
  };

  const getPageTitle = (tab) => {
    switch (tab) {
      case 'dashboard': return 'Security Operations Center';
      case 'live-traffic': return 'Real-Time Traffic Inspection';
      case 'threats': return 'Cyber Threat Analytics';
      case 'alerts': return 'Incident Alerts Log';
      case 'ip-intelligence': return 'IP Reputation & Intelligence';
      case 'traffic-analysis': return 'Protocol & Volume Analysis';
      case 'reports': return 'Executive Security Reports';
      case 'settings': return 'System Settings & Adapter Config';
      case 'about': return 'Architecture & Specification';
      default: return 'Dashboard';
    }
  };

  return (
    <header style={{
      height: '65px',
      backgroundColor: '#0F172A',
      borderBottom: '1px solid #1E293B',
      padding: '0 1.5rem',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      userSelect: 'none'
    }}>
      {/* Title & Section */}
      <div>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F8FAFC', margin: 0 }}>
          {getPageTitle(activeTab)}
        </h2>
        <span style={{ fontSize: '0.75rem', color: '#64748B' }}>
          Last sync: {lastUpdated || 'Initial'} • {clockStr}
        </span>
      </div>

      {/* Controls & Interface Selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        {/* Network Interface Select */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <WifiIcon size={16} color="#38BDF8" />
          <select
            value={selectedIface}
            onChange={(e) => setSelectedIface(e.target.value)}
            disabled={isRunning || actionLoading}
            className="select-input"
            style={{ maxWidth: '280px' }}
          >
            {interfaces.map((iface, idx) => (
              <option key={idx} value={iface.display_name}>
                {iface.display_name}
              </option>
            ))}
          </select>
        </div>

        {/* Start / Stop Monitoring Button */}
        <button
          onClick={handleStartStopToggle}
          disabled={actionLoading}
          className={`btn ${isRunning ? 'btn-danger' : 'btn-primary'}`}
          style={{ minWidth: '170px' }}
        >
          {actionLoading ? (
            <span>Processing...</span>
          ) : isRunning ? (
            <>
              <SquareIcon size={16} />
              <span>STOP MONITORING</span>
            </>
          ) : (
            <>
              <PlayIcon size={16} />
              <span>START MONITORING</span>
            </>
          )}
        </button>

        {/* Manual Refresh */}
        <button
          onClick={onRefresh}
          className="btn btn-outline"
          title="Manual Refresh"
          style={{ padding: '0.5rem' }}
        >
          <RefreshIcon size={16} color="#94A3B8" />
        </button>
      </div>
    </header>
  );
}
