import React from 'react';
import {
  ShieldIcon,
  ActivityIcon,
  AlertTriangleIcon,
  LayersIcon,
  BarChartIcon,
  CrosshairIcon,
  SettingsIcon,
  InfoIcon,
  FileTextIcon,
  CpuIcon
} from './Icons';

export function Sidebar({ activeTab, setActiveTab, statusData }) {
  const isRunning = statusData?.monitoring_running ?? false;
  const stateStr = statusData?.state ?? 'STOPPED';
  const modelLoaded = statusData?.model_loaded ?? false;

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayersIcon },
    { id: 'live-traffic', label: 'Live Traffic', icon: ActivityIcon },
    { id: 'threats', label: 'Threats', icon: AlertTriangleIcon },
    { id: 'alerts', label: 'Alerts', icon: ShieldIcon },
    { id: 'ip-intelligence', label: 'IP Intelligence', icon: CrosshairIcon },
    { id: 'traffic-analysis', label: 'Traffic Analysis', icon: BarChartIcon },
    { id: 'reports', label: 'Reports', icon: FileTextIcon },
    { id: 'settings', label: 'Settings', icon: SettingsIcon },
    { id: 'about', label: 'About', icon: InfoIcon },
  ];

  return (
    <aside style={{
      width: '260px',
      backgroundColor: '#0F172A',
      borderRight: '1px solid #1E293B',
      display: 'flex',
      flexDirection: 'column',
      minHeight: '100vh',
      userSelect: 'none'
    }}>
      {/* Brand Header */}
      <div style={{
        padding: '1.5rem 1.25rem',
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem',
        borderBottom: '1px solid #1E293B'
      }}>
        <div style={{
          width: '42px',
          height: '42px',
          borderRadius: '10px',
          background: 'linear-gradient(135deg, #0284C7 0%, #06B6D4 100%)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 4px 10px rgba(6, 182, 212, 0.3)',
          color: '#FFF'
        }}>
          <ShieldIcon size={24} />
        </div>
        <div>
          <h1 style={{ fontSize: '1.15rem', fontWeight: 800, color: '#F8FAFC', letterSpacing: '0.5px', margin: 0 }}>
            NET SHIELD
          </h1>
          <span style={{ fontSize: '0.7rem', color: '#38BDF8', fontWeight: 700, letterSpacing: '1px' }}>
            NIDS SOC ENGINE
          </span>
        </div>
      </div>

      {/* Engine Status Banner */}
      <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid #1E293B' }}>
        <div style={{
          backgroundColor: '#1E293B',
          borderRadius: '8px',
          padding: '0.75rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span className={`pulse-dot ${isRunning ? 'running' : (stateStr === 'ERROR' ? 'error' : 'stopped')}`}></span>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#E2E8F0' }}>
              {stateStr}
            </span>
          </div>
          <span style={{
            fontSize: '0.7rem',
            padding: '0.15rem 0.5rem',
            borderRadius: '4px',
            backgroundColor: isRunning ? 'rgba(16, 185, 129, 0.2)' : 'rgba(148, 163, 184, 0.15)',
            color: isRunning ? '#10B981' : '#94A3B8',
            fontWeight: 700
          }}>
            {isRunning ? 'ACTIVE' : 'IDLE'}
          </span>
        </div>
      </div>

      {/* Navigation List */}
      <nav style={{ flex: 1, padding: '1rem 0.75rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                width: '100%',
                padding: '0.65rem 0.85rem',
                borderRadius: '8px',
                border: 'none',
                backgroundColor: isActive ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                color: isActive ? '#38BDF8' : '#94A3B8',
                fontWeight: isActive ? 700 : 500,
                fontSize: '0.875rem',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all 0.15s ease'
              }}
            >
              <Icon size={18} color={isActive ? '#38BDF8' : '#64748B'} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* ML Model Footer Info */}
      <div style={{
        padding: '1rem 1.25rem',
        borderTop: '1px solid #1E293B',
        backgroundColor: '#0B0F19'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#64748B', fontSize: '0.75rem', marginBottom: '0.25rem' }}>
          <CpuIcon size={14} color="#06B6D4" />
          <span>ML ENGINE</span>
        </div>
        <div style={{ fontSize: '0.8rem', fontWeight: 600, color: modelLoaded ? '#E2E8F0' : '#EF4444' }}>
          {statusData?.model_name || (modelLoaded ? 'Extra Trees ML' : 'Model Unavailable')}
        </div>
        <div style={{ fontSize: '0.7rem', color: '#64748B', marginTop: '0.15rem' }}>
          53 Features • 15 Classes
        </div>
      </div>
    </aside>
  );
}
