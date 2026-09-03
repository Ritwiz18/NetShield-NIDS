import React from 'react';

export function MetricCard({ title, value, subtitle, icon: Icon, color = 'cyan', trend }) {
  const getColorStyles = (c) => {
    switch (c) {
      case 'green':
        return { border: 'rgba(16, 185, 129, 0.3)', iconBg: 'rgba(16, 185, 129, 0.15)', iconColor: '#10B981', valueColor: '#10B981' };
      case 'amber':
        return { border: 'rgba(245, 158, 11, 0.3)', iconBg: 'rgba(245, 158, 11, 0.15)', iconColor: '#F59E0B', valueColor: '#F59E0B' };
      case 'red':
        return { border: 'rgba(239, 68, 68, 0.3)', iconBg: 'rgba(239, 68, 68, 0.15)', iconColor: '#EF4444', valueColor: '#EF4444' };
      case 'purple':
        return { border: 'rgba(168, 85, 247, 0.3)', iconBg: 'rgba(168, 85, 247, 0.15)', iconColor: '#A855F7', valueColor: '#A855F7' };
      default:
        return { border: 'rgba(6, 182, 212, 0.3)', iconBg: 'rgba(6, 182, 212, 0.15)', iconColor: '#38BDF8', valueColor: '#38BDF8' };
    }
  };

  const style = getColorStyles(color);

  return (
    <div
      className="soc-card"
      style={{
        borderColor: style.border,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        position: 'relative',
        overflow: 'hidden'
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          {title}
        </span>
        {Icon && (
          <div style={{
            width: '36px',
            height: '36px',
            borderRadius: '8px',
            backgroundColor: style.iconBg,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Icon size={20} color={style.iconColor} />
          </div>
        )}
      </div>

      <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#F8FAFC', letterSpacing: '-0.5px', marginBottom: '0.25rem' }}>
        {typeof value === 'number' ? value.toLocaleString() : (value ?? '0')}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.75rem', color: '#64748B' }}>
        <span>{subtitle}</span>
        {trend && (
          <span style={{ fontWeight: 600, color: style.valueColor }}>
            {trend}
          </span>
        )}
      </div>
    </div>
  );
}
