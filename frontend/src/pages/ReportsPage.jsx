import React, { useState, useEffect, useCallback } from 'react';
import { apiService, downloadReport } from '../services/api';
import {
  FileTextIcon, DownloadIcon, RefreshCwIcon, AlertCircleIcon,
  PlusIcon, EyeIcon, XIcon, ShieldIcon
} from '../components/Icons';

// ─── Severity Badge ─────────────────────────────────────────────────
function SeverityBadge({ severity }) {
  const map = {
    CRITICAL: { bg: '#7F1D1D', border: '#EF4444', text: '#FCA5A5', label: 'CRITICAL' },
    HIGH:     { bg: '#78350F', border: '#F97316', text: '#FDBA74', label: 'HIGH' },
    MEDIUM:   { bg: '#713F12', border: '#EAB308', text: '#FDE047', label: 'MEDIUM' },
    LOW:      { bg: '#14532D', border: '#22C55E', text: '#86EFAC', label: 'LOW' },
  };
  const s = map[severity?.toUpperCase()] || map.LOW;
  return (
    <span style={{
      padding: '0.15rem 0.45rem',
      borderRadius: '4px',
      fontSize: '0.7rem',
      fontWeight: 700,
      background: s.bg,
      border: `1px solid ${s.border}55`,
      color: s.text,
      letterSpacing: '0.03em',
    }}>
      {s.label}
    </span>
  );
}

// ─── Format Badge ──────────────────────────────────────────────────
function FormatBadge({ format }) {
  const map = {
    pdf:  { bg: '#5B21B622', border: '#7C3AED', text: '#A78BFA' },
    csv:  { bg: '#065F4622', border: '#059669', text: '#34D399' },
    json: { bg: '#0C4A6E22', border: '#0284C7', text: '#38BDF8' },
  };
  const f = map[format?.toLowerCase()] || map.pdf;
  return (
    <span style={{
      padding: '0.15rem 0.45rem',
      borderRadius: '4px',
      fontSize: '0.7rem',
      fontWeight: 700,
      background: f.bg,
      border: `1px solid ${f.border}55`,
      color: f.text,
      letterSpacing: '0.05em',
    }}>
      {format?.toUpperCase()}
    </span>
  );
}

// ─── Loading Spinner ───────────────────────────────────────────────
function Spinner({ size = 16 }) {
  return (
    <RefreshCwIcon
      size={size}
      color="#0EA5E9"
      style={{ animation: 'spin 1s linear infinite', display: 'inline-block' }}
    />
  );
}

// ─── Modal Overlay ────────────────────────────────────────────────
function Modal({ title, onClose, children, width = '680px' }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.7)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: '1rem',
    }} onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={{
        background: '#0F172A',
        border: '1px solid #1E293B',
        borderRadius: '12px',
        width: '100%',
        maxWidth: width,
        maxHeight: '90vh',
        overflowY: 'auto',
        boxShadow: '0 25px 50px rgba(0,0,0,0.5)',
      }}>
        {/* Header */}
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '1rem 1.25rem',
          borderBottom: '1px solid #1E293B',
          position: 'sticky', top: 0, background: '#0F172A', zIndex: 1,
        }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 700, color: '#F8FAFC', margin: 0 }}>
            {title}
          </h2>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: '#64748B', fontSize: '1.25rem', padding: '0.25rem',
            borderRadius: '4px', lineHeight: 1,
          }}>
            <XIcon size={18} color="#64748B" />
          </button>
        </div>
        {/* Body */}
        <div style={{ padding: '1.25rem' }}>
          {children}
        </div>
      </div>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

// ─── Section Label ─────────────────────────────────────────────────
function SectionLabel({ children }) {
  return (
    <div style={{
      fontSize: '0.7rem', fontWeight: 600, color: '#64748B',
      textTransform: 'uppercase', letterSpacing: '0.08em',
      marginBottom: '0.35rem',
    }}>
      {children}
    </div>
  );
}

// ─── Selector Button Group ────────────────────────────────────────
function SelectorGroup({ options, value, onChange, style = {} }) {
  return (
    <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', ...style }}>
      {options.map(opt => (
        <button
          key={opt.value}
          onClick={() => onChange(opt.value)}
          style={{
            padding: '0.4rem 0.85rem',
            borderRadius: '6px',
            border: value === opt.value ? '1.5px solid #0EA5E9' : '1px solid #1E293B',
            background: value === opt.value ? '#0EA5E911' : '#1E293B',
            color: value === opt.value ? '#0EA5E9' : '#94A3B8',
            cursor: 'pointer',
            fontSize: '0.8rem',
            fontWeight: value === opt.value ? 600 : 400,
            transition: 'all 0.15s ease',
          }}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

// ─── Summary Card ─────────────────────────────────────────────────
function SummaryCard({ label, value, sub, icon, accent = '#0EA5E9' }) {
  return (
    <div className="soc-card" style={{ padding: '1rem 1.25rem', flex: '1 1 180px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
        <div style={{ color: accent }}>{icon}</div>
        <span style={{ fontSize: '0.7rem', color: '#64748B', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          {label}
        </span>
      </div>
      <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#F8FAFC', lineHeight: 1.1 }}>
        {value?.toLocaleString() ?? 0}
      </div>
      {sub && <div style={{ fontSize: '0.72rem', color: '#475569', marginTop: '0.25rem' }}>{sub}</div>}
    </div>
  );
}

// ─── Report Detail View ───────────────────────────────────────────
function ReportDetail({ report, onClose, onDownload }) {
  if (!report) return null;

  const fmtDate = (iso) => {
    if (!iso) return 'N/A';
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
  };

  const fmtBytes = (b) => {
    if (!b) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const Section = ({ title, children }) => (
    <div style={{ marginBottom: '1.5rem' }}>
      <div style={{
        fontSize: '0.8rem', fontWeight: 700, color: '#0EA5E9',
        textTransform: 'uppercase', letterSpacing: '0.06em',
        paddingBottom: '0.5rem',
        borderBottom: '1px solid #1E293B',
        marginBottom: '0.75rem',
      }}>
        {title}
      </div>
      {children}
    </div>
  );

  const InfoRow = ({ label, value }) => (
    <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.4rem', fontSize: '0.82rem' }}>
      <span style={{ color: '#64748B', minWidth: '140px' }}>{label}:</span>
      <span style={{ color: '#E2E8F0', fontWeight: 500 }}>{value || 'N/A'}</span>
    </div>
  );

  return (
    <div style={{
      background: '#0F172A', border: '1px solid #1E293B',
      borderRadius: '10px', overflow: 'hidden',
    }}>
      {/* Detail Header */}
      <div style={{
        padding: '1rem 1.25rem',
        background: '#1E293B',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ color: '#0EA5E9' }}>
            <FileTextIcon size={20} color="#0EA5E9" />
          </div>
          <div>
            <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#F8FAFC', fontFamily: 'monospace' }}>
              {report.report_id}
            </div>
            <div style={{ fontSize: '0.72rem', color: '#64748B' }}>
              Generated {fmtDate(report.generated_at)}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <FormatBadge format={report.format} />
          <button
            onClick={onClose}
            style={{
              padding: '0.35rem 0.85rem', borderRadius: '6px',
              border: '1px solid #1E293B', background: '#0F172A',
              color: '#94A3B8', cursor: 'pointer', fontSize: '0.78rem',
            }}
          >
            Close
          </button>
        </div>
      </div>

      {/* Detail Body */}
      <div style={{ padding: '1.25rem' }}>
        {/* Report Info */}
        <Section title="Report Information">
          <InfoRow label="Report ID" value={report.report_id} />
          <InfoRow label="Report Type" value={report.report_type} />
          <InfoRow label="Sensor" value={report.sensor_id} />
          <InfoRow label="Format" value={report.format?.toUpperCase()} />
          <InfoRow label="Monitoring Period" value={`${fmtDate(report.start_time)} → ${fmtDate(report.end_time)}`} />
          <InfoRow label="Generated At" value={fmtDate(report.generated_at)} />
          <InfoRow label="File Size" value={fmtBytes(report.file_size_bytes)} />
          <InfoRow label="SHA-256" value={report.sha256 ? `${report.sha256.slice(0, 16)}...` : 'N/A'} />
          <InfoRow label="Status" value={report.status} />
        </Section>

        {/* Incident Summary */}
        <Section title="Incident Summary">
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem',
          }}>
            <div style={{ background: '#1E293B', borderRadius: '8px', padding: '0.75rem', textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#F8FAFC' }}>
                {report.incident_count ?? 0}
              </div>
              <div style={{ fontSize: '0.7rem', color: '#64748B', marginTop: '0.2rem' }}>Total Incidents</div>
            </div>
            <div style={{ background: '#7F1D1D', borderRadius: '8px', padding: '0.75rem', textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#FCA5A5' }}>—</div>
              <div style={{ fontSize: '0.7rem', color: '#EF4444', marginTop: '0.2rem' }}>High Risk</div>
            </div>
            <div style={{ background: '#1E293B', borderRadius: '8px', padding: '0.75rem', textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#F8FAFC' }}>—</div>
              <div style={{ fontSize: '0.7rem', color: '#64748B', marginTop: '0.2rem' }}>Confirmed</div>
            </div>
          </div>
          <div style={{ marginTop: '0.75rem', padding: '0.75rem', background: '#0F172A', borderRadius: '6px', fontSize: '0.82rem', color: '#94A3B8', lineHeight: 1.6 }}>
            {report.incident_count > 0
              ? `${report.incident_count} security incident(s) were recorded during the monitoring period from ${fmtDate(report.start_time)} to ${fmtDate(report.end_time)}.`
              : 'No security incidents were recorded during the selected monitoring period. All monitored network flows were classified as benign.'}
          </div>
        </Section>

        {/* Evidence Integrity */}
        <Section title="Evidence Integrity">
          <div style={{ background: '#0F172A', border: '1px solid #1E293B', borderRadius: '6px', padding: '0.85rem', fontSize: '0.8rem', color: '#94A3B8' }}>
            <div style={{ marginBottom: '0.5rem' }}>
              <span style={{ color: '#64748B' }}>Report ID: </span>
              <span style={{ color: '#E2E8F0', fontFamily: 'monospace' }}>{report.report_id}</span>
            </div>
            <div style={{ marginBottom: '0.5rem' }}>
              <span style={{ color: '#64748B' }}>Generated (UTC): </span>
              <span style={{ color: '#E2E8F0' }}>{fmtDate(report.generated_at)}</span>
            </div>
            <div style={{ marginBottom: '0.5rem' }}>
              <span style={{ color: '#64748B' }}>Incident Count: </span>
              <span style={{ color: '#E2E8F0' }}>{report.incident_count ?? 0}</span>
            </div>
            <div>
              <span style={{ color: '#64748B' }}>SHA-256: </span>
              <span style={{ color: '#86EFAC', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                {report.sha256 || 'N/A'}
              </span>
            </div>
            <div style={{ marginTop: '0.5rem', fontSize: '0.72rem', color: '#475569', fontStyle: 'italic' }}>
              The SHA-256 hash is computed over the final report file bytes. It can be used to detect later modification. NetShield does not claim legal admissibility.
            </div>
          </div>
        </Section>

        {/* Download Actions */}
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
          <button
            onClick={() => onDownload(report.report_id)}
            style={{
              padding: '0.5rem 1rem', borderRadius: '6px', border: 'none',
              background: '#0EA5E9', color: '#F8FAFC',
              cursor: 'pointer', fontSize: '0.82rem', fontWeight: 600,
              display: 'flex', alignItems: 'center', gap: '0.4rem',
            }}
          >
            <DownloadIcon size={14} color="#F8FAFC" />
            Download Report
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Create Report Modal ──────────────────────────────────────────
function CreateReportModal({ onClose, onGenerate, generating }) {
  const [reportType, setReportType] = useState('security_investigation');
  const [timeRange, setTimeRange] = useState('24h');
  const [format, setFormat] = useState('pdf');
  const [sensor, setSensor] = useState('all');

  const handleGenerate = () => {
    onGenerate({ reportType, timeRange, format, sensor });
  };

  return (
    <Modal title="Create Security Report" onClose={onClose} width="580px">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

        {/* Report Type */}
        <div>
          <SectionLabel>Report Type</SectionLabel>
          <SelectorGroup
            options={[
              { value: 'security_investigation', label: 'Security Investigation' },
              { value: 'incident_report', label: 'Incident Report' },
            ]}
            value={reportType}
            onChange={setReportType}
          />
        </div>

        {/* Time Range */}
        <div>
          <SectionLabel>Time Range</SectionLabel>
          <SelectorGroup
            options={[
              { value: '1h', label: 'Last 1 Hour' },
              { value: '24h', label: 'Last 24 Hours' },
              { value: '7d', label: 'Last 7 Days' },
              { value: '30d', label: 'Last 30 Days' },
            ]}
            value={timeRange}
            onChange={setTimeRange}
          />
        </div>

        {/* Sensor */}
        <div>
          <SectionLabel>Sensor</SectionLabel>
          <SelectorGroup
            options={[
              { value: 'all', label: 'All Sensors' },
              { value: 'local', label: 'Local Sensor' },
            ]}
            value={sensor}
            onChange={setSensor}
          />
        </div>

        {/* Format */}
        <div>
          <SectionLabel>Output Format</SectionLabel>
          <SelectorGroup
            options={[
              { value: 'pdf', label: 'PDF' },
              { value: 'csv', label: 'CSV' },
              { value: 'json', label: 'JSON' },
            ]}
            value={format}
            onChange={setFormat}
          />
        </div>

        {/* Sections included (always all for now) */}
        <div style={{
          background: '#1E293B', borderRadius: '8px', padding: '0.85rem',
          fontSize: '0.8rem', color: '#64748B',
        }}>
          <div style={{ fontWeight: 600, color: '#94A3B8', marginBottom: '0.4rem' }}>
            Report Sections:
          </div>
          {[
            'Executive Summary',
            'Incident Timeline',
            'Incident Evidence',
            'Threat Analysis',
            'Traffic Analysis',
            'Sensor Information',
            'Evidence Integrity',
          ].map(s => (
            <div key={s} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginLeft: '0.5rem' }}>
              <span style={{ color: '#10B981', fontSize: '0.7rem' }}>✓</span>
              {s}
            </div>
          ))}
        </div>

        {/* Generate Button */}
        <button
          onClick={handleGenerate}
          disabled={generating}
          style={{
            padding: '0.65rem 1.5rem', borderRadius: '8px', border: 'none',
            background: generating ? '#1E293B' : 'linear-gradient(135deg, #0EA5E9, #0284C7)',
            color: '#F8FAFC', cursor: generating ? 'not-allowed' : 'pointer',
            fontSize: '0.88rem', fontWeight: 600, display: 'flex',
            alignItems: 'center', justifyContent: 'center', gap: '0.5rem',
            opacity: generating ? 0.6 : 1,
          }}
        >
          {generating ? (
            <><Spinner /> Generating {format.toUpperCase()}...</>
          ) : (
            <><ShieldIcon size={15} color="#F8FAFC" /> Generate Report</>
          )}
        </button>
      </div>
    </Modal>
  );
}

// ─── Main ReportsPage ──────────────────────────────────────────────
export function ReportsPage({ dashboardData, statusData, alertsData, sensorsData, threatsData }) {
  const [reports, setReports] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDetail, setShowDetail] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(null);
  const [lastGenerated, setLastGenerated] = useState(null);

  const fetchReports = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await apiService.getReports(50);
      if (res.status === 'ok') {
        setReports(res.reports || []);
      } else {
        setError(res.error || 'Failed to load reports');
      }
    } catch (err) {
      setError(err.message || 'Network error');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const handleGenerate = async ({ reportType, timeRange, format, sensor }) => {
    setGenerating(true);
    setError(null);
    try {
      const result = await apiService.generateReport({
        format,
        timeRange,
        sensorId: sensor === 'all' ? null : sensor,
        reportType,
      });
      if (result.status === 'ok' || result.report_id) {
        setLastGenerated(result);
        setShowCreateModal(false);
        await fetchReports();
        // Auto-open the detail view
        setSelectedReport(result);
        setShowDetail(true);
      } else {
        setError(result.detail || 'Generation failed');
      }
    } catch (err) {
      setError(err.message || 'Generation failed');
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = useCallback(async (reportId, fmt = null) => {
    try {
      const { blob, filename } = await downloadReport(reportId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(`Download failed: ${err.message}`);
    }
  }, []);

  const handleView = async (reportId) => {
    try {
      const res = await apiService.getReport(reportId);
      if (res.status === 'ok' && res.report) {
        setSelectedReport(res.report);
        setShowDetail(true);
      } else {
        setError('Failed to load report details');
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const fmtDate = (iso) => {
    if (!iso) return 'N/A';
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
  };

  const fmtBytes = (b) => {
    if (!b) return '0 B';
    const k = 1024, sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  // Real data from props
  const totalReports = reports.length;
  const totalIncidents = (dashboardData?.threat_count ?? 0) + (dashboardData?.review_count ?? 0);
  const highRiskIncidents = dashboardData?.high_risk_threat_count ?? 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>

      {/* Error Banner */}
      {error && (
        <div style={{
          background: '#7F1D1D', border: '1px solid #EF4444',
          borderRadius: '8px', padding: '0.75rem 1rem',
          color: '#FCA5A5', fontSize: '0.82rem',
          display: 'flex', alignItems: 'center', gap: '0.5rem',
        }}>
          <AlertCircleIcon size={15} color="#EF4444" />
          <span>{error}</span>
          <button
            onClick={() => setError(null)}
            style={{
              marginLeft: 'auto', background: 'none', border: 'none',
              color: '#FCA5A5', cursor: 'pointer', fontSize: '1rem',
            }}
          >
            <XIcon size={15} color="#FCA5A5" />
          </button>
        </div>
      )}

      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#F8FAFC', margin: 0 }}>
            Security Reports
          </h1>
          <p style={{ fontSize: '0.8rem', color: '#64748B', margin: '0.25rem 0 0' }}>
            Generate, review and export NetShield security investigation reports.
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          style={{
            padding: '0.55rem 1.25rem', borderRadius: '8px', border: 'none',
            background: 'linear-gradient(135deg, #0EA5E9, #0284C7)',
            color: '#F8FAFC', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600,
            display: 'flex', alignItems: 'center', gap: '0.4rem',
          }}
        >
          <PlusIcon size={14} color="#F8FAFC" />
          Create Report
        </button>
      </div>

      {/* Summary Cards */}
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        <SummaryCard
          label="Total Reports"
          value={totalReports}
          sub="generated reports"
          icon={<FileTextIcon size={18} color="#0EA5E9" />}
          accent="#0EA5E9"
        />
        <SummaryCard
          label="Total Incidents"
          value={totalIncidents}
          sub="threats + review"
          icon={<AlertCircleIcon size={18} color="#F97316" />}
          accent="#F97316"
        />
        <SummaryCard
          label="High Risk"
          value={highRiskIncidents}
          sub="critical threats"
          icon={<ShieldIcon size={18} color="#EF4444" />}
          accent="#EF4444"
        />
      </div>

      {/* Report Detail View */}
      {showDetail && selectedReport && (
        <div>
          <ReportDetail
            report={selectedReport}
            onClose={() => { setShowDetail(false); setSelectedReport(null); }}
            onDownload={handleDownload}
          />
        </div>
      )}

      {/* Report History Table */}
      <div className="soc-card" style={{ padding: 0, overflow: 'hidden' }}>
        {/* Table Header */}
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '1rem 1.25rem',
          borderBottom: '1px solid #1E293B',
        }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#F8FAFC', margin: 0 }}>
            Report History
          </h3>
          <button
            onClick={fetchReports}
            disabled={isLoading}
            style={{
              padding: '0.3rem 0.75rem', borderRadius: '6px',
              border: '1px solid #1E293B', background: '#1E293B',
              color: '#94A3B8', cursor: isLoading ? 'not-allowed' : 'pointer',
              fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem',
              opacity: isLoading ? 0.5 : 1,
            }}
          >
            <RefreshCwIcon size={13} color="#94A3B8" />
            Refresh
          </button>
        </div>

        {/* Table */}
        {isLoading ? (
          <div style={{ padding: '2.5rem', textAlign: 'center', color: '#475569' }}>
            <Spinner size={24} /><br /><br />Loading reports...
          </div>
        ) : reports.length === 0 ? (
          <div style={{ padding: '2.5rem', textAlign: 'center', color: '#475569' }}>
            <FileTextIcon size={32} color="#334155" /><br />
            <div style={{ marginTop: '0.75rem', fontSize: '0.85rem' }}>
              No reports generated yet.
            </div>
            <div style={{ fontSize: '0.78rem', color: '#334155', marginTop: '0.3rem' }}>
              Click <strong style={{ color: '#64748B' }}>Create Report</strong> above to generate your first report.
            </div>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ color: '#475569', borderBottom: '1px solid #1E293B', background: '#0F172A' }}>
                  {['Report ID', 'Format', 'Generated', 'Period', 'Sensor', 'Incidents', 'Size', 'Actions'].map(h => (
                    <th key={h} style={{ padding: '0.6rem 0.85rem', textAlign: 'left', fontWeight: 600, fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {reports.map((r) => (
                  <tr key={r.report_id} style={{ color: '#E2E8F0', borderBottom: '1px solid #0F172A', transition: 'background 0.1s' }}
                    onMouseEnter={e => e.currentTarget.style.background = '#1E293B'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <td style={{ padding: '0.6rem 0.85rem', fontFamily: 'monospace', fontSize: '0.78rem', color: '#86EFAC' }}>
                      {r.report_id}
                    </td>
                    <td style={{ padding: '0.6rem 0.85rem' }}>
                      <FormatBadge format={r.format} />
                    </td>
                    <td style={{ padding: '0.6rem 0.85rem', color: '#94A3B8', whiteSpace: 'nowrap', fontSize: '0.78rem' }}>
                      {fmtDate(r.generated_at)}
                    </td>
                    <td style={{ padding: '0.6rem 0.85rem', color: '#94A3B8', fontSize: '0.78rem', maxWidth: '140px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {fmtDate(r.start_time)} → {fmtDate(r.end_time)}
                    </td>
                    <td style={{ padding: '0.6rem 0.85rem', color: '#94A3B8', fontSize: '0.78rem' }}>
                      {r.sensor_id || 'all'}
                    </td>
                    <td style={{ padding: '0.6rem 0.85rem', textAlign: 'center' }}>
                      <span style={{
                        padding: '0.15rem 0.45rem', borderRadius: '4px', fontSize: '0.72rem',
                        background: (r.incident_count ?? 0) > 0 ? '#7F1D1D33' : '#1E293B',
                        color: (r.incident_count ?? 0) > 0 ? '#FCA5A5' : '#64748B',
                        border: (r.incident_count ?? 0) > 0 ? '1px solid #EF444455' : '1px solid #334155',
                      }}>
                        {(r.incident_count ?? 0).toLocaleString()}
                      </span>
                    </td>
                    <td style={{ padding: '0.6rem 0.85rem', color: '#64748B', fontSize: '0.78rem' }}>
                      {fmtBytes(r.file_size_bytes)}
                    </td>
                    <td style={{ padding: '0.6rem 0.85rem' }}>
                      <div style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
                        {/* View */}
                        <button
                          onClick={() => handleView(r.report_id)}
                          title="View Report Details"
                          style={{
                            padding: '0.25rem 0.5rem', borderRadius: '5px',
                            border: '1px solid #334155', background: 'transparent',
                            color: '#94A3B8', cursor: 'pointer', fontSize: '0.72rem',
                            display: 'flex', alignItems: 'center', gap: '0.2rem',
                          }}
                        >
                          <EyeIcon size={11} color="#94A3B8" />
                        </button>
                        {/* PDF */}
                        <button
                          onClick={() => handleDownload(r.report_id, 'pdf')}
                          title="Download PDF"
                          style={{
                            padding: '0.25rem 0.5rem', borderRadius: '5px',
                            border: '1px solid #7C3AED55', background: '#7C3AED11',
                            color: '#A78BFA', cursor: 'pointer', fontSize: '0.72rem',
                            fontWeight: 600,
                          }}
                        >
                          PDF
                        </button>
                        {/* CSV */}
                        <button
                          onClick={() => handleDownload(r.report_id, 'csv')}
                          title="Download CSV"
                          style={{
                            padding: '0.25rem 0.5rem', borderRadius: '5px',
                            border: '1px solid #05966955', background: '#05966911',
                            color: '#34D399', cursor: 'pointer', fontSize: '0.72rem',
                            fontWeight: 600,
                          }}
                        >
                          CSV
                        </button>
                        {/* JSON */}
                        <button
                          onClick={() => handleDownload(r.report_id, 'json')}
                          title="Download JSON"
                          style={{
                            padding: '0.25rem 0.5rem', borderRadius: '5px',
                            border: '1px solid #0284C755', background: '#0284C711',
                            color: '#38BDF8', cursor: 'pointer', fontSize: '0.72rem',
                            fontWeight: 600,
                          }}
                        >
                          JSON
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Footer count */}
        {reports.length > 0 && (
          <div style={{
            padding: '0.6rem 1.25rem', borderTop: '1px solid #1E293B',
            fontSize: '0.72rem', color: '#475569',
          }}>
            Showing {reports.length} report(s)
          </div>
        )}
      </div>

      {/* Last Generated Success Banner */}
      {lastGenerated && (
        <div style={{
          background: '#064E3B', border: '1px solid #10B981',
          borderRadius: '8px', padding: '0.75rem 1rem',
          color: '#6EE7B7', fontSize: '0.82rem',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div>
            <strong>Report generated successfully!</strong>
            &nbsp; ID: <code style={{ fontFamily: 'monospace' }}>{lastGenerated.report_id}</code>
            &nbsp;({lastGenerated.format?.toUpperCase()}, {lastGenerated.incident_count} incidents, {fmtBytes(lastGenerated.file_size_bytes)})
          </div>
          <div style={{ display: 'flex', gap: '0.4rem' }}>
            <button
              onClick={() => handleDownload(lastGenerated.report_id)}
              style={{
                padding: '0.3rem 0.75rem', borderRadius: '5px',
                border: '1px solid #10B981', background: 'transparent',
                color: '#6EE7B7', cursor: 'pointer', fontSize: '0.78rem',
              }}
            >
              Download
            </button>
            <button
              onClick={() => setLastGenerated(null)}
              style={{
                background: 'none', border: 'none', color: '#6EE7B7',
                cursor: 'pointer', fontSize: '0.9rem', padding: '0.2rem 0.4rem',
              }}
            >
              <XIcon size={14} color="#6EE7B7" />
            </button>
          </div>
        </div>
      )}

      {/* Create Report Modal */}
      {showCreateModal && (
        <CreateReportModal
          onClose={() => setShowCreateModal(false)}
          onGenerate={handleGenerate}
          generating={generating}
        />
      )}
    </div>
  );
}
