/**
 * NetShield-NIDS — Centralized FastAPI Client Service
 * Connects React Frontend to FastAPI Backend (:8000)
 */

const BASE_URL = import.meta.env.VITE_API_URL !== undefined ? import.meta.env.VITE_API_URL : 'http://localhost:8000';

async function fetchJSON(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout || 10000);

  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP Error ${response.status}: ${response.statusText}`);
    }

    return await response.json();
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      throw new Error('API Request Timed Out');
    }
    throw err;
  }
}

export const apiService = {
  // GET /api/status
  getStatus: () => fetchJSON('/api/status'),

  // GET /api/dashboard
  getDashboard: () => fetchJSON('/api/dashboard'),

  // GET /api/traffic?limit=60
  getTraffic: (limit = 60) => fetchJSON(`/api/traffic?limit=${limit}`),

  // GET /api/threats
  getThreats: () => fetchJSON('/api/threats'),

  // GET /api/alerts?limit=50
  getAlerts: (limit = 50) => fetchJSON(`/api/alerts?limit=${limit}`),

  // GET /api/interfaces
  getInterfaces: () => fetchJSON('/api/interfaces'),

  // GET /api/sensors
  getSensors: () => fetchJSON('/api/sensors'),

  // POST /api/monitor/start
  startMonitoring: (ifaceName = null) =>
    fetchJSON('/api/monitor/start', {
      method: 'POST',
      body: JSON.stringify(ifaceName ? { interface: ifaceName } : {}),
    }),

  // POST /api/monitor/stop
  stopMonitoring: () =>
    fetchJSON('/api/monitor/stop', {
      method: 'POST',
    }),

  // POST /api/monitor/reset
  resetMonitoring: () =>
    fetchJSON('/api/monitor/reset', {
      method: 'POST',
    }),

  // GET /api/reports
  getReports: (limit = 25) => fetchJSON(`/api/reports?limit=${limit}`),

  // GET /api/reports/{report_id}
  getReport: (reportId) => fetchJSON(`/api/reports/${encodeURIComponent(reportId)}`),

  // POST /api/reports/generate
  generateReport: (options = {}) =>
    fetchJSON('/api/reports/generate', {
      method: 'POST',
      body: JSON.stringify({
        format: options.format || 'pdf',
        time_range: options.timeRange || '24h',
        start_time: options.startTime || null,
        end_time: options.endTime || null,
        sensor_id: options.sensorId || null,
        report_type: options.reportType || 'security_investigation',
      }),
      timeout: 60000,
    }),
};

// Direct download using browser fetch (bypasses JSON wrapper)
export function downloadReport(reportId) {
  const url = `${BASE_URL}/api/reports/${encodeURIComponent(reportId)}/download`;
  return fetch(url).then(response => {
    if (!response.ok) {
      throw new Error(`Download failed: ${response.status} ${response.statusText}`);
    }
    const contentDisposition = response.headers.get('Content-Disposition') || '';
    const match = contentDisposition.match(/filename="([^"]+)"/);
    const filename = match ? match[1] : `${reportId}.pdf`;
    return response.blob().then(blob => ({ blob, filename }));
  });
}

export default apiService;
