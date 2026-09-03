/**
 * NetShield-NIDS — Data Synchronization Hook
 * Performs periodic polling (2.5s) of API endpoints with thread-safe state management.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import apiService from '../services/api';

export function useNIDSData(pollIntervalMs = 2500) {
  const [statusData, setStatusData] = useState(null);
  const [dashboardData, setDashboardData] = useState(null);
  const [trafficData, setTrafficData] = useState([]);
  const [currentRate, setCurrentRate] = useState({ packets_per_sec: 0, bytes_per_sec: 0 });
  const [threatsData, setThreatsData] = useState(null);
  const [alertsData, setAlertsData] = useState([]);
  const [interfaces, setInterfaces] = useState([]);
  
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  const isMountedRef = useRef(true);

  const fetchAllData = useCallback(async () => {
    try {
      const [statusRes, dashRes, trafficRes, threatsRes, alertsRes, ifaceRes] = await Promise.allSettled([
        apiService.getStatus(),
        apiService.getDashboard(),
        apiService.getTraffic(60),
        apiService.getThreats(),
        apiService.getAlerts(50),
        apiService.getInterfaces(),
      ]);

      if (!isMountedRef.current) return;

      let hasError = false;
      let errMsg = '';

      if (statusRes.status === 'fulfilled') {
        setStatusData(statusRes.value);
      } else {
        hasError = true;
        errMsg = statusRes.reason?.message || 'Failed to connect to API';
      }

      if (dashRes.status === 'fulfilled') {
        setDashboardData(dashRes.value);
      }

      if (trafficRes.status === 'fulfilled') {
        setTrafficData(trafficRes.value.time_series || []);
        setCurrentRate(trafficRes.value.current_rate || { packets_per_sec: 0, bytes_per_sec: 0 });
      }

      if (threatsRes.status === 'fulfilled') {
        setThreatsData(threatsRes.value);
      }

      if (alertsRes.status === 'fulfilled') {
        setAlertsData(alertsRes.value.alerts || []);
      }

      if (ifaceRes.status === 'fulfilled') {
        setInterfaces(ifaceRes.value.interfaces || []);
      }

      if (hasError) {
        setError(errMsg);
      } else {
        setError(null);
      }

      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      if (isMountedRef.current) {
        setError(err.message || 'Network error');
      }
    } finally {
      if (isMountedRef.current) {
        setIsLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    isMountedRef.current = true;
    fetchAllData();

    const interval = setInterval(fetchAllData, pollIntervalMs);

    return () => {
      isMountedRef.current = false;
      clearInterval(interval);
    };
  }, [fetchAllData, pollIntervalMs]);

  const startMonitoring = async (ifaceName = null) => {
    setActionLoading(true);
    try {
      const res = await apiService.startMonitoring(ifaceName);
      await fetchAllData();
      return res;
    } catch (err) {
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const stopMonitoring = async () => {
    setActionLoading(true);
    try {
      const res = await apiService.stopMonitoring();
      await fetchAllData();
      return res;
    } catch (err) {
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const resetMonitoring = async () => {
    setActionLoading(true);
    try {
      const res = await apiService.resetMonitoring();
      await fetchAllData();
      return res;
    } catch (err) {
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  return {
    statusData,
    dashboardData,
    trafficData,
    currentRate,
    threatsData,
    alertsData,
    interfaces,
    isLoading,
    error,
    actionLoading,
    lastUpdated,
    refreshAll: fetchAllData,
    startMonitoring,
    stopMonitoring,
    resetMonitoring,
  };
}
