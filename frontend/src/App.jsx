import React, { useState } from 'react';
import { useNIDSData } from './hooks/useNIDSData';
import { Sidebar } from './components/Sidebar';
import { Topbar } from './components/Topbar';
import { DashboardPage } from './pages/DashboardPage';
import { LiveTrafficPage } from './pages/LiveTrafficPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { AlertsPage } from './pages/AlertsPage';
import { IPIntelligencePage } from './pages/IPIntelligencePage';
import { TrafficAnalysisPage } from './pages/TrafficAnalysisPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';
import { AboutPage } from './pages/AboutPage';

export function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  
  const {
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
    refreshAll,
    startMonitoring,
    stopMonitoring,
    resetMonitoring,
  } = useNIDSData(2500);

  const renderActivePage = () => {
    switch (activeTab) {
      case 'dashboard':
        return (
          <DashboardPage
            statusData={statusData}
            dashboardData={dashboardData}
            trafficData={trafficData}
            currentRate={currentRate}
            threatsData={threatsData}
            alertsData={alertsData}
            error={error}
          />
        );
      case 'live-traffic':
        return (
          <LiveTrafficPage
            dashboardData={dashboardData}
            trafficData={trafficData}
            currentRate={currentRate}
          />
        );
      case 'threats':
        return (
          <ThreatsPage
            threatsData={threatsData}
            dashboardData={dashboardData}
          />
        );
      case 'alerts':
        return (
          <AlertsPage
            alertsData={alertsData}
          />
        );
      case 'ip-intelligence':
        return (
          <IPIntelligencePage
            dashboardData={dashboardData}
          />
        );
      case 'traffic-analysis':
        return (
          <TrafficAnalysisPage
            dashboardData={dashboardData}
            trafficData={trafficData}
          />
        );
      case 'reports':
        return (
          <ReportsPage
            dashboardData={dashboardData}
            statusData={statusData}
          />
        );
      case 'settings':
        return (
          <SettingsPage
            interfaces={interfaces}
            statusData={statusData}
            onReset={resetMonitoring}
          />
        );
      case 'about':
        return <AboutPage />;
      default:
        return (
          <DashboardPage
            statusData={statusData}
            dashboardData={dashboardData}
            trafficData={trafficData}
            currentRate={currentRate}
            threatsData={threatsData}
            alertsData={alertsData}
            error={error}
          />
        );
    }
  };

  return (
    <div className="app-container">
      {/* Left Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        statusData={statusData}
      />

      {/* Main Content Area */}
      <div className="main-wrapper">
        <Topbar
          activeTab={activeTab}
          statusData={statusData}
          interfaces={interfaces}
          actionLoading={actionLoading}
          onStart={startMonitoring}
          onStop={stopMonitoring}
          onRefresh={refreshAll}
          lastUpdated={lastUpdated}
        />

        <main className="content-body">
          {renderActivePage()}
        </main>
      </div>
    </div>
  );
}

export default App;
