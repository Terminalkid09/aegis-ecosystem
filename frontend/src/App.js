import React from 'react';
import { RefreshCcw } from 'lucide-react';
import { DashboardProvider, useDashboard } from './context/DashboardContext';
import Sidebar from './components/Sidebar';
import DashboardOverview from './components/DashboardOverview';
import AlertsTable from './components/AlertsTable';
import AgentsList from './components/AgentsList';
import Settings from './components/Settings';
import './styles/index.css';

function AppContent() {
  const { currentPage, manualRefresh, settings } = useDashboard();

  const renderContent = () => {
    switch (currentPage) {
      case 'dashboard':
        return <DashboardOverview />;
      case 'alerts':
        return <AlertsTable />;
      case 'agents':
        return <AgentsList />;
      case 'settings':
        return <Settings />;
      default:
        return <DashboardOverview />;
    }
  };

  const outerClass = settings.darkMode
    ? 'flex h-screen bg-slate-950 text-slate-100'
    : 'flex h-screen bg-slate-100 text-slate-900';

  const barClass = settings.darkMode
    ? 'bg-gradient-to-r from-slate-900 to-slate-800 border-b border-slate-700'
    : 'bg-gradient-to-r from-slate-200 to-slate-100 border-b border-slate-300';

  const titleClass = settings.darkMode ? 'text-slate-200' : 'text-slate-900';
  const statusTextClass = settings.darkMode ? 'text-slate-400' : 'text-slate-600';

  return (
    <div className={outerClass}>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Bar */}
        <div className={`${barClass} px-8 py-4 flex items-center justify-between`}>
          <div>
            <h1 className={`${titleClass} font-bold`}>AEGIS EDR Dashboard</h1>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={manualRefresh}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-800 px-4 py-2 text-sm text-slate-100 transition-all hover:bg-slate-700 hover:border-slate-500"
            >
              <RefreshCcw size={16} />
              Refresh
            </button>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span className={`text-sm ${statusTextClass}`}>System Online</span>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 overflow-auto">
          <div className="p-8">{renderContent()}</div>
        </div>
      </div>
    </div>
  );
}

function App() {
  return (
    <DashboardProvider>
      <AppContent />
    </DashboardProvider>
  );
}

export default App;
