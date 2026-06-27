import React, { useState, useEffect } from 'react';
import { RefreshCcw } from 'lucide-react';
import { DashboardProvider, useDashboard } from './context/DashboardContext';
import Sidebar from './components/Sidebar';
import DashboardOverview from './components/DashboardOverview';
import AlertsTable from './components/AlertsTable';
import AgentsList from './components/AgentsList';
import VaultX from './components/VaultX';
import SentinelX from './components/SentinelX';
import AIChat from './components/AIChat';
import Settings from './components/Settings';
import RulesManager from './components/RulesManager';
import DiscoveryCenter from './components/DiscoveryCenter';
import AuthButton from './components/AuthButton';
import './styles/index.css';

function AppContent() {
  const { currentPage, manualRefresh, settings } = useDashboard();
  const [user, setUser] = useState(null);

  useEffect(() => {
    const load = () => {
      try {
        const u = JSON.parse(localStorage.getItem('aegis_user'));
        setUser(u);
      } catch {
        setUser(null);
      }
    };
    load();
    window.addEventListener('storage', load);
    window.addEventListener('aegis-auth-changed', load);
    return () => {
      window.removeEventListener('storage', load);
      window.removeEventListener('aegis-auth-changed', load);
    };
  }, []);

  const renderContent = () => {
    if (!user) {
        return (
            <div className="flex flex-col items-center justify-center h-full text-slate-400">
                <div className="text-2xl font-black mb-4">ACCESS DENIED</div>
                <p>Please authenticate to access the Security Operations Center.</p>
            </div>
        );
    }
    switch (currentPage) {
      case 'dashboard':
        return <DashboardOverview />;
      case 'alerts':
        return <AlertsTable />;
      case 'agents':
        return <AgentsList />;
      case 'vault':
        return <VaultX />;
      case 'osint':
        return <SentinelX />;
      case 'ai':
        return <AIChat />;
      case 'settings':
        return <Settings />;
      case 'rules':
        return <RulesManager />;
      case 'discovery':
        return <DiscoveryCenter />;
      default:
        return <DashboardOverview />;
    }
  };

  const outerClass = settings.darkMode
    ? 'flex h-screen bg-slate-950 text-slate-100'
    : 'flex h-screen bg-slate-100 text-slate-900';

  const barClass = settings.darkMode
    ? 'bg-gradient-to-r from-slate-900 to-slate-900 border-b border-slate-800'
    : 'bg-gradient-to-r from-slate-200 to-slate-100 border-b border-slate-300';

  return (
    <div className={outerClass}>
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Bar */}
        <div className={`${barClass} px-8 py-5 flex items-center justify-between shadow-sm z-10`}>
          <div>
            <h1 className="text-sm font-black uppercase tracking-widest text-slate-500">
                Security Operations Center <span className="text-cyan-500 mx-2">/</span> 
                <span className="text-slate-200">{currentPage.toUpperCase()}</span>
            </h1>
          </div>
          <div className="flex items-center gap-6">
            <button
              onClick={manualRefresh}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/50 px-4 py-2 text-xs font-bold text-slate-300 transition-all hover:bg-slate-700 hover:text-white"
            >
              <RefreshCcw size={14} />
              SYNC ASSETS
            </button>
            <div className="flex items-center gap-3 pl-6 border-l border-slate-800">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse shadow-[0_0_10px_#22c55e]"></div>
              <span className="text-[10px] font-black uppercase tracking-tighter text-slate-400">Node Status: <span className="text-green-500">Optimal</span></span>
            </div>
            <div className="pl-6">
              <AuthButton />
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 overflow-auto bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')]">
          <div className="p-8 max-w-[1600px] mx-auto">{renderContent()}</div>
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
