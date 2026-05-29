import React from 'react';
import {
  BarChart3,
  AlertCircle,
  Shield,
  Lock,
  Globe,
  Bot,
  Settings,
  LogOut,
} from 'lucide-react';
import { useDashboard } from '../context/DashboardContext';

export default function Sidebar() {
  const { currentPage, setCurrentPage, settings } = useDashboard();

  const menuItems = [
    {
      id: 'dashboard',
      label: 'Overview',
      icon: BarChart3,
    },
    {
      id: 'alerts',
      label: 'Threat Monitor',
      icon: AlertCircle,
    },
    {
      id: 'agents',
      label: 'Endpoints',
      icon: Shield,
    },
    {
        id: 'osint',
        label: 'SentinelX (OSINT)',
        icon: Globe,
    },
    {
        id: 'ai',
        label: 'AI Analyst',
        icon: Bot,
    },
    {
        id: 'vault',
        label: 'VaultX (Notes)',
        icon: Lock,
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: Settings,
    },
  ];

  const sidebarClass = settings.darkMode
    ? 'bg-gradient-to-b from-slate-950 to-slate-900 text-white border-slate-800'
    : 'bg-gradient-to-b from-slate-100 to-slate-200 text-slate-900 border-slate-300';

  const logoPanelClass = settings.darkMode
    ? 'bg-slate-950 border-slate-800'
    : 'bg-white border-slate-300';

  return (
    <div className={`w-72 flex flex-col h-screen border-r ${sidebarClass} shadow-2xl`}>
      {/* Logo */}
      <div className={`p-8 border-b ${logoPanelClass}`}>
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 bg-gradient-to-br from-cyan-400 to-blue-600 rounded-xl flex items-center justify-center font-black text-xl text-white shadow-[0_0_20px_rgba(6,182,212,0.3)]">
            A
          </div>
          <div>
            <h1 className="text-2xl font-black tracking-tighter">AEGIS XDR</h1>
            <p className={settings.darkMode ? 'text-[10px] text-slate-500 uppercase tracking-widest font-bold' : 'text-[10px] text-slate-500 uppercase tracking-widest font-bold'}>Secure Monolith</p>
          </div>
        </div>
      </div>

      {/* Navigation Menu */}
      <nav className="flex-1 px-4 py-8 overflow-y-auto">
        <div className="space-y-1.5">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            const isSpecial = ['osint', 'ai', 'vault'].includes(item.id);

            return (
              <button
                key={item.id}
                onClick={() => setCurrentPage(item.id)}
                className={`w-full flex items-center gap-4 px-5 py-3.5 rounded-xl transition-all duration-300 group ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-[0_5px_15px_rgba(8,145,178,0.3)]'
                    : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-100'
                }`}
              >
                <Icon size={20} className={isActive ? 'text-white' : isSpecial ? 'text-purple-500 group-hover:text-purple-400' : 'text-slate-500 group-hover:text-cyan-400'} />
                <span className="font-bold text-sm">{item.label}</span>
              </button>
            );
          })}
        </div>
      </nav>

      {/* Footer */}
      <div className="p-6 border-t border-slate-800">
        <button className="w-full flex items-center gap-4 px-5 py-3 text-slate-500 hover:text-red-400 hover:bg-red-950/20 rounded-xl transition-all font-bold text-sm">
          <LogOut size={20} />
          <span>Terminate Session</span>
        </button>
      </div>
    </div>
  );
}
