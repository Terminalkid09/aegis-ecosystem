import React from 'react';
import {
  BarChart3,
  AlertCircle,
  Shield,
  Settings,
  LogOut,
} from 'lucide-react';
import { useDashboard } from '../context/DashboardContext';

export default function Sidebar() {
  const { currentPage, setCurrentPage, settings } = useDashboard();

  const menuItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: BarChart3,
    },
    {
      id: 'alerts',
      label: 'Alerts',
      icon: AlertCircle,
    },
    {
      id: 'agents',
      label: 'Agents',
      icon: Shield,
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: Settings,
    },
  ];

  const sidebarClass = settings.darkMode
    ? 'bg-gradient-to-b from-slate-900 to-slate-800 text-white border-slate-700'
    : 'bg-gradient-to-b from-slate-100 to-slate-200 text-slate-900 border-slate-300';

  const panelClass = settings.darkMode
    ? 'bg-slate-900 border-slate-700'
    : 'bg-white border-slate-300';

  return (
    <div className={`w-64 flex flex-col h-screen border-r ${sidebarClass}`}>
      {/* Logo */}
      <div className={`p-6 border-b ${panelClass}`}>
        <div className="flex items-center gap-2">
          <div className="w-10 h-10 bg-gradient-to-br from-cyan-400 to-blue-500 rounded-lg flex items-center justify-center font-bold text-white">
            A
          </div>
          <div>
            <h1 className="text-xl font-bold">AEGIS</h1>
            <p className={settings.darkMode ? 'text-xs text-slate-400' : 'text-xs text-slate-500'}>EDR Dashboard</p>
          </div>
        </div>
      </div>

      {/* Navigation Menu */}
      <nav className="flex-1 px-4 py-6">
        <div className="space-y-2">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentPage(item.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg'
                    : 'text-slate-300 hover:bg-slate-700 hover:text-white'
                }`}
              >
                <Icon size={20} />
                <span className="font-medium">{item.label}</span>
              </button>
            );
          })}
        </div>
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-slate-700">
        <button className="w-full flex items-center gap-3 px-4 py-3 text-slate-300 hover:text-red-400 hover:bg-slate-700 rounded-lg transition-all">
          <LogOut size={20} />
          <span className="text-sm font-medium">Logout</span>
        </button>
      </div>
    </div>
  );
}
