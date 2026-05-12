import React from 'react';
import { Bell, Lock, Monitor, Zap } from 'lucide-react';
import { useDashboard } from '../context/DashboardContext';

export default function Settings() {
  const { settings, toggleSetting, resetSettings } = useDashboard();

  const handleSave = () => {
    localStorage.setItem('aegis-settings', JSON.stringify(settings));
    alert('Settings saved successfully!');
  };

  const outerClass = settings.darkMode ? 'text-slate-100' : 'text-slate-900';
  const cardClass = settings.darkMode ? 'theme-surface border-slate-700' : 'theme-surface border-slate-300';
  const inputClass = settings.darkMode
    ? 'bg-slate-800 border-slate-700 text-white placeholder-slate-500'
    : 'bg-slate-100 border-slate-300 text-slate-900 placeholder-slate-500';

  return (
    <div className={`space-y-6 ${outerClass}`}>
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold">Settings</h2>
        <p className={settings.darkMode ? 'text-slate-400 mt-1' : 'text-slate-600 mt-1'}>
          Configure your dashboard preferences
        </p>
      </div>

      {/* Settings Cards */}
      <div className="space-y-4">
        <SettingCard
          icon={Bell}
          title="Notifications"
          description="Enable desktop notifications for new alerts"
          enabled={settings.notifications}
          onChange={() => toggleSetting('notifications')}
          darkMode={settings.darkMode}
        />

        <SettingCard
          icon={Zap}
          title="Auto Refresh"
          description="Automatically refresh data every 30 seconds"
          enabled={settings.autoRefresh}
          onChange={() => toggleSetting('autoRefresh')}
          darkMode={settings.darkMode}
        />

        <SettingCard
          icon={Monitor}
          title="Dark Mode"
          description="Use dark theme for better visibility"
          enabled={settings.darkMode}
          onChange={() => toggleSetting('darkMode')}
          darkMode={settings.darkMode}
        />

        <SettingCard
          icon={Zap}
          title="Sound Alerts"
          description="Play sound on critical threats"
          enabled={settings.soundAlerts}
          onChange={() => toggleSetting('soundAlerts')}
          darkMode={settings.darkMode}
        />
      </div>

      {/* API Configuration */}
      <div className={`rounded-lg p-6 ${cardClass}`}>
        <div className="flex items-center gap-3 mb-4">
          <Lock size={24} className="text-cyan-400" />
          <h3 className="text-lg font-bold">API Configuration</h3>
        </div>
        <div className="space-y-4">
          <div>
            <label className="block text-slate-500 text-sm font-medium mb-2">
              API Base URL
            </label>
            <input
              type="text"
              defaultValue="http://localhost:8000/api/v1"
              className={`w-full px-4 py-2 rounded-lg focus:outline-none focus:border-cyan-500 transition-all font-mono text-sm ${inputClass}`}
            />
            <p className="text-slate-500 text-xs mt-2">
              Configure the backend API endpoint
            </p>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex flex-wrap gap-4">
        <button
          onClick={handleSave}
          className="px-6 py-3 btn-gradient"
        >
          Save Settings
        </button>
        <button
          onClick={resetSettings}
          className="px-6 py-3 bg-slate-200 text-slate-900 rounded-lg border border-slate-300 hover:bg-slate-300 transition-all"
        >
          Reset to Default
        </button>
      </div>

      {/* About */}
      <div className={`rounded-lg p-6 ${cardClass}`}>
        <h3 className="text-lg font-bold mb-3">About</h3>
        <div className="space-y-2 text-slate-500 text-sm">
          <p>
            <span className="font-medium text-slate-900">Application:</span> AEGIS EDR Dashboard
          </p>
          <p>
            <span className="font-medium text-slate-900">Version:</span> 1.0.0
          </p>
          <p>
            <span className="font-medium text-slate-900">Built with:</span> React, Tailwind CSS, Lucide React
          </p>
        </div>
      </div>
    </div>
  );
}

function SettingCard({ icon: Icon, title, description, enabled, onChange, darkMode }) {
  return (
    <div className={`rounded-lg p-6 border ${darkMode ? 'border-slate-700 bg-slate-900' : 'border-slate-300 bg-white'} transition-all hover:border-slate-600`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="bg-gradient-to-br from-cyan-500 to-blue-500 p-3 rounded-lg">
            <Icon size={24} className="text-white" />
          </div>
          <div>
            <h3 className={darkMode ? 'font-bold text-white' : 'font-bold text-slate-900'}>{title}</h3>
            <p className={darkMode ? 'text-slate-400 text-sm' : 'text-slate-600 text-sm'}>{description}</p>
          </div>
        </div>
        <button
          onClick={onChange}
          className={`relative inline-flex h-8 w-14 items-center rounded-full transition-all ${enabled ? 'bg-gradient-to-r from-cyan-500 to-blue-500' : darkMode ? 'bg-slate-700' : 'bg-slate-200'}`}
        >
          <span
            className={`inline-block h-6 w-6 transform rounded-full bg-white transition-all ${
              enabled ? 'translate-x-7' : 'translate-x-1'
            }`}
          />
        </button>
      </div>
    </div>
  );
}
