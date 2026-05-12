import React, { useState, useEffect } from 'react';
import { AlertTriangle, Shield, Activity, TrendingUp } from 'lucide-react';
import { statsAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function DashboardOverview() {
  const { refreshTrigger, settings } = useDashboard();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchStats();
  }, [refreshTrigger]);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const response = await statsAPI.getStats();
      setStats(response.data);
      setError(null);
    } catch (err) {
      setError('Failed to load statistics');
      console.error('Stats fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const getThreatLevel = () => {
    if (!stats) return { level: 'UNKNOWN', color: 'text-slate-500', bgColor: 'bg-slate-900' };
    
    const criticalCount = stats.current_critical_alerts || 0;
    const highCount = stats.current_high_alerts || 0;
    
    if (criticalCount > 0) {
      return { level: 'CRITICAL', color: 'text-red-500', bgColor: 'bg-red-950' };
    } else if (highCount > 2) {
      return { level: 'WARNING', color: 'text-orange-500', bgColor: 'bg-orange-950' };
    } else {
      return { level: 'NORMAL', color: 'text-green-500', bgColor: 'bg-green-950' };
    }
  };

  const threatLevel = getThreatLevel();

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className={settings.darkMode ? 'text-slate-400' : 'text-slate-500'}>Loading statistics...</div>
      </div>
    );
  }

  const sectionClass = settings.darkMode
    ? 'text-white'
    : 'text-slate-900';

  const panelClass = settings.darkMode
    ? 'bg-slate-900 border border-slate-700'
    : 'bg-white border border-slate-200';

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h2 className={`text-3xl font-bold ${sectionClass}`}>Dashboard</h2>
        <p className={settings.darkMode ? 'text-slate-500 mt-1' : 'text-slate-600 mt-1'}>Real-time security overview</p>
      </div>

      {/* Threat Level Indicator */}
      <div className={`${threatLevel.bgColor} border border-slate-700 rounded-lg p-6`}>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-slate-300 text-sm font-medium uppercase tracking-wider">
              Threat Level
            </h3>
            <p className={`text-4xl font-bold mt-2 ${threatLevel.color}`}>
              {threatLevel.level}
            </p>
          </div>
          <div className={`${threatLevel.color} opacity-20`}>
            <AlertTriangle size={64} />
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Alerts Card */}
        <StatCard
          label="Total Alerts"
          value={stats?.total_alerts || 0}
          icon={AlertTriangle}
          color="from-red-500 to-red-600"
          iconColor="text-red-400"
          darkMode={settings.darkMode}
        />

        {/* Unresolved Threats Card */}
        <StatCard
          label="Unresolved Threats"
          value={stats?.unresolved_alerts || 0}
          icon={Shield}
          color="from-orange-500 to-orange-600"
          iconColor="text-orange-400"
          darkMode={settings.darkMode}
        />

        {/* Active Agents Card */}
        <StatCard
          label="Active Agents"
          value={stats?.active_agents || 0}
          icon={Activity}
          color="from-green-500 to-green-600"
          iconColor="text-green-400"
          darkMode={settings.darkMode}
        />

        {/* Critical Threats Card */}
        <StatCard
          label="Critical Threats"
          value={stats?.current_critical_alerts || 0}
          icon={TrendingUp}
          color="from-purple-500 to-purple-600"
          iconColor="text-purple-400"
          darkMode={settings.darkMode}
        />
      </div>

      {/* Severity Breakdown */}
      <div className={`${panelClass} rounded-lg p-6`}>
        <h3 className={`text-lg font-bold mb-6 ${settings.darkMode ? 'text-white' : 'text-slate-900'}`}>Alerts by Severity (Current)</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <SeverityItem
            label="Critical"
            count={stats?.current_critical_alerts || 0}
            color="bg-red-500"
            textColor="text-red-400"
          />
          <SeverityItem
            label="High"
            count={stats?.current_high_alerts || 0}
            color="bg-orange-500"
            textColor="text-orange-400"
          />
          <SeverityItem
            label="Medium"
            count={stats?.current_medium_alerts || 0}
            color="bg-yellow-500"
            textColor="text-yellow-400"
          />
          <SeverityItem
            label="Low"
            count={stats?.current_low_alerts || 0}
            color="bg-blue-500"
            textColor="text-blue-400"
          />
        </div>
      </div>

      {error && (
        <div className="bg-red-950 border border-red-700 rounded-lg p-4 text-red-400">
          {error}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, icon: Icon, color, iconColor, darkMode }) {
  return (
    <div className={`rounded-lg p-6 transition-all hover:shadow-lg ${darkMode ? 'bg-slate-900 border border-slate-700 hover:border-slate-600 hover:shadow-slate-900 text-white' : 'bg-white border border-slate-200 hover:border-slate-300 hover:shadow-slate-200 text-slate-900'}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className={`text-sm font-medium uppercase tracking-wider ${darkMode ? 'text-slate-400' : 'text-slate-500'}`}>
            {label}
          </p>
          <p className="text-4xl font-bold mt-2">{value}</p>
        </div>
        <div className={`bg-gradient-to-br ${color} p-3 rounded-lg ${iconColor}`}>
          <Icon size={24} />
        </div>
      </div>
    </div>
  );
}

function SeverityItem({ label, count, color, textColor }) {
  return (
    <div className="text-center">
      <div className={`inline-flex items-center justify-center w-12 h-12 rounded-full ${color} ${textColor} font-bold text-lg mb-2`}>
        {count}
      </div>
      <p className="text-slate-400 text-sm">{label}</p>
    </div>
  );
}
