import React, { useState, useEffect } from 'react';
import { AlertTriangle, Shield, Activity, TrendingUp, Cpu, HardDrive } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { statsAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function DashboardOverview() {
  const { refreshTrigger, settings } = useDashboard();
  const [stats, setStats] = useState(null);
  const [telemetry, setTelemetry] = useState([]);
  const [activity, setActivity] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchStats();
  }, [refreshTrigger]);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const response = await statsAPI.getStats();
      const telemetryResponse = await statsAPI.getRecentTelemetry({ limit: 8 });
      const activityResponse = await statsAPI.getActivity({ limit: 10 });
      setStats(response.data);
      setTelemetry(telemetryResponse.data || []);
      setActivity(activityResponse.data || []);
      setError(null);
    } catch (err) {
      setError('Failed to load statistics');
      console.error('Stats fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const chartData = telemetry
    .filter(t => t.agent_type.toLowerCase() === 'nodetrace' && t.cpu_usage !== null && t.ram_usage !== null)
    .map(t => ({
      time: new Date(t.timestamp).toLocaleTimeString(),
      cpu: t.cpu_usage,
      ram: t.ram_usage,
      name: t.hostname || t.agent_id
    })).reverse();

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

      {/* Performance Metrics Chart */}
      <div className={`${panelClass} rounded-lg p-6`}>
        <div className="flex items-center justify-between mb-6">
          <h3 className={`text-lg font-bold ${settings.darkMode ? 'text-white' : 'text-slate-900'}`}>System Performance Metrics</h3>
          <div className="flex gap-4 text-xs">
            <div className="flex items-center gap-1"><div className="w-3 h-3 bg-cyan-500 rounded-full"/> <span className="text-slate-400">CPU Usage</span></div>
            <div className="flex items-center gap-1"><div className="w-3 h-3 bg-purple-500 rounded-full"/> <span className="text-slate-400">RAM Usage</span></div>
          </div>
        </div>
        <div className="h-80 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorRam" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#a855f7" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#a855f7" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
              <XAxis 
                dataKey="time" 
                stroke="#64748b" 
                fontSize={10} 
                tickLine={false}
                axisLine={false}
              />
              <YAxis 
                stroke="#64748b" 
                fontSize={10} 
                tickLine={false}
                axisLine={false}
                tickFormatter={(value) => `${value}%`}
              />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#0f172a', 
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  fontSize: '12px'
                }}
                itemStyle={{ padding: '2px 0' }}
              />
              <Area 
                type="monotone" 
                dataKey="cpu" 
                stroke="#06b6d4" 
                strokeWidth={2}
                fillOpacity={1} 
                fill="url(#colorCpu)" 
                name="CPU Usage"
              />
              <Area 
                type="monotone" 
                dataKey="ram" 
                stroke="#a855f7" 
                strokeWidth={2}
                fillOpacity={1} 
                fill="url(#colorRam)" 
                name="RAM Usage"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className={`${panelClass} rounded-lg p-6`}>
          <h3 className={`text-lg font-bold mb-4 ${settings.darkMode ? 'text-white' : 'text-slate-900'}`}>Live Telemetry</h3>
          <div className="space-y-3">
            {telemetry.map(row => (
              <div key={row.id} className="grid grid-cols-[1fr_auto] gap-3 rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                <div>
                  <div className="text-sm font-bold">{row.hostname || row.agent_id}</div>
                  <div className="text-[10px] uppercase tracking-widest text-slate-500">{row.agent_type || 'agent'} / {new Date(row.timestamp).toLocaleTimeString()}</div>
                </div>
                <div className="flex items-center gap-3 text-xs text-slate-300">
                  <span className="inline-flex items-center gap-1"><Cpu size={13}/>{Number(row.cpu_usage || 0).toFixed(1)}%</span>
                  <span className="inline-flex items-center gap-1"><Activity size={13}/>{Number(row.ram_usage || 0).toFixed(1)}%</span>
                  <span className="inline-flex items-center gap-1"><HardDrive size={13}/>{formatDisk(row.disk_free)}</span>
                </div>
              </div>
            ))}
            {telemetry.length === 0 && <div className="text-sm text-slate-500 italic">No telemetry samples received yet.</div>}
          </div>
        </div>

        <div className={`${panelClass} rounded-lg p-6`}>
          <h3 className={`text-lg font-bold mb-4 ${settings.darkMode ? 'text-white' : 'text-slate-900'}`}>Activity Stream</h3>
          <div className="space-y-3">
            {activity.map((item, index) => (
              <div key={`${item.type}-${item.timestamp}-${index}`} className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                <div className={`mt-1 h-2.5 w-2.5 rounded-full ${item.type === 'alert' ? 'bg-red-500' : 'bg-green-500'}`} />
                <div>
                  <div className="text-sm">{item.summary}</div>
                  <div className="text-[10px] uppercase tracking-widest text-slate-500">{item.hostname || item.agent_id} / {new Date(item.timestamp).toLocaleTimeString()}</div>
                </div>
              </div>
            ))}
            {activity.length === 0 && <div className="text-sm text-slate-500 italic">No agent activity received yet.</div>}
          </div>
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

function formatDisk(value) {
  if (!value) return 'n/a';
  if (value > 1024) return `${(value / 1024).toFixed(1)} GB`;
  return `${value} MB`;
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

