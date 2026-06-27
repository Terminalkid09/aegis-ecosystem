import React, { useState, useEffect } from 'react';
import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import { alertsAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function AlertsTable() {
  const { refreshTrigger, refreshData, settings } = useDashboard();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAlerts();
  }, [refreshTrigger]);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const res = await alertsAPI.getAlerts();
      setAlerts(res.data || []);
    } finally {
      setLoading(false);
    }
  };

  const handleResolve = async (id) => {
    await alertsAPI.resolveAlert(id);
    refreshData();
  };

  const resolveStatus = (a) => [true, 't', 'true', 1, '1'].includes(a.is_resolved);
  const unresolved = alerts.filter(a => !resolveStatus(a));
  const resolved = alerts.filter(a => resolveStatus(a));

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Threat Threads</h2>

      {/* Unresolved */}
      <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
        <h3 className="text-red-500 font-bold mb-4 flex items-center gap-2"><AlertTriangle size={18}/> Unresolved ({unresolved.length})</h3>
        {unresolved.map(a => (
          <div key={a.id} className="flex justify-between items-center bg-slate-800 p-3 rounded mb-2 border-l-4 border-red-500">
            <div>
              <span className="font-bold">{a.process_name}</span> - <span className="text-xs text-slate-400">{a.event_type}</span>
            </div>
            <button onClick={() => handleResolve(a.id)} className="text-xs bg-cyan-700 hover:bg-cyan-600 px-3 py-1 rounded">Resolve</button>
          </div>
        ))}
      </div>

      {/* Resolved */}
      <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
        <h3 className="text-green-500 font-bold mb-4 flex items-center gap-2"><CheckCircle2 size={18}/> Resolved ({resolved.length})</h3>
        {resolved.map(a => (
          <div key={a.id} className="flex justify-between items-center bg-slate-800 p-3 rounded mb-2 border-l-4 border-green-500 opacity-60">
            <div>
              <span className="font-bold">{a.process_name}</span> - <span className="text-xs text-slate-400">{a.event_type}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// CheckCircle2 imported from lucide-react
