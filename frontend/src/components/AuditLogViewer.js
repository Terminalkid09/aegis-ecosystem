import React, { useState, useEffect } from 'react';
import { auditAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';
import { ClipboardList } from 'lucide-react';

export default function AuditLogViewer() {
  const { settings } = useDashboard();
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await auditAPI.getLogs({ limit: 200 });
      setLogs(res.data || []);
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Audit Log</h2>
        <button onClick={fetchLogs} className="text-xs bg-slate-700 hover:bg-slate-600 px-3 py-1.5 rounded font-bold">
          Refresh
        </button>
      </div>

      {loading ? (
        <div className="text-slate-500 italic">Loading audit logs...</div>
      ) : logs.length === 0 ? (
        <div className="text-slate-500 italic">No audit log entries yet.</div>
      ) : (
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-400 text-xs uppercase tracking-wider border-b border-slate-700">
                <th className="text-left p-2">Time</th>
                <th className="text-left p-2">User</th>
                <th className="text-left p-2">Action</th>
                <th className="text-left p-2">Resource</th>
                <th className="text-left p-2">Details</th>
                <th className="text-left p-2">IP</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((l) => (
                <tr key={l.id} className="border-b border-slate-800 hover:bg-slate-800/50">
                  <td className="p-2 text-xs text-slate-400 font-mono whitespace-nowrap">{new Date(l.created_at).toLocaleString()}</td>
                  <td className="p-2 text-slate-200">{l.username || 'system'}</td>
                  <td className="p-2">
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-cyan-900 text-cyan-300">{l.action}</span>
                  </td>
                  <td className="p-2 text-slate-300">{l.resource}{l.resource_id ? ` #${l.resource_id}` : ''}</td>
                  <td className="p-2 text-slate-400 max-w-xs truncate">{l.details ? JSON.stringify(l.details) : '-'}</td>
                  <td className="p-2 text-xs text-slate-500 font-mono">{l.ip_address || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
