import React, { useState, useEffect } from 'react';
import { syslogAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';
import { Activity } from 'lucide-react';

const SEVERITY_LABELS = { 0:'Emerg', 1:'Alert', 2:'Crit', 3:'Error', 4:'Warn', 5:'Notice', 6:'Info', 7:'Debug' };

export default function SyslogViewer() {
  const { settings } = useDashboard();
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchEvents();
  }, []);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const res = await syslogAPI.getEvents({ limit: 200 });
      setEvents(res.data || []);
    } catch (err) {
      console.error('Failed to fetch syslog events:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Syslog Events</h2>
        <button onClick={fetchEvents} className="text-xs bg-slate-700 hover:bg-slate-600 px-3 py-1.5 rounded font-bold">
          Refresh
        </button>
      </div>

      {loading ? (
        <div className="text-slate-500 italic">Loading syslog events...</div>
      ) : events.length === 0 ? (
        <div className="text-slate-500 italic">No syslog events received yet. Ensure aegis-link is forwarding syslog on UDP 1514.</div>
      ) : (
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-400 text-xs uppercase tracking-wider border-b border-slate-700">
                <th className="text-left p-2">Timestamp</th>
                <th className="text-left p-2">Severity</th>
                <th className="text-left p-2">Hostname</th>
                <th className="text-left p-2">App</th>
                <th className="text-left p-2">Message</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="border-b border-slate-800 hover:bg-slate-800/50">
                  <td className="p-2 text-xs text-slate-400 font-mono whitespace-nowrap">{new Date(e.timestamp).toLocaleString()}</td>
                  <td className="p-2">
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                      e.severity <= 1 ? 'bg-red-900 text-red-300' :
                      e.severity <= 3 ? 'bg-orange-900 text-orange-300' :
                      e.severity <= 5 ? 'bg-yellow-900 text-yellow-300' :
                      'bg-slate-700 text-slate-300'
                    }`}>{SEVERITY_LABELS[e.severity] || e.severity}</span>
                  </td>
                  <td className="p-2 text-slate-300">{e.hostname || '-'}</td>
                  <td className="p-2 text-slate-400">{e.app_name || '-'}</td>
                  <td className="p-2 text-slate-200 max-w-lg truncate">{e.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
