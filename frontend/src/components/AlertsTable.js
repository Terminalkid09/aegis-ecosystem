import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  Filter,
} from 'lucide-react';
import { alertsAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function AlertsTable() {
  const { refreshTrigger, refreshData, settings } = useDashboard();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [resolvedFilter, setResolvedFilter] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);
  const [resolving, setResolving] = useState({});
  const previousAlertsRef = useRef([]);

  useEffect(() => {
    fetchAlerts();
  }, [refreshTrigger, severityFilter, resolvedFilter]);

  useEffect(() => {
    if (settings.notifications && 'Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }, [settings.notifications]);

  const notifyNewAlerts = (newAlerts) => {
    if (!('Notification' in window) || Notification.permission !== 'granted') {
      return;
    }

    const newest = newAlerts[0];
    new Notification('AEGIS Alert', {
      body: `${newAlerts.length} new alert${newAlerts.length > 1 ? 's' : ''}: ${newest.event_type}`,
      icon: '/favicon.ico',
    });
  };

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const params = {
        limit: 1000,
        offset: 0,
      };
      if (severityFilter) params.severity = severityFilter;
      if (resolvedFilter !== '') params.is_resolved = resolvedFilter === 'resolved';

      const response = await alertsAPI.getAlerts(params);
      const data = response.data || [];
      if (settings.notifications && previousAlertsRef.current.length > 0) {
        const previousIds = new Set(previousAlertsRef.current.map((alert) => alert.id));
        const newAlerts = data.filter((alert) => !previousIds.has(alert.id));
        if (newAlerts.length > 0) {
          notifyNewAlerts(newAlerts);
        }
      }
      previousAlertsRef.current = data;
      setAlerts(data);
      setError(null);
    } catch (err) {
      setError('Failed to load alerts');
      console.error('Alerts fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleResolve = async (alertId) => {
    try {
      setResolving((prev) => ({ ...prev, [alertId]: true }));
      await alertsAPI.resolveAlert(alertId, true);
      refreshData();
      setResolving((prev) => ({ ...prev, [alertId]: false }));
    } catch (err) {
      console.error('Failed to resolve alert:', err);
      setResolving((prev) => ({ ...prev, [alertId]: false }));
    }
  };

  const filteredAlerts = alerts.filter((alert) => {
    const searchLower = searchTerm.toLowerCase();
    return (
      alert.process_name?.toLowerCase().includes(searchLower) ||
      alert.agent_id?.toLowerCase().includes(searchLower) ||
      alert.event_type?.toLowerCase().includes(searchLower)
    );
  });

  const totalPages = Math.ceil(filteredAlerts.length / itemsPerPage);
  const startIdx = (currentPage - 1) * itemsPerPage;
  const paginatedAlerts = filteredAlerts.slice(startIdx, startIdx + itemsPerPage);

  const getSeverityBadgeColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-900 text-red-300 border border-red-700';
      case 'HIGH':
        return 'bg-orange-900 text-orange-300 border border-orange-700';
      case 'MEDIUM':
        return 'bg-yellow-900 text-yellow-300 border border-yellow-700';
      case 'LOW':
        return 'bg-blue-900 text-blue-300 border border-blue-700';
      default:
        return 'bg-slate-700 text-slate-300 border border-slate-600';
    }
  };

  const containerClass = settings.darkMode ? 'text-white' : 'text-slate-900';
  const panelClass = settings.darkMode ? 'bg-slate-900 border-slate-700 text-white' : 'bg-white border-slate-200 text-slate-900';
  const inputClass = settings.darkMode ? 'bg-slate-800 border-slate-700 text-white placeholder-slate-500' : 'bg-slate-100 border-slate-300 text-slate-900 placeholder-slate-500';
  const selectClass = inputClass;

  return (
    <div className={`space-y-6 ${containerClass}`}>
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold">Alerts</h2>
        <p className={settings.darkMode ? 'text-slate-400 mt-1' : 'text-slate-600 mt-1'}>Monitor and manage detected threats</p>
      </div>

      {/* Filters */}
      <div className={`rounded-lg p-4 border ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Search */}
          <div className="relative">
            <Search
              size={18}
              className="absolute left-3 top-3 text-slate-400"
            />
            <input
              type="text"
              placeholder="Search process, agent, or event type..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              className={`w-full pl-10 pr-4 py-2 rounded-lg focus:outline-none focus:border-cyan-500 transition-all ${inputClass}`}
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setCurrentPage(1);
            }}
            className={`px-4 py-2 rounded-lg focus:outline-none focus:border-cyan-500 transition-all ${selectClass}`}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Resolution Filter */}
          <select
            value={resolvedFilter}
            onChange={(e) => {
              setResolvedFilter(e.target.value);
              setCurrentPage(1);
            }}
            className={`px-4 py-2 rounded-lg focus:outline-none focus:border-cyan-500 transition-all ${selectClass}`}
          >
            <option value="">All Statuses</option>
            <option value="unresolved">Unresolved</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div className="flex items-center justify-center h-96">
          <div className="text-slate-400">Loading alerts...</div>
        </div>
      ) : error ? (
        <div className="bg-red-950 border border-red-700 rounded-lg p-4 text-red-400">
          {error}
        </div>
      ) : filteredAlerts.length === 0 ? (
        <div className={`rounded-lg p-12 text-center border ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
          <Filter size={48} className={settings.darkMode ? 'mx-auto text-slate-500 mb-4' : 'mx-auto text-slate-400 mb-4'} />
          <p className={settings.darkMode ? 'text-slate-400' : 'text-slate-600'}>No alerts found</p>
        </div>
      ) : (
        <>
          <div className={`rounded-lg overflow-hidden border ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className={settings.darkMode ? 'bg-slate-800 border-b border-slate-700' : 'bg-slate-100 border-b border-slate-200'}>
                    <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${settings.darkMode ? 'text-slate-300' : 'text-slate-500'}`}>
                      Timestamp
                    </th>
                    <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${settings.darkMode ? 'text-slate-300' : 'text-slate-500'}`}>
                      Agent ID
                    </th>
                    <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${settings.darkMode ? 'text-slate-300' : 'text-slate-500'}`}>
                      Severity
                    </th>
                    <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${settings.darkMode ? 'text-slate-300' : 'text-slate-500'}`}>
                      Process Name
                    </th>
                    <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${settings.darkMode ? 'text-slate-300' : 'text-slate-500'}`}>
                      Event Type
                    </th>
                    <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${settings.darkMode ? 'text-slate-300' : 'text-slate-500'}`}>
                      Status
                    </th>
                    <th className={`px-6 py-4 text-left text-xs font-bold uppercase tracking-wider ${settings.darkMode ? 'text-slate-300' : 'text-slate-500'}`}>
                      Action
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedAlerts.map((alert) => (
                    <tr
                      key={alert.id}
                      className={`border-b ${settings.darkMode ? 'border-slate-700 hover:bg-slate-800' : 'border-slate-200 hover:bg-slate-50'} transition-all`}
                    >
                      <td className="px-6 py-4 text-sm text-slate-300">
                        {new Date(alert.timestamp).toLocaleString()}
                      </td>
                      <td className={`px-6 py-4 text-sm font-mono ${settings.darkMode ? 'text-cyan-400' : 'text-cyan-600'}`}>
                        {alert.agent_id}
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <span
                          className={`px-3 py-1 rounded-full text-xs font-bold ${getSeverityBadgeColor(
                            alert.severity
                          )}`}
                        >
                          {alert.severity}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-300">
                        {alert.process_name}
                      </td>
                      <td className={`px-6 py-4 text-sm ${settings.darkMode ? 'text-slate-400' : 'text-slate-600'}`}>
                        {alert.event_type}
                      </td>
                      <td className="px-6 py-4 text-sm">
                        {alert.is_resolved ? (
                          <span className="flex items-center gap-2 text-green-400">
                            <CheckCircle2 size={16} />
                            Resolved
                          </span>
                        ) : (
                          <span className="flex items-center gap-2 text-orange-400">
                            <AlertTriangle size={16} />
                            Unresolved
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-sm">
                        {!alert.is_resolved && (
                          <button
                            onClick={() => handleResolve(alert.id)}
                            disabled={resolving[alert.id]}
                            className="px-3 py-1 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white rounded text-xs font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {resolving[alert.id] ? 'Resolving...' : 'Resolve'}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between">
            <p className={settings.darkMode ? 'text-slate-400 text-sm' : 'text-slate-500 text-sm'}>
              Showing {startIdx + 1} to {Math.min(startIdx + itemsPerPage, filteredAlerts.length)} of{' '}
              {filteredAlerts.length} alerts
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
                disabled={currentPage === 1}
                className="p-2 border border-slate-700 rounded-lg text-slate-300 hover:border-slate-600 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeft size={20} />
              </button>
              <div className="flex items-center gap-2">
                {Array.from({ length: totalPages }).map((_, i) => (
                  <button
                    key={i + 1}
                    onClick={() => setCurrentPage(i + 1)}
                    className={`px-3 py-1 rounded-lg text-sm font-medium transition-all ${
                      currentPage === i + 1
                        ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white'
                        : 'border border-slate-700 text-slate-300 hover:border-slate-600'
                    }`}
                  >
                    {i + 1}
                  </button>
                ))}
              </div>
              <button
                onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}
                disabled={currentPage === totalPages}
                className="p-2 border border-slate-700 rounded-lg text-slate-300 hover:border-slate-600 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronRight size={20} />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
