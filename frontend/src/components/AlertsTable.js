import React, { useState, useEffect, useRef } from 'react';
import { AlertTriangle, CheckCircle2, ExternalLink, Shield, Activity, Server, Clock } from 'lucide-react';
import { alertsAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function AlertsTable() {
  const { refreshTrigger, refreshData, settings } = useDashboard();
  const [unresolved, setUnresolved] = useState([]);
  const [resolved, setResolved] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showResolved, setShowResolved] = useState(false);
  const [detailAlert, setDetailAlert] = useState(null);
  const [detailData, setDetailData] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [bulkActionLoading, setBulkActionLoading] = useState(false);
  const initialLoad = useRef(true);

  useEffect(() => {
    fetchAlerts();
  }, [refreshTrigger]);

  const fetchAlerts = async () => {
    if (initialLoad.current) {
      setLoading(true);
    }
    try {
      const [unresRes, resRes] = await Promise.all([
        alertsAPI.getAlerts({ is_resolved: false, limit: 500 }),
        alertsAPI.getAlerts({ is_resolved: true, limit: 500 }),
      ]);
      setUnresolved(unresRes.data || []);
      setResolved(resRes.data || []);
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
    } finally {
      setLoading(false);
      initialLoad.current = false;
    }
  };

  const handleResolve = async (id) => {
    try {
      await alertsAPI.resolveAlert(id);
      setDetailAlert(null);
      setDetailData(null);
      refreshData();
    } catch (err) {
      console.error('Resolve failed:', err);
    }
  };

  const handleResolveAll = async () => {
    if (!window.confirm('Resolve ALL unresolved alerts? This will mark them as resolved but not delete them.')) return;
    setBulkActionLoading(true);
    try {
      await alertsAPI.resolveAllAlerts();
      refreshData();
    } catch (err) {
      console.error('Resolve all failed:', err);
    } finally {
      setBulkActionLoading(false);
    }
  };

  const handleDeleteAll = async () => {
    if (!window.confirm('DELETE ALL alerts? This cannot be undone.')) return;
    setBulkActionLoading(true);
    try {
      await alertsAPI.deleteAllAlerts();
      refreshData();
    } catch (err) {
      console.error('Delete all failed:', err);
    } finally {
      setBulkActionLoading(false);
    }
  };

  const handleOpenDetail = async (alert) => {
    setDetailAlert(alert);
    setLoadingDetail(true);
    setDetailData(null);
    try {
      const res = await alertsAPI.getAlert(alert.id);
      setDetailData(res.data);
    } catch (err) {
      console.error('Failed to fetch alert detail:', err);
      setDetailData(null);
    } finally {
      setLoadingDetail(false);
    }
  };

  if (loading && unresolved.length === 0 && resolved.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500 italic">Loading alerts...</div>
    );
  }

  const renderAlertRow = (a, isResolved) => (
    <div key={a.id} onClick={() => handleOpenDetail(a)} className={`flex justify-between items-center bg-slate-800 p-3 rounded mb-2 border-l-4 cursor-pointer hover:bg-slate-700/80 transition-colors ${isResolved ? 'border-green-500 opacity-60' : 'border-red-500'}`}>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-bold truncate">{a.process_name}</span>
          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
            a.severity === 'CRITICAL' ? 'bg-red-900 text-red-300' :
            a.severity === 'HIGH' ? 'bg-orange-900 text-orange-300' :
            a.severity === 'MEDIUM' ? 'bg-yellow-900 text-yellow-300' :
            a.severity === 'LOW' ? 'bg-blue-900 text-blue-300' :
            'bg-slate-700 text-slate-300'
          }`}>{a.severity}</span>
        </div>
        <div className="text-xs text-slate-400 mt-0.5 truncate max-w-xl">
          <span className="text-slate-500">[{a.event_type}]</span> {a.description?.slice(0, 150) || a.process_name}
        </div>
      </div>
      <div className="flex items-center gap-2 ml-3 shrink-0" onClick={(e) => e.stopPropagation()}>
        <button onClick={() => handleOpenDetail(a)} className="text-xs bg-slate-700 hover:bg-slate-600 px-2 py-1 rounded" title="View details">
          <ExternalLink size={14} />
        </button>
        {!isResolved && (
          <button onClick={() => handleResolve(a.id)} className="text-xs bg-cyan-700 hover:bg-cyan-600 px-3 py-1 rounded">Resolve</button>
        )}
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">{unresolved.length} Unresolved Threats</h2>
        <div className="flex gap-2">
          <button
            onClick={handleResolveAll}
            disabled={bulkActionLoading || unresolved.length === 0}
            className="text-xs bg-cyan-700 hover:bg-cyan-600 disabled:opacity-40 px-3 py-1.5 rounded font-bold"
          >
            {bulkActionLoading ? 'Processing...' : 'Resolve All'}
          </button>
          <button
            onClick={handleDeleteAll}
            disabled={bulkActionLoading || (unresolved.length === 0 && resolved.length === 0)}
            className="text-xs bg-red-800 hover:bg-red-700 disabled:opacity-40 px-3 py-1.5 rounded font-bold"
          >
            {bulkActionLoading ? 'Processing...' : 'Delete All'}
          </button>
        </div>
      </div>

      {/* Unresolved */}
      <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
        <h3 className="text-red-500 font-bold mb-4 flex items-center gap-2">
          <AlertTriangle size={18}/> Unresolved ({unresolved.length})
        </h3>
        {unresolved.map(a => renderAlertRow(a, false))}
        {unresolved.length === 0 && (
          <div className="text-sm text-slate-500 italic">No unresolved threats. System clear.</div>
        )}
      </div>

      {/* Resolved toggle */}
      <button
        onClick={() => setShowResolved(!showResolved)}
        className="flex items-center gap-2 text-sm text-slate-400 hover:text-white transition-colors"
      >
        <CheckCircle2 size={16} className="text-green-500" />
        {showResolved ? 'Hide' : 'Show'} Resolved ({resolved.length})
      </button>

      {/* Resolved */}
      {showResolved && (
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
          <h3 className="text-green-500 font-bold mb-4 flex items-center gap-2">
            <CheckCircle2 size={18}/> Resolved ({resolved.length})
          </h3>
          {resolved.map(a => renderAlertRow(a, true))}
          {resolved.length === 0 && (
            <div className="text-sm text-slate-500 italic">No resolved alerts.</div>
          )}
        </div>
      )}

      {/* Detail Modal */}
      {detailAlert && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={() => setDetailAlert(null)}>
          <div className={`w-full max-w-3xl max-h-[85vh] overflow-y-auto rounded-lg shadow-2xl border ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`} onClick={(e) => e.stopPropagation()}>
            <div className={`sticky top-0 z-10 p-4 border-b flex justify-between items-center ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
              <h3 className="text-xl font-bold flex items-center gap-2">
                <AlertTriangle className="text-cyan-500" size={20} />
                Alert Details — {detailAlert.process_name}
              </h3>
              <button onClick={() => setDetailAlert(null)} className="text-slate-400 hover:text-red-500 text-2xl leading-none">&times;</button>
            </div>

            {loadingDetail ? (
              <div className="p-8 text-center text-slate-500 animate-pulse">Loading full details...</div>
            ) : detailData ? (
              <div className="p-6 space-y-6">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div className={`p-3 rounded border ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-slate-500 text-xs uppercase tracking-wider">Severity</span>
                    <p className={`font-bold text-lg ${
                      detailData.severity === 'CRITICAL' ? 'text-red-400' :
                      detailData.severity === 'HIGH' ? 'text-orange-400' :
                      detailData.severity === 'MEDIUM' ? 'text-yellow-400' : 'text-blue-400'
                    }`}>{detailData.severity}</p>
                  </div>
                  <div className={`p-3 rounded border ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-slate-500 text-xs uppercase tracking-wider">Event Type</span>
                    <p className="font-bold text-white">{detailData.event_type}</p>
                  </div>
                  <div className={`p-3 rounded border ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-slate-500 text-xs uppercase tracking-wider">Process</span>
                    <p className="font-bold text-white">{detailData.process_name} {detailData.pid ? <span className="text-slate-400 text-xs">(PID {detailData.pid})</span> : null}</p>
                    {detailData.process_path && <p className="text-xs text-slate-400 truncate">{detailData.process_path}</p>}
                  </div>
                  <div className={`p-3 rounded border ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-slate-500 text-xs uppercase tracking-wider">Agent</span>
                    <p className="font-bold text-white">{detailData.agent_hostname || 'Unknown'}</p>
                    <p className="text-xs text-cyan-400 font-mono truncate">{detailData.agent_id}</p>
                  </div>
                  <div className={`col-span-2 p-3 rounded border ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-slate-500 text-xs uppercase tracking-wider">Description</span>
                    <p className="mt-1 text-sm text-slate-300">{detailData.description}</p>
                  </div>
                  <div className={`col-span-2 p-3 rounded border flex items-center gap-2 ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                    <Clock size={14} className="text-slate-400" />
                    <span className="text-xs text-slate-400">{new Date(detailData.timestamp).toLocaleString()}</span>
                    <span className="text-slate-600 mx-2">|</span>
                    <span className={`text-xs ${detailData.is_resolved ? 'text-green-400' : 'text-red-400'}`}>
                      {detailData.is_resolved ? 'Resolved' : 'Unresolved'}
                    </span>
                  </div>
                </div>

                {detailData.telemetry && (
                  <div>
                    <h4 className="text-md font-semibold text-cyan-500 border-b border-cyan-900/50 pb-1 mb-3 flex items-center gap-2">
                      <Activity size={16} /> Telemetry Snapshot
                    </h4>
                    <div className="grid grid-cols-3 gap-3 text-sm">
                      <div className={`p-2 rounded border ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                        <span className="text-slate-500 text-xs">CPU</span>
                        <p className="font-bold text-cyan-400">{detailData.telemetry.cpu_usage != null ? detailData.telemetry.cpu_usage.toFixed(1) + '%' : 'n/a'}</p>
                      </div>
                      <div className={`p-2 rounded border ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                        <span className="text-slate-500 text-xs">RAM</span>
                        <p className="font-bold text-purple-400">{detailData.telemetry.ram_usage != null ? detailData.telemetry.ram_usage.toFixed(1) + '%' : 'n/a'}</p>
                      </div>
                      <div className={`p-2 rounded border ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                        <span className="text-slate-500 text-xs">Users</span>
                        <p className="font-bold text-white">{(detailData.telemetry.users || []).length}</p>
                      </div>
                    </div>
                    {detailData.telemetry.processes && detailData.telemetry.processes.length > 0 && (
                      <div className="mt-3">
                        <span className="text-xs text-slate-500">Processes:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {(detailData.telemetry.processes || []).slice(0, 10).map((p, i) => (
                            <span key={i} className="px-1.5 py-0.5 rounded bg-slate-800 text-xs text-slate-300 font-mono">{p.name || p.pid}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {detailData.telemetry.network_flows && detailData.telemetry.network_flows.length > 0 && (
                      <div className="mt-3">
                        <span className="text-xs text-slate-500">Network Flows:</span>
                        <div className="mt-1 space-y-1 max-h-24 overflow-y-auto">
                          {detailData.telemetry.network_flows.slice(0, 10).map((f, i) => (
                            <div key={i} className="text-xs font-mono text-slate-400">
                              {f.laddr} → {f.raddr} <span className="text-green-400">{f.status}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {detailData.threat_reports && detailData.threat_reports.length > 0 && (
                  <div>
                    <h4 className="text-md font-semibold text-purple-500 border-b border-purple-900/50 pb-1 mb-3 flex items-center gap-2">
                      <Shield size={16} /> AI Threat Analysis ({detailData.threat_reports.length})
                    </h4>
                    {detailData.threat_reports.map((tr, i) => (
                      <div key={tr.id || i} className={`p-4 rounded border mb-3 ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                        <div className="flex items-center gap-2 mb-2">
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            tr.confidence === 'high' ? 'bg-green-900 text-green-300' :
                            tr.confidence === 'medium' ? 'bg-yellow-900 text-yellow-300' : 'bg-slate-800 text-slate-300'
                          }`}>{tr.confidence}</span>
                          {tr.is_auto_generated && <span className="text-[9px] text-slate-500">auto-generated</span>}
                        </div>
                        <p className="text-sm text-slate-200">{tr.summary}</p>
                        {tr.recommended_actions && tr.recommended_actions.length > 0 && (
                          <div className="mt-2">
                            <span className="text-xs text-slate-500 uppercase tracking-wider">Recommended Actions</span>
                            <ul className="mt-1 space-y-0.5">
                              {tr.recommended_actions.map((action, j) => (
                                <li key={j} className="text-xs text-cyan-300 flex items-start gap-1.5">
                                  <span className="text-cyan-500 mt-0.5">→</span> {action}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                        {tr.osint_data && (
                          <div className="mt-2 text-xs text-slate-400">
                            <span className="text-slate-500">OSINT data:</span>
                            <pre className="mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap">{JSON.stringify(tr.osint_data, null, 2)}</pre>
                          </div>
                        )}
                        {tr.ai_analysis && (
                          <div className="mt-2 p-2 rounded bg-slate-950/60 border border-slate-700">
                            <span className="text-xs text-slate-500">AI Analysis</span>
                            <p className="text-xs text-slate-300 mt-1 whitespace-pre-wrap">{tr.ai_analysis}</p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {detailData.remediations && detailData.remediations.length > 0 && (
                  <div>
                    <h4 className="text-md font-semibold text-green-500 border-b border-green-900/50 pb-1 mb-3 flex items-center gap-2">
                      <Server size={16} /> Remediation Actions
                    </h4>
                    <div className="space-y-2">
                      {detailData.remediations.map((r, i) => (
                        <div key={r.id || i} className={`flex justify-between items-center p-3 rounded border text-sm ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                          <div>
                            <span className="font-bold text-white">{r.action}</span>
                            <span className="text-slate-400 ml-2">on <span className="font-mono text-cyan-400">{r.target}</span></span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                              r.status === 'completed' ? 'bg-green-900 text-green-300' :
                              r.status === 'failed' ? 'bg-red-900 text-red-300' : 'bg-yellow-900 text-yellow-300'
                            }`}>{r.status}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex justify-end gap-3 pt-2">
                  <button onClick={() => setDetailAlert(null)} className="px-4 py-2 rounded text-sm text-slate-400 border border-slate-700 hover:bg-slate-800">
                    Close
                  </button>
                  <button onClick={() => handleResolve(detailAlert.id)} className="bg-cyan-700 hover:bg-cyan-600 px-4 py-2 rounded text-sm font-bold">
                    {detailAlert.is_resolved ? 'Reopen' : 'Resolve Threat'}
                  </button>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-slate-500">
                Failed to load details.
                <button onClick={() => handleOpenDetail(detailAlert)} className="ml-2 text-cyan-400 underline">Retry</button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
