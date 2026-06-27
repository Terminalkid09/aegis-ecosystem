import React, { useState, useEffect } from 'react';
import { Shield, Cloud, Laptop, Clock, Cpu, Zap, Activity } from 'lucide-react';
import { agentsAPI, statsAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function AgentsList() {
  const { refreshTrigger, settings } = useDashboard();
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [agentTelemetry, setAgentTelemetry] = useState(null);
  const [loadingTelemetry, setLoadingTelemetry] = useState(false);
  const [showDemo, setShowDemo] = useState(false);

  useEffect(() => {
    fetchAgents();
  }, [refreshTrigger]);

  const fetchAgents = async () => {
    try {
      setLoading(true);
      const response = await agentsAPI.getAgents({ limit: 1000 });
      setAgents(response.data || []);
      setError(null);
    } catch (err) {
      setError('Failed to load agents');
      console.error('Agents fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredAgents = agents.filter((agent) => {
    const searchLower = searchTerm.toLowerCase();
    const matchesSearch = (
      agent.hostname?.toLowerCase().includes(searchLower) ||
      agent.ip_address?.toLowerCase().includes(searchLower) ||
      agent.agent_id?.toLowerCase().includes(searchLower)
    );
    if (!showDemo && agent.is_demo) return false;
    return matchesSearch;
  });

  const nodeTraceAgents = filteredAgents.filter(a => a.agent_type === 'nodetrace');
  const aegisAgents = filteredAgents.filter(a => a.agent_type === 'aegis-guard');
  const unknownAgents = filteredAgents.filter(a => !a.agent_type || !['nodetrace', 'aegis-guard'].includes(a.agent_type));

  const getOSIcon = (osType) => {
    if (!osType) return Laptop;
    const lower = osType.toLowerCase();
    if (lower.includes('windows')) return Laptop;
    if (lower.includes('linux')) return Cloud;
    return Laptop;
  };

  const isAgentActive = (lastSeen) => {
    if (!lastSeen) return false;
    const now = new Date();
    const lastSeenDate = new Date(lastSeen);
    const diffInMinutes = (now - lastSeenDate) / (1000 * 60);
    return diffInMinutes < 10;
  };

  const handleAgentClick = async (agent) => {
    setSelectedAgent(agent);
    setLoadingTelemetry(true);
    try {
      const response = await statsAPI.getRecentTelemetry({ agent_id: agent.agent_id, limit: 1 });
      if (response.data && response.data.length > 0) {
        setAgentTelemetry(response.data[0]);
      } else {
        setAgentTelemetry(null);
      }
    } catch (err) {
      console.error('Failed to fetch agent telemetry:', err);
      setAgentTelemetry(null);
    } finally {
      setLoadingTelemetry(false);
    }
  };

  const renderAgentCard = (agent) => {
    const OSIcon = getOSIcon(agent.os_type);
    const isActive = isAgentActive(agent.last_seen);
    const isNodeTrace = agent.agent_type === 'nodetrace';

    return (
      <div
        key={agent.agent_id}
        onClick={() => handleAgentClick(agent)}
        className={`rounded-lg p-5 transition-all cursor-pointer hover:shadow-lg border ${
          settings.darkMode 
            ? 'bg-slate-900 border-slate-700 hover:border-slate-500 text-white' 
            : 'bg-white border-slate-200 hover:border-slate-400 text-slate-900'
        }`}
      >
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${isNodeTrace ? 'bg-purple-600' : 'bg-cyan-600'}`}>
              <OSIcon size={20} className="text-white" />
            </div>
            <div>
              <h3 className="font-bold truncate max-w-[150px]">{agent.hostname || 'Unknown'}</h3>
              <p className="text-[10px] font-mono text-slate-500 truncate max-w-[120px]">{agent.agent_id}</p>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            {agent.is_demo && (
              <span className="px-1.5 py-0.5 rounded-full text-[9px] font-bold border border-yellow-800 bg-yellow-950/50 text-yellow-400">DEMO</span>
            )}
            <div className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${
              isActive ? 'bg-green-950 text-green-400 border-green-800' : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}>
              {isActive ? 'ONLINE' : 'OFFLINE'}
            </div>
          </div>
        </div>

        <div className="space-y-2 text-xs">
          <div className="flex justify-between">
            <span className="text-slate-500">IP Address:</span>
            <span className="font-mono text-cyan-500">{agent.ip_address || '127.0.0.1'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">OS Platform:</span>
            <span>{agent.os_type || 'Unknown'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Agent Type:</span>
            <span>{agent.agent_type || 'Unknown'}</span>
          </div>
          <div className="flex justify-between items-center pt-2 border-t border-slate-800">
            <span className="text-slate-500 flex items-center gap-1"><Clock size={12}/> Last seen:</span>
            <span className="text-[10px]">{formatLastSeen(agent.last_seen)}</span>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-3xl font-bold flex items-center gap-3">
            <Shield className="text-cyan-500" /> Endpoint Inventory
          </h2>
          <p className="text-slate-400 mt-1">Unified monitoring for Aegis and NodeTrace fleets</p>
        </div>
        <div className="flex gap-2">
            <div className="px-3 py-1 bg-cyan-900/30 border border-cyan-800 rounded text-xs text-cyan-400 flex items-center gap-2">
                <Activity size={14}/> Aegis: {aegisAgents.length}
            </div>
            <div className="px-3 py-1 bg-purple-900/30 border border-purple-800 rounded text-xs text-purple-400 flex items-center gap-2">
                <Zap size={14}/> NodeTrace: {nodeTraceAgents.length + unknownAgents.length}
            </div>
        </div>
      </div>

      <div className={`rounded-lg p-4 border space-y-3 ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
        <input
          type="text"
          placeholder="Filter by name, IP, or ID..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className={`w-full px-4 py-2 rounded-lg focus:outline-none focus:border-cyan-500 transition-all ${
            settings.darkMode ? 'bg-slate-800 text-white' : 'bg-slate-100 text-slate-900'
          }`}
        />
        <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
          <input type="checkbox" checked={showDemo} onChange={(e) => setShowDemo(e.target.checked)} className="rounded border-slate-600" />
          Show demo agents
        </label>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-48 text-slate-500 italic">Synchronizing assets...</div>
      ) : (
        <>
          {/* SECTION: Aegis-Guard (Java/EDR) */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-cyan-500 flex items-center gap-2 uppercase tracking-widest border-b border-cyan-900/50 pb-2">
              <Shield size={18}/> Aegis-Guard Fleet ({aegisAgents.length})
            </h3>
            {aegisAgents.length === 0 ? (
                <p className="text-slate-600 text-sm italic">No Aegis-Guard agents reported yet.</p>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {aegisAgents.map(renderAgentCard)}
                </div>
            )}
          </div>

          {/* SECTION: NodeTrace (Python/Telemetry) */}
          <div className="space-y-4 pt-4">
            <h3 className="text-lg font-semibold text-purple-500 flex items-center gap-2 uppercase tracking-widest border-b border-purple-900/50 pb-2">
              <Zap size={18}/> NodeTrace Telemetry Fleet ({nodeTraceAgents.length + unknownAgents.length})
            </h3>
            {[...nodeTraceAgents, ...unknownAgents].length === 0 ? (
                <p className="text-slate-600 text-sm italic">No telemetry agents reported yet.</p>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {[...nodeTraceAgents, ...unknownAgents].map(renderAgentCard)}
                </div>
            )}
          </div>
        </>
      )}

      {selectedAgent && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className={`w-full max-w-4xl max-h-[80vh] overflow-y-auto rounded-lg shadow-2xl border ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
            <div className={`p-4 border-b flex justify-between items-center sticky top-0 z-10 ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
              <h3 className="text-xl font-bold flex items-center gap-2">
                <Laptop className="text-cyan-500" /> {selectedAgent.hostname || 'Unknown'} Details
              </h3>
              <button onClick={() => setSelectedAgent(null)} className="text-slate-400 hover:text-red-500 text-2xl leading-none">&times;</button>
            </div>
            
            <div className="p-6 space-y-6">
              {loadingTelemetry ? (
                <div className="text-center py-8 text-slate-500 animate-pulse">Fetching Deep Identity & Network Telemetry...</div>
              ) : agentTelemetry ? (
                <>
                  {/* Identity Section */}
                  <div>
                    <h4 className="text-md font-semibold text-cyan-500 border-b border-cyan-900/50 pb-1 mb-3">Logged-in Users (Identity)</h4>
                    {agentTelemetry.users && agentTelemetry.users.length > 0 ? (
                      <div className="grid grid-cols-2 gap-3">
                        {agentTelemetry.users.map((u, i) => (
                          <div key={i} className={`p-3 rounded border text-sm ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                            <div className="font-bold text-white">{u.name}</div>
                            <div className="text-slate-400 text-xs">Terminal: {u.terminal} | Host: {u.host}</div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-slate-500 text-sm italic">No users currently logged in.</p>
                    )}
                  </div>

                  {/* Network Section */}
                  <div>
                    <h4 className="text-md font-semibold text-purple-500 border-b border-purple-900/50 pb-1 mb-3">Active Network Flows</h4>
                    {agentTelemetry.network_flows && agentTelemetry.network_flows.length > 0 ? (
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm">
                          <thead>
                            <tr className={`text-xs uppercase ${settings.darkMode ? 'text-slate-400 bg-slate-800' : 'text-slate-500 bg-slate-100'}`}>
                              <th className="p-2">Local Address</th>
                              <th className="p-2">Remote Address</th>
                              <th className="p-2">State</th>
                              <th className="p-2">PID</th>
                            </tr>
                          </thead>
                          <tbody>
                            {agentTelemetry.network_flows.map((flow, i) => (
                              <tr key={i} className={`border-b ${settings.darkMode ? 'border-slate-800' : 'border-slate-200'}`}>
                                <td className="p-2 font-mono text-cyan-400">{flow.laddr}</td>
                                <td className="p-2 font-mono text-purple-400">{flow.raddr}</td>
                                <td className="p-2">
                                  <span className="px-2 py-0.5 rounded text-[10px] bg-green-900/30 text-green-400 border border-green-800">{flow.status}</span>
                                </td>
                                <td className="p-2 text-slate-400">{flow.pid}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <p className="text-slate-500 text-sm italic">No active external connections found.</p>
                    )}
                  </div>
                </>
              ) : (
                <div className="text-center py-8 text-slate-500 italic">No telemetry data available for this agent.</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function formatLastSeen(timestamp) {
  if (!timestamp) return 'Never';
  const now = new Date();
  const lastSeen = new Date(timestamp);
  const diff = Math.floor((now - lastSeen) / 1000);
  if (diff < 60) return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return lastSeen.toLocaleDateString();
}
