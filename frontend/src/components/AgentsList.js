import React, { useState, useEffect } from 'react';
import { Shield, Cloud, Laptop, Clock } from 'lucide-react';
import { agentsAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function AgentsList() {
  const { refreshTrigger, settings } = useDashboard();
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');

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
    return (
      agent.hostname?.toLowerCase().includes(searchLower) ||
      agent.ip_address?.toLowerCase().includes(searchLower) ||
      agent.agent_id?.toLowerCase().includes(searchLower)
    );
  });

  const getOSIcon = (osType) => {
    if (!osType) return Laptop;
    const lower = osType.toLowerCase();
    if (lower.includes('windows')) return Laptop;
    if (lower.includes('linux')) return Cloud;
    if (lower.includes('mac') || lower.includes('darwin')) return Laptop;
    return Laptop;
  };

  const isAgentActive = (lastSeen) => {
    if (!lastSeen) return false;
    const now = new Date();
    const lastSeenDate = new Date(lastSeen);
    const diffInMinutes = (now - lastSeenDate) / (1000 * 60);
    return diffInMinutes < 10; // Active if seen in last 10 minutes
  };

  const containerClass = settings.darkMode ? 'text-white' : 'text-slate-900';
  const panelClass = settings.darkMode ? 'bg-slate-900 border-slate-700 text-white' : 'bg-white border-slate-200 text-slate-900';
  const inputClass = settings.darkMode ? 'bg-slate-800 border-slate-700 text-white placeholder-slate-500' : 'bg-slate-100 border-slate-300 text-slate-900 placeholder-slate-500';

  return (
    <div className={`space-y-6 ${containerClass}`}>
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold text-white">Monitored Agents</h2>
        <p className="text-slate-400 mt-1">Manage your security endpoints</p>
      </div>

      {/* Search */}
      <div className={`rounded-lg p-4 border ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
        <input
          type="text"
          placeholder="Search by hostname, IP, or agent ID..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className={`w-full px-4 py-2 rounded-lg focus:outline-none focus:border-cyan-500 transition-all ${inputClass}`}
        />
      </div>

      {/* Agents Grid */}
      {loading ? (
        <div className="flex items-center justify-center h-96">
          <div className="text-slate-400">Loading agents...</div>
        </div>
      ) : error ? (
        <div className="bg-red-950 border border-red-700 rounded-lg p-4 text-red-400">
          {error}
        </div>
      ) : filteredAgents.length === 0 ? (
        <div className={`rounded-lg p-12 text-center border ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
          <Shield size={48} className={settings.darkMode ? 'mx-auto text-slate-500 mb-4' : 'mx-auto text-slate-400 mb-4'} />
          <p className={settings.darkMode ? 'text-slate-400' : 'text-slate-600'}>No agents found</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredAgents.map((agent) => {
            const OSIcon = getOSIcon(agent.os_type);
            const isActive = isAgentActive(agent.last_seen);

            return (
              <div
                key={agent.agent_id}
                className={`rounded-lg p-6 transition-all hover:shadow-lg ${settings.darkMode ? 'bg-slate-900 border border-slate-700 hover:border-slate-600 hover:shadow-slate-900 text-white' : 'bg-white border border-slate-200 hover:border-slate-300 hover:shadow-slate-200 text-slate-900'}`}
              >
                {/* Header with Status */}
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="bg-gradient-to-br from-cyan-500 to-blue-500 p-3 rounded-lg">
                      <OSIcon size={24} className="text-white" />
                    </div>
                    <div className="flex-1">
                      <h3 className="font-bold text-white truncate">
                        {agent.hostname || 'Unknown'}
                      </h3>
                      <p className="text-xs font-mono text-slate-400 truncate">
                        {agent.agent_id}
                      </p>
                    </div>
                  </div>
                  <div
                    className={`px-3 py-1 rounded-full text-xs font-bold ${
                      isActive
                        ? 'bg-green-900 text-green-300 border border-green-700'
                        : 'bg-slate-800 text-slate-300 border border-slate-700'
                    }`}
                  >
                    {isActive ? 'Active' : 'Offline'}
                  </div>
                </div>

                {/* Details */}
                <div className="space-y-3 text-sm">
                  {/* IP Address */}
                  <div className="flex items-center gap-3 text-slate-300">
                    <span className="text-slate-500 font-medium">IP:</span>
                    <span className="font-mono text-cyan-400">
                      {agent.ip_address || 'N/A'}
                    </span>
                  </div>

                  {/* OS Type */}
                  <div className="flex items-center gap-3 text-slate-300">
                    <span className="text-slate-500 font-medium">OS:</span>
                    <span>{agent.os_type || 'Unknown'}</span>
                  </div>

                  {/* Last Seen */}
                  <div className="flex items-center gap-3 text-slate-300">
                    <Clock size={16} className="text-slate-500" />
                    <span className="text-xs">
                      Last seen: {formatLastSeen(agent.last_seen)}
                    </span>
                  </div>
                </div>

                {/* Action Button */}
                <button className={`w-full mt-4 px-4 py-2 rounded-lg text-sm font-medium transition-all ${settings.darkMode ? 'bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white' : 'bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-900 hover:text-slate-900'}`}>
                  View Details
                </button>
              </div>
            );
          })}
        </div>
      )}

      {/* Summary */}
      {filteredAgents.length > 0 && (
        <div className={`rounded-lg p-4 border ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
          <p className={settings.darkMode ? 'text-slate-400 text-sm' : 'text-slate-500 text-sm'}>
            Showing {filteredAgents.length} of {agents.length} agents •{' '}
            <span className="text-green-400">
              {agents.filter((a) => isAgentActive(a.last_seen)).length} active
            </span>
          </p>
        </div>
      )}
    </div>
  );
}

function formatLastSeen(timestamp) {
  if (!timestamp) return 'Never';

  const now = new Date();
  const lastSeen = new Date(timestamp);
  const diffInSeconds = Math.floor((now - lastSeen) / 1000);

  if (diffInSeconds < 60) {
    return 'Just now';
  } else if (diffInSeconds < 3600) {
    const minutes = Math.floor(diffInSeconds / 60);
    return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
  } else if (diffInSeconds < 86400) {
    const hours = Math.floor(diffInSeconds / 3600);
    return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  } else {
    const days = Math.floor(diffInSeconds / 86400);
    return `${days} day${days > 1 ? 's' : ''} ago`;
  }
}
