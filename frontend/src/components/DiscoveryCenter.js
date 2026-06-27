import React, { useEffect, useState } from 'react';
import { Network, Search, Play, RefreshCcw, ShieldCheck, Server, Terminal } from 'lucide-react';
import { discoveryAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function DiscoveryCenter() {
  const { settings } = useDashboard();
  const [cidr, setCidr] = useState('192.168.1.0/24');
  const [hosts, setHosts] = useState([]);
  const [reputation, setReputation] = useState([]);
  const [selectedIp, setSelectedIp] = useState('');
  const [repLabel, setRepLabel] = useState('suspicious');
  const [plan, setPlan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    refresh();
  }, []);

  const refresh = async () => {
    try {
      const [hostRes, repRes] = await Promise.all([
        discoveryAPI.getHosts(),
        discoveryAPI.getReputation(),
      ]);
      setHosts(hostRes.data.items || []);
      setReputation(repRes.data.items || []);
    } catch (err) {
      setMessage(err?.response?.data?.detail || 'Failed to refresh discovery data.');
    }
  };

  const runScan = async () => {
    setLoading(true);
    setMessage('');
    try {
      const res = await discoveryAPI.scan({ cidr, include_unreachable: false });
      setHosts(res.data.discovered || []);
      setMessage(`Scan complete: ${res.data.discovered?.length || 0} reachable host(s).`);
      refresh();
    } catch (err) {
      setMessage(err?.response?.data?.detail || 'Scan failed.');
    } finally {
      setLoading(false);
    }
  };

  const startDemo = async () => {
    setLoading(true);
    setMessage('');
    try {
      await discoveryAPI.startDemo();
      await refresh();
      setMessage('Demo endpoints are online. Use Refresh Demo Heartbeat to keep them fresh.');
    } catch (err) {
      setMessage(err?.response?.data?.detail || 'Demo start failed.');
    } finally {
      setLoading(false);
    }
  };

  const refreshDemoHeartbeat = async () => {
    try {
      const res = await discoveryAPI.demoHeartbeat();
      await refresh();
      setMessage(`Demo heartbeat refreshed for ${res.data.count || 0} agent(s).`);
    } catch (err) {
      setMessage(err?.response?.data?.detail || 'Demo heartbeat failed.');
    }
  };

  const saveReputation = async () => {
    if (!selectedIp) return;
    try {
      await discoveryAPI.upsertReputation({
        ip_address: selectedIp,
        label: repLabel,
        confidence: repLabel === 'malicious' ? 90 : repLabel === 'suspicious' ? 65 : 40,
        source: 'analyst',
      });
      await refresh();
      setMessage(`Reputation saved for ${selectedIp}.`);
    } catch (err) {
      setMessage(err?.response?.data?.detail || 'Failed to save reputation.');
    }
  };

  const createPlan = async (ip, osGuess = 'linux') => {
    try {
      const normalizedOs = osGuess === 'windows' ? 'windows' : 'linux';
      const agentType = normalizedOs === 'windows' ? 'aegis-guard' : 'nodetrace';
      const res = await discoveryAPI.deploymentPlan({ ip_address: ip, os_type: normalizedOs, agent_type: agentType, method: 'manual' });
      setSelectedIp(ip);
      setPlan(res.data);
    } catch (err) {
      setMessage(err?.response?.data?.detail || 'Failed to create deployment plan.');
    }
  };

  const panelClass = settings.darkMode
    ? 'bg-slate-900 border border-slate-700 text-slate-100'
    : 'bg-white border border-slate-200 text-slate-900';
  const inputClass = settings.darkMode
    ? 'bg-slate-800 border-slate-700 text-white'
    : 'bg-slate-50 border-slate-300 text-slate-900';

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold flex items-center gap-3">
            <Network className="text-cyan-500" /> Aegis Discovery
          </h2>
          <p className="text-slate-400 mt-1">Network discovery, agent enrollment planning, demo heartbeat, and IP reputation.</p>
        </div>
        <button onClick={refresh} className="inline-flex items-center gap-2 rounded border border-slate-700 px-4 py-2 text-xs font-bold text-slate-300 hover:bg-slate-800">
          <RefreshCcw size={15} /> Refresh
        </button>
      </div>

      {message && <div className="rounded border border-cyan-800 bg-cyan-950/30 px-4 py-3 text-sm text-cyan-200">{message}</div>}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className={`${panelClass} rounded-lg p-5 space-y-4`}>
          <h3 className="text-sm font-black uppercase tracking-widest text-slate-500 flex items-center gap-2"><Search size={15}/> Discovery Scan</h3>
          <input value={cidr} onChange={(e) => setCidr(e.target.value)} className={`w-full rounded border px-3 py-2 font-mono text-sm ${inputClass}`} />
          <button disabled={loading} onClick={runScan} className="w-full inline-flex items-center justify-center gap-2 rounded bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-500 disabled:opacity-60">
            <Search size={16}/> {loading ? 'Scanning...' : 'Scan Network'}
          </button>
          <button disabled={loading} onClick={startDemo} className="w-full inline-flex items-center justify-center gap-2 rounded bg-purple-600 px-4 py-2 text-sm font-bold text-white hover:bg-purple-500 disabled:opacity-60">
            <Play size={16}/> Start Demo Mode
          </button>
          <button onClick={refreshDemoHeartbeat} className="w-full inline-flex items-center justify-center gap-2 rounded border border-green-800 bg-green-950/30 px-4 py-2 text-sm font-bold text-green-300 hover:bg-green-900/40">
            <ShieldCheck size={16}/> Refresh Demo Heartbeat
          </button>
        </div>

        <div className={`${panelClass} rounded-lg p-5 space-y-4`}>
          <h3 className="text-sm font-black uppercase tracking-widest text-slate-500 flex items-center gap-2"><ShieldCheck size={15}/> IP Reputation</h3>
          <input value={selectedIp} onChange={(e) => setSelectedIp(e.target.value)} placeholder="192.168.1.20" className={`w-full rounded border px-3 py-2 font-mono text-sm ${inputClass}`} />
          <select value={repLabel} onChange={(e) => setRepLabel(e.target.value)} className={`w-full rounded border px-3 py-2 text-sm ${inputClass}`}>
            <option value="known">known</option>
            <option value="suspicious">suspicious</option>
            <option value="malicious">malicious</option>
            <option value="unknown">unknown</option>
          </select>
          <button onClick={saveReputation} className="w-full rounded bg-green-600 px-4 py-2 text-sm font-bold text-white hover:bg-green-500">Save Reputation</button>
          <div className="space-y-2 max-h-40 overflow-auto">
            {reputation.map((item) => (
              <button key={item.ip_address} onClick={() => setSelectedIp(item.ip_address)} className="w-full flex justify-between rounded border border-slate-800 px-3 py-2 text-left text-xs hover:bg-slate-800/60">
                <span className="font-mono">{item.ip_address}</span>
                <span className={item.label === 'malicious' ? 'text-red-400' : item.label === 'suspicious' ? 'text-yellow-400' : 'text-green-400'}>{item.label}</span>
              </button>
            ))}
          </div>
        </div>

        <div className={`${panelClass} rounded-lg p-5 space-y-4`}>
          <h3 className="text-sm font-black uppercase tracking-widest text-slate-500 flex items-center gap-2"><Terminal size={15}/> Deployment Plan</h3>
          {plan ? (
            <div className="space-y-3 text-sm">
              <div className="flex justify-between"><span className="text-slate-500">Target</span><span className="font-mono">{plan.ip_address}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Agent</span><span>{plan.agent_type}</span></div>
              <div>
                <div className="text-xs uppercase text-slate-500 mb-1">Host command</div>
                <code className="block rounded bg-slate-950 p-3 text-xs text-cyan-300 whitespace-pre-wrap">{plan.local_command}</code>
              </div>
              <p className="text-xs text-slate-500">{plan.note}</p>
            </div>
          ) : (
            <div className="h-40 flex items-center justify-center text-sm text-slate-500 border border-dashed border-slate-700 rounded">
              Select a discovered host to generate a plan.
            </div>
          )}
        </div>
      </div>

      <div className={`${panelClass} rounded-lg overflow-hidden`}>
        <table className="w-full text-left text-sm">
          <thead className={settings.darkMode ? 'bg-slate-800 text-slate-400' : 'bg-slate-100 text-slate-600'}>
            <tr>
              <th className="p-4">Host</th>
              <th className="p-4">Status</th>
              <th className="p-4">OS Guess</th>
              <th className="p-4">Open Ports</th>
              <th className="p-4">Agent</th>
              <th className="p-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((host) => (
              <tr key={host.ip_address} className="border-t border-slate-800">
                <td className="p-4">
                  <div className="font-mono text-cyan-400">{host.ip_address}</div>
                  <div className="text-xs text-slate-500">{host.hostname || 'unresolved'}</div>
                </td>
                <td className="p-4">{host.status}</td>
                <td className="p-4">{host.os_guess || 'unknown'}</td>
                <td className="p-4 font-mono text-xs">{(host.open_ports || []).join(', ') || '-'}</td>
                <td className="p-4">{host.agent_status || 'not_deployed'}</td>
                <td className="p-4 text-right">
                  <button onClick={() => createPlan(host.ip_address, host.os_guess)} className="inline-flex items-center gap-2 rounded border border-slate-700 px-3 py-1.5 text-xs font-bold hover:bg-slate-800">
                    <Server size={14}/> Plan
                  </button>
                </td>
              </tr>
            ))}
            {hosts.length === 0 && (
              <tr><td colSpan="6" className="p-8 text-center text-slate-500">No discovered hosts yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
