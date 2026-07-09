import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Network, Search, Play, RefreshCcw, ShieldCheck, Server, Terminal, Upload, Wifi, Monitor, Smartphone, Info, X, Eye, EyeOff } from 'lucide-react';
import { discoveryAPI, vaultAPI, agentsAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function DiscoveryCenter() {
  const { settings, discoveryHosts: hosts, setDiscoveryHosts: setHosts, discoveryReputation: reputation, setDiscoveryReputation: setReputation, scanInProgress, setScanInProgress, scanMessage: message, setScanMessage: setMessage, scanCidr: cidr, setScanCidr: setCidr } = useDashboard();
  const [selectedIp, setSelectedIp] = useState('');
  const [repLabel, setRepLabel] = useState('suspicious');
  const [plan, setPlan] = useState(null);
  const [deployResult, setDeployResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [deployAgentType, setDeployAgentType] = useState(() => { try { return localStorage.getItem('aegis-deploy-agent-type') || 'nodetrace'; } catch { return 'nodetrace'; }});
  const [deployMethod, setDeployMethod] = useState(() => { try { return localStorage.getItem('aegis-deploy-method') || 'manual'; } catch { return 'manual'; }});
  const [manualIp, setManualIp] = useState('');
  const [deployModal, setDeployModal] = useState(null);
  const [deployUsername, setDeployUsername] = useState('');
  const [deployPassword, setDeployPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showRepHelp, setShowRepHelp] = useState(false);
  const [agents, setAgents] = useState([]);
  const [selectedAgentId, setSelectedAgentId] = useState('');
  const [probeTimeout, setProbeTimeout] = useState(() => { try { return parseFloat(localStorage.getItem('aegis-probe-timeout')) || 0.1; } catch { return 0.1; }});
  const pollingRef = useRef(null);
  const timeoutRef = useRef(null);
  const hostsCountRef = useRef(hosts.length);

  // Persist deploy settings
  useEffect(() => { try { localStorage.setItem('aegis-deploy-agent-type', deployAgentType); } catch {} }, [deployAgentType]);
  useEffect(() => { try { localStorage.setItem('aegis-deploy-method', deployMethod); } catch {} }, [deployMethod]);
  useEffect(() => { try { localStorage.setItem('aegis-probe-timeout', probeTimeout.toString()); } catch {} }, [probeTimeout]);

  // Poll for scan-via-agent results
  useEffect(() => {
    if (!scanInProgress) {
      if (pollingRef.current) { clearInterval(pollingRef.current); pollingRef.current = null; }
      if (timeoutRef.current) { clearTimeout(timeoutRef.current); timeoutRef.current = null; }
      return;
    }
    hostsCountRef.current = hosts.length;
    // Auto-timeout after 180s so scan never stays stuck (agent heartbeat=10s + ARP sweep + port scan = 2-3min)
    timeoutRef.current = setTimeout(() => {
      setScanInProgress(false);
      setMessage('Scan timed out — no new hosts found. Verify NodeTrace agent is running and reachable, then try again.');
      if (pollingRef.current) { clearInterval(pollingRef.current); pollingRef.current = null; }
    }, 60000);
    pollingRef.current = setInterval(async () => {
      try {
        const hostRes = await discoveryAPI.getHosts();
        const newHosts = hostRes.data.items || [];
        if (newHosts.length > hostsCountRef.current) {
          setHosts(newHosts);
          setScanInProgress(false);
          if (timeoutRef.current) { clearTimeout(timeoutRef.current); timeoutRef.current = null; }
          setMessage(`Agent scan complete: ${newHosts.length - hostsCountRef.current} new host(s) discovered. Total: ${newHosts.length}`);
          clearInterval(pollingRef.current);
          pollingRef.current = null;
        }
      } catch {}
    }, 3000);
    return () => {
      if (pollingRef.current) { clearInterval(pollingRef.current); pollingRef.current = null; }
      if (timeoutRef.current) { clearTimeout(timeoutRef.current); timeoutRef.current = null; }
    };
  }, [scanInProgress]);

  useEffect(() => { refresh(); loadAgents(); }, []);

  const loadAgents = async () => {
    try {
      const res = await agentsAPI.getAgents({ active_only: true });
      setAgents(res.data || []);
      if (res.data?.length > 0 && !selectedAgentId) setSelectedAgentId(res.data[0].agent_id);
    } catch {}
  };

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
      hostsCountRef.current = res.data.discovered?.length || 0;
      setMessage(`Scan complete: ${res.data.discovered?.length || 0} reachable host(s).`);
      refresh();
    } catch (err) {
      setMessage(err?.response?.data?.detail || 'Scan failed.');
    } finally { setLoading(false); }
  };

  const scanViaAgent = async () => {
    if (!selectedAgentId) { setMessage('Select an active agent first.'); return; }
    // If a scan is already in progress, clicking resets it so user can try again
    if (scanInProgress) {
      setScanInProgress(false);
      setMessage('Scan cancelled. You can start a new one.');
      return;
    }
    setLoading(true);
    setScanInProgress(true);
    setMessage('');
    try {
      const res = await discoveryAPI.scanViaAgent(selectedAgentId, { cidr, ports: [22, 80, 135, 139, 443, 445, 3389, 8000, 8080], probe_timeout: probeTimeout });
      hostsCountRef.current = hosts.length;
      setMessage(`Scan command sent to agent — waiting for results (timeout 180s). Click Cancel to stop.`);
    } catch (err) {
      // API call itself failed — this is a connectivity/auth issue, not the scan itself
      // Keep scanInProgress so the polling loop can still pick up results if agent is already working
      setMessage(err?.response?.data?.detail || 'Failed to queue agent scan command. Agent may be offline.');
    } finally { setLoading(false); }
  };

  const syncStatus = async () => {
    setMessage('');
    try {
      const res = await discoveryAPI.syncAgentStatus();
      await refresh();
      setMessage(`Agent status synced: ${res.data.count} hosts updated.`);
    } catch (err) { setMessage(err?.response?.data?.detail || 'Sync failed.'); }
  };

  const startDemo = async () => {
    setLoading(true);
    setMessage('');
    try {
      await discoveryAPI.startDemo();
      await refresh();
      setMessage('Demo endpoints online. Use Refresh Demo Heartbeat to keep them fresh.');
    } catch (err) { setMessage(err?.response?.data?.detail || 'Demo start failed.'); }
    finally { setLoading(false); }
  };

  const refreshDemoHeartbeat = async () => {
    try {
      const res = await discoveryAPI.demoHeartbeat();
      await refresh();
      setMessage(`Demo heartbeat refreshed for ${res.data.count || 0} agent(s).`);
    } catch (err) { setMessage(err?.response?.data?.detail || 'Demo heartbeat failed.'); }
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
    } catch (err) { setMessage(err?.response?.data?.detail || 'Failed to save reputation.'); }
  };

  const openDeployModal = (host) => {
    setDeployModal(host);
    setDeployResult(null);
    setPlan(null);
    setDeployUsername('');
    setDeployPassword('');
    setMessage('');
  };

  const generatePlan = async () => {
    if (!deployModal) return;
    setLoading(true);
    setMessage('');
    try {
      const osGuess = deployModal.os_guess?.includes('windows') ? 'windows' : 'linux';
      const res = await discoveryAPI.deploymentPlan({
        ip_address: deployModal.ip_address,
        os_type: osGuess,
        agent_type: deployAgentType,
        method: deployMethod,
      });
      setPlan(res.data);
    } catch (err) { setMessage(err?.response?.data?.detail || 'Failed to generate plan.'); }
    finally { setLoading(false); }
  };

  const executeDeploy = async () => {
    if (!deployModal) return;
    setDeploying(true);
    setMessage('');
    try {
      const res = await discoveryAPI.autoDeploy({
        ip_address: deployModal.ip_address,
        agent_type: deployAgentType,
        username: deployUsername || undefined,
        password: deployPassword || undefined,
      });
      setDeployResult(res.data);
      setMessage(`Deploy initiated: ${res.data.status}`);
    } catch (err) { setMessage(err?.response?.data?.detail || 'Auto-deploy failed.'); }
    finally { setDeploying(false); }
  };

  const addManualHost = async () => {
    if (!manualIp) return;
    setMessage('');
    try {
      const res = await discoveryAPI.scan({ cidr: `${manualIp}/32`, include_unreachable: true, fast_scan: false });
      const newHosts = res.data.discovered || [];
      setHosts(current => {
        const existing = new Set(current.map(h => h.ip_address));
        return [...current, ...newHosts.filter(h => !existing.has(h.ip_address))];
      });
      setMessage(`Added ${manualIp} to discovery.`);
      setManualIp('');
    } catch (err) { setMessage(err?.response?.data?.detail || 'Failed to add host.'); }
  };

  const createPlan = async (ip, osGuess = 'linux') => {
    try {
      const normalizedOs = osGuess === 'windows' ? 'windows' : 'linux';
      const res = await discoveryAPI.deploymentPlan({ ip_address: ip, os_type: normalizedOs, agent_type: deployAgentType, method: 'manual' });
      setSelectedIp(ip);
      setPlan(res.data);
    } catch (err) { setMessage(err?.response?.data?.detail || 'Failed to create deployment plan.'); }
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
          <p className="text-slate-400 mt-1">Network discovery, agent enrollment, demo heartbeat, and IP reputation.</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={syncStatus} className="inline-flex items-center gap-2 rounded border border-cyan-800 px-4 py-2 text-xs font-bold text-cyan-300 hover:bg-cyan-900/30">
            <ShieldCheck size={15} /> Sync Agents
          </button>
          <button onClick={refresh} className="inline-flex items-center gap-2 rounded border border-slate-700 px-4 py-2 text-xs font-bold text-slate-300 hover:bg-slate-800">
            <RefreshCcw size={15} /> Refresh
          </button>
        </div>
      </div>

      {message && <div className="rounded border border-cyan-800 bg-cyan-950/30 px-4 py-3 text-sm text-cyan-200">{message}</div>}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Scan Panel */}
        <div className={`${panelClass} rounded-lg p-5 space-y-4`}>
          <h3 className="text-sm font-black uppercase tracking-widest text-slate-500 flex items-center gap-2"><Search size={15}/> Discovery Scan</h3>
          <input value={cidr} onChange={(e) => setCidr(e.target.value)} className={`w-full rounded border px-3 py-2 font-mono text-sm ${inputClass}`} />
          <button disabled={loading} onClick={runScan} className="w-full inline-flex items-center justify-center gap-2 rounded bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-500 disabled:opacity-60">
            <Search size={16}/> {loading ? 'Scanning...' : 'Scan Network (Docker)'}
          </button>
          <div className="border-t border-slate-700 pt-3">
            <p className="text-xs text-slate-500 mb-2">Scan via agent (from host network):</p>
            <div className="flex gap-2">
              <select value={selectedAgentId} onChange={(e) => setSelectedAgentId(e.target.value)} className={`flex-1 rounded border px-2 py-2 text-xs font-mono ${inputClass}`}>
                {agents.map(a => <option key={a.agent_id} value={a.agent_id}>{a.hostname || a.agent_id.slice(0,12)}</option>)}
              </select>
              <button disabled={loading || !selectedAgentId} onClick={scanViaAgent} className="rounded px-3 py-2 text-xs font-bold text-white disabled:opacity-50 ${scanInProgress ? 'bg-red-700 hover:bg-red-600 animate-pulse' : 'bg-purple-700 hover:bg-purple-600'}">
                {scanInProgress ? 'Cancel' : <Search size={14}/>}
              </button>
            </div>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-[10px] text-slate-500 whitespace-nowrap">ARP probe:</span>
              <input
                type="range"
                min="0.05"
                max="0.5"
                step="0.05"
                value={probeTimeout}
                onChange={(e) => setProbeTimeout(parseFloat(e.target.value))}
                className="flex-1 h-1 accent-purple-500 cursor-pointer"
                title="Higher values = more thorough for large/noisy networks"
              />
              <span className="text-[10px] font-mono text-purple-400 w-8 text-right">{probeTimeout.toFixed(2)}s</span>
            </div>
          </div>
          <div className="border-t border-slate-700 pt-3">
            <p className="text-xs text-slate-500 mb-2">Add host manually:</p>
            <div className="flex gap-2">
              <input value={manualIp} onChange={(e) => setManualIp(e.target.value)} placeholder="192.168.1.100" className={`flex-1 rounded border px-3 py-2 font-mono text-sm ${inputClass}`} />
              <button onClick={addManualHost} className="rounded bg-slate-700 px-3 py-2 text-xs font-bold text-white hover:bg-slate-600"><Search size={14}/></button>
            </div>
          </div>
          <div className="border-t border-slate-700 pt-3 space-y-2">
            <button disabled={loading} onClick={startDemo} className="w-full inline-flex items-center justify-center gap-2 rounded bg-purple-600 px-4 py-2 text-sm font-bold text-white hover:bg-purple-500 disabled:opacity-60">
              <Play size={16}/> Start Demo Mode
            </button>
            <button onClick={refreshDemoHeartbeat} className="w-full inline-flex items-center justify-center gap-2 rounded border border-green-800 bg-green-950/30 px-4 py-2 text-sm font-bold text-green-300 hover:bg-green-900/40">
              <ShieldCheck size={16}/> Refresh Demo Heartbeat
            </button>
          </div>
        </div>

        {/* Reputation Panel */}
        <div className={`${panelClass} rounded-lg p-5 space-y-4`}>
          <h3 className="text-sm font-black uppercase tracking-widest text-slate-500 flex items-center gap-2">
            <ShieldCheck size={15}/> IP Reputation
            <button onClick={() => setShowRepHelp(!showRepHelp)} className="text-slate-500 hover:text-white ml-auto">
              <Info size={14} />
            </button>
          </h3>
          {showRepHelp && (
            <div className="text-xs text-slate-400 bg-slate-800/50 rounded p-2 border border-slate-700">
              Tagga gli IP della rete come <span className="text-green-400">known</span>, <span className="text-yellow-400">suspicious</span> o <span className="text-red-400">malicious</span>.
              Questi label vengono usati dal sistema OSINT e AI per dare priorità alle minacce.
              <br/>Esempio: un IP sconosciuto che fa scanning → taggalo come <span className="text-yellow-400">suspicious</span>
            </div>
          )}
          <input value={selectedIp} onChange={(e) => setSelectedIp(e.target.value)} placeholder="192.168.1.20" className={`w-full rounded border px-3 py-2 font-mono text-sm ${inputClass}`} />
          <select value={repLabel} onChange={(e) => setRepLabel(e.target.value)} className={`w-full rounded border px-3 py-2 text-sm ${inputClass}`}>
            <option value="known">known — host fidato</option>
            <option value="suspicious">suspicious — comportamenti anomali</option>
            <option value="malicious">malicious — attivo minaccia</option>
            <option value="unknown">unknown — nessuna informazione</option>
          </select>
          <button onClick={saveReputation} className="w-full rounded bg-green-600 px-4 py-2 text-sm font-bold text-white hover:bg-green-500">Save Reputation</button>
          <div className="space-y-2 max-h-40 overflow-auto">
            {reputation.map((item) => (
              <button key={item.ip_address} onClick={() => { setSelectedIp(item.ip_address); setRepLabel(item.label); }} className="w-full flex justify-between rounded border border-slate-800 px-3 py-2 text-left text-xs hover:bg-slate-800/60">
                <span className="font-mono">{item.ip_address}</span>
                <span className={item.label === 'malicious' ? 'text-red-400' : item.label === 'suspicious' ? 'text-yellow-400' : 'text-green-400'}>{item.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Plan Panel */}
        <div className={`${panelClass} rounded-lg p-5 space-y-4`}>
          <h3 className="text-sm font-black uppercase tracking-widest text-slate-500 flex items-center gap-2"><Terminal size={15}/> Deployment Command</h3>

          {deployResult ? (
            <div className="space-y-3 text-sm">
              <div className="flex items-center gap-2 text-green-400 font-bold"><Upload size={16}/> Deploy Initiated</div>
              <div className="flex justify-between"><span className="text-slate-500">Method</span><span className="text-cyan-400">{deployResult.method}</span></div>
              {deployResult.command && (
                <div>
                  <div className="text-xs uppercase text-slate-500 mb-1">Remote command</div>
                  <code className="block rounded bg-slate-950 p-3 text-xs text-cyan-300 whitespace-pre-wrap max-h-40 overflow-auto">{deployResult.command}</code>
                </div>
              )}
              <p className="text-xs text-slate-500">{deployResult.note}</p>
              <button onClick={() => setDeployResult(null)} className="text-xs text-slate-500 hover:text-white">Clear</button>
            </div>
          ) : plan ? (
            <div className="space-y-3 text-sm">
              <div className="flex justify-between"><span className="text-slate-500">Target</span><span className="font-mono">{plan.ip_address}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Agent</span><span>{plan.agent_type}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Method</span><span>{plan.method}{plan.has_credentials ? ' (creds found)' : ''}</span></div>
              {plan.deploy_command ? (
                <div>
                  <div className="text-xs uppercase text-green-500 mb-1">Auto-deploy command</div>
                  <code className="block rounded bg-slate-950 p-3 text-xs text-green-300 whitespace-pre-wrap max-h-32 overflow-auto">{plan.deploy_command}</code>
                </div>
              ) : (
                <div>
                  <div className="text-xs uppercase text-slate-500 mb-1">Run this on the target host:</div>
                  <code className="block rounded bg-slate-950 p-3 text-xs text-cyan-300 whitespace-pre-wrap">{plan.local_command}</code>
                </div>
              )}
              <p className="text-xs text-slate-500">{plan.note}</p>
              <button onClick={() => setPlan(null)} className="text-xs text-slate-500 hover:text-white">Clear</button>
            </div>
          ) : (
            <div className="h-40 flex items-center justify-center text-sm text-slate-500 border border-dashed border-slate-700 rounded">
              Select a host and click <strong className="text-cyan-400 mx-1">Deploy</strong> or <strong className="text-slate-400 mx-1">Plan</strong>
            </div>
          )}
        </div>
      </div>

      {/* Hosts Table */}
      <div className={`${panelClass} rounded-lg overflow-hidden`}>
        <table className="w-full text-left text-sm">
          <thead className={settings.darkMode ? 'bg-slate-800 text-slate-400' : 'bg-slate-100 text-slate-600'}>
            <tr>
              <th className="p-4">Host</th>
              <th className="p-4">MAC / Vendor</th>
              <th className="p-4">Status</th>
              <th className="p-4">OS Guess</th>
              <th className="p-4">Open Ports</th>
              <th className="p-4">Guard</th>
              <th className="p-4">NodeTrace</th>
              <th className="p-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((host) => {
              const osIcon = host.os_guess?.includes('windows') ? Monitor : host.os_guess?.includes('android') ? Smartphone : Wifi;
              return (
              <tr key={host.ip_address} className="border-t border-slate-800">
                <td className="p-4">
                  <div className="font-mono text-cyan-400">{host.ip_address}</div>
                  <div className="text-xs text-slate-500 flex items-center gap-1">{React.createElement(osIcon, {size: 11})} {host.hostname || 'unresolved'}</div>
                </td>
                <td className="p-4 text-xs">
                  {host.mac_address ? <div className="font-mono text-slate-400">{host.mac_address}</div> : null}
                  {host.vendor ? <div className="text-slate-500">{host.vendor}</div> : <div className="text-slate-600">-</div>}
                </td>
                <td className="p-4">
                  <span className={`px-2 py-0.5 rounded-full text-[10px] border ${
                    host.status === 'reachable' ? 'bg-green-950 text-green-400 border-green-800' : 'bg-slate-800 text-slate-500 border-slate-700'
                  }`}>{host.status}</span>
                </td>
                <td className="p-4 text-xs">{host.os_guess || 'unknown'}{host.os_confidence ? <span className="text-slate-500 ml-1">({host.os_confidence}%)</span> : null}</td>
                <td className="p-4 font-mono text-xs">{(host.open_ports || []).join(', ') || '-'}</td>
                <td className="p-4">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    host.guard_status === 'active' ? 'bg-green-950 text-green-400' :
                    host.guard_status === 'deployed' ? 'bg-blue-950 text-blue-400' : 'text-slate-600'
                  }`}>{host.guard_status}</span>
                </td>
                <td className="p-4">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    host.nodetrace_status === 'active' ? 'bg-green-950 text-green-400' :
                    host.nodetrace_status === 'deployed' ? 'bg-blue-950 text-blue-400' : 'text-slate-600'
                  }`}>{host.nodetrace_status}</span>
                </td>
                <td className="p-4 text-right">
                  <div className="flex items-center justify-end gap-1.5">
                    <button onClick={() => createPlan(host.ip_address, host.os_guess)} className="inline-flex items-center gap-1 rounded border border-slate-700 px-2.5 py-1.5 text-xs font-bold hover:bg-slate-800" title="Show deploy command">
                      <Terminal size={13}/> Cmd
                    </button>
                    <button onClick={() => openDeployModal(host)} className="inline-flex items-center gap-1 rounded border border-cyan-800 bg-cyan-950/30 px-2.5 py-1.5 text-xs font-bold text-cyan-300 hover:bg-cyan-900/40" title="Deploy agent">
                      <Upload size={13}/> Deploy
                    </button>
                  </div>
                </td>
              </tr>
            )})}
            {hosts.length === 0 && (
              <tr><td colSpan="8" className="p-8 text-center text-slate-500">No discovered hosts yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Deploy Modal */}
      {deployModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={() => setDeployModal(null)}>
          <div className={`w-full max-w-lg rounded-lg shadow-2xl border ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`} onClick={(e) => e.stopPropagation()}>
            <div className={`flex justify-between items-center p-4 border-b ${settings.darkMode ? 'border-slate-700' : 'border-slate-200'}`}>
              <h3 className="text-lg font-bold flex items-center gap-2">
                <Upload className="text-cyan-500" size={20} />
                Deploy Agent — {deployModal.ip_address}
              </h3>
              <button onClick={() => setDeployModal(null)} className="text-slate-400 hover:text-red-500">&times;</button>
            </div>
            <div className="p-5 space-y-4">
              <div className="flex gap-3">
                <div className="flex-1">
                  <label className="text-xs uppercase tracking-wider text-slate-500">Agent Type</label>
                  <select value={deployAgentType} onChange={(e) => setDeployAgentType(e.target.value)} className={`w-full rounded border px-3 py-2 text-sm mt-1 ${inputClass}`}>
                    <option value="nodetrace">NodeTrace (Python telemetry)</option>
                    <option value="aegis-guard">Aegis-Guard (Java EDR)</option>
                  </select>
                </div>
                <div className="flex-1">
                  <label className="text-xs uppercase tracking-wider text-slate-500">Method</label>
                  <select value={deployMethod} onChange={(e) => setDeployMethod(e.target.value)} className={`w-full rounded border px-3 py-2 text-sm mt-1 ${inputClass}`}>
                    <option value="manual">Manual (show command)</option>
                    <option value="winrm">WinRM (Windows)</option>
                    <option value="ssh">SSH (Linux)</option>
                  </select>
                </div>
              </div>

              {deployMethod !== 'manual' && (
                <div className="space-y-3 border-t border-slate-700 pt-3">
                  <p className="text-xs text-slate-500">Credentials for remote deploy:</p>
                  <input value={deployUsername} onChange={(e) => setDeployUsername(e.target.value)} placeholder="Username (e.g. Administrator)" className={`w-full rounded border px-3 py-2 text-sm ${inputClass}`} />
                  <div className="relative">
                    <input value={deployPassword} onChange={(e) => setDeployPassword(e.target.value)} type={showPassword ? 'text' : 'password'} placeholder="Password" className={`w-full rounded border px-3 py-2 text-sm ${inputClass}`} />
                    <button onClick={() => setShowPassword(!showPassword)} className="absolute right-2 top-2 text-slate-500 hover:text-white">
                      {showPassword ? <EyeOff size={16}/> : <Eye size={16}/>}
                    </button>
                  </div>
                </div>
              )}

              <div className="flex gap-3 pt-2">
                <button onClick={generatePlan} disabled={loading} className="flex-1 inline-flex items-center justify-center gap-2 rounded border border-cyan-800 bg-cyan-950/30 px-4 py-2 text-sm font-bold text-cyan-300 hover:bg-cyan-900/40 disabled:opacity-50">
                  <Terminal size={16}/> {loading ? 'Generating...' : 'Show Command'}
                </button>
                {deployMethod !== 'manual' && (
                  <button onClick={executeDeploy} disabled={deploying || !deployUsername || !deployPassword} className="flex-1 inline-flex items-center justify-center gap-2 rounded bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-500 disabled:opacity-50">
                    <Upload size={16}/> {deploying ? 'Deploying...' : 'Deploy Now'}
                  </button>
                )}
              </div>

              {plan && (
                <div className={`p-3 rounded border text-sm space-y-2 ${settings.darkMode ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-500">Method</span>
                    <span className="text-cyan-400">{plan.method}</span>
                  </div>
                  {plan.deploy_command ? (
                    <div>
                      <div className="text-xs uppercase text-green-500 mb-1">Remote command</div>
                      <code className="block rounded bg-slate-950 p-2 text-xs text-green-300 whitespace-pre-wrap max-h-32 overflow-auto">{plan.deploy_command}</code>
                    </div>
                  ) : (
                    <div>
                      <div className="text-xs uppercase text-slate-500 mb-1">Run on target host:</div>
                      <code className="block rounded bg-slate-950 p-2 text-xs text-cyan-300 whitespace-pre-wrap">{plan.local_command}</code>
                    </div>
                  )}
                  <p className="text-xs text-slate-500">{plan.note}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
