import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Network, Search, Play, RefreshCcw, ShieldCheck, Terminal, Upload, Wifi, Monitor, Smartphone, Info, X } from 'lucide-react'
import { discoveryAPI, agentsAPI } from '@/services/api'
import { useAppStore } from '@/store/appStore'
import { cn } from '@/lib/utils'

export default function DiscoveryCenter() {
  const qc = useQueryClient()
  const { setCurrentPage } = useAppStore()

  // State
  const [msg, setMsg] = useState('')
  const [selectedIp, setSelectedIp] = useState('')
  const [repLabel, setRepLabel] = useState('suspicious')
  const [cidr, setCidr] = useState('192.168.1.0/24')
  const [selectedAgentId, setSelectedAgentId] = useState('')
  const [probeTimeout, setProbeTimeout] = useState(0.1)
  const [manualIp, setManualIp] = useState('')
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set())
  const [showRepHelp, setShowRepHelp] = useState(false)
  const [deployModal, setDeployModal] = useState<any>(null)
  const [deployAgentType, setDeployAgentType] = useState('nodetrace')
  const [plan, setPlan] = useState<any>(null)

  // Queries
  const { data: hosts = [], isLoading: loadingHosts } = useQuery({
    queryKey: ['discovery-hosts'],
    queryFn: () => discoveryAPI.getHosts().then(r => r.data.items || []),
    refetchInterval: 15000,
  })

  const { data: reputation = [] } = useQuery({
    queryKey: ['discovery-reputation'],
    queryFn: () => discoveryAPI.getReputation().then(r => r.data.items || []),
  })

  const { data: agents = [] } = useQuery({
    queryKey: ['agents-active'],
    queryFn: () => agentsAPI.getAgents({ active_only: true }).then(r => r.data || []),
  })

  // Set default agent when agents load
  useEffect(() => {
    if (agents.length > 0 && !selectedAgentId) {
      setSelectedAgentId(agents[0].agent_id)
    }
  }, [agents, selectedAgentId])

  // Mutations
  const scanMut = useMutation({
    mutationFn: () => discoveryAPI.scan({ cidr, include_unreachable: false }),
    onSuccess: (res) => {
      setMsg(`Scan complete: ${res.data.discovered?.length || 0} reachable host(s).`)
      qc.invalidateQueries({ queryKey: ['discovery-hosts'] })
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Scan failed.')
  })

  const scanViaAgentMut = useMutation({
    mutationFn: () => discoveryAPI.scanViaAgent(selectedAgentId, { cidr, ports: [22, 80, 135, 139, 443, 445, 3389, 8000, 8080], probe_timeout: probeTimeout }),
    onSuccess: () => {
      setMsg(`Scan command sent to agent. Results will populate shortly via polling.`)
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Failed to queue agent scan command.')
  })

  const syncStatusMut = useMutation({
    mutationFn: () => discoveryAPI.syncAgentStatus(),
    onSuccess: (res) => {
      setMsg(`Agent status synced: ${res.data.count} hosts updated.`)
      qc.invalidateQueries({ queryKey: ['discovery-hosts'] })
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Sync failed.')
  })

  const startDemoMut = useMutation({
    mutationFn: () => discoveryAPI.startDemo(),
    onSuccess: () => {
      setMsg('Demo endpoints online. Use Refresh Demo Heartbeat to keep them fresh.')
      qc.invalidateQueries({ queryKey: ['discovery-hosts'] })
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Demo start failed.')
  })

  const demoHeartbeatMut = useMutation({
    mutationFn: () => discoveryAPI.demoHeartbeat(),
    onSuccess: (res) => {
      setMsg(`Demo heartbeat refreshed for ${res.data.count || 0} agent(s).`)
      qc.invalidateQueries({ queryKey: ['discovery-hosts'] })
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Demo heartbeat failed.')
  })

  const saveReputationMut = useMutation({
    mutationFn: () => discoveryAPI.upsertReputation({
      ip_address: selectedIp,
      label: repLabel,
      confidence: repLabel === 'malicious' ? 90 : repLabel === 'suspicious' ? 65 : 40,
      source: 'analyst',
    }),
    onSuccess: () => {
      setMsg(`Reputation saved for ${selectedIp}.`)
      qc.invalidateQueries({ queryKey: ['discovery-reputation'] })
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Failed to save reputation.')
  })

  const addManualHostMut = useMutation({
    mutationFn: () => discoveryAPI.scan({ cidr: `${manualIp}/32`, include_unreachable: true, fast_scan: false }),
    onSuccess: () => {
      setMsg(`Added ${manualIp} to discovery.`)
      setManualIp('')
      qc.invalidateQueries({ queryKey: ['discovery-hosts'] })
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Failed to add host.')
  })

  const planMut = useMutation({
    mutationFn: (host: any) => {
      const osGuess = host.os_guess?.includes('windows') ? 'windows' : 'linux'
      return discoveryAPI.deploymentPlan({
        ip_address: host.ip_address,
        os_type: osGuess,
        agent_type: deployAgentType,
        method: 'manual',
      })
    },
    onSuccess: (res, host) => {
      setSelectedIp(host.ip_address)
      setPlan(res.data)
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Failed to generate plan.')
  })

  // Handlers
  const toggleSelect = (ip: string) => {
    const next = new Set(selectedHosts)
    if (next.has(ip)) next.delete(ip)
    else next.add(ip)
    setSelectedHosts(next)
  }

  const toggleAll = () => {
    if (selectedHosts.size === hosts.length) setSelectedHosts(new Set())
    else setSelectedHosts(new Set((hosts as any[]).map(h => h.ip_address)))
  }

  const handleMassDeploy = () => {
    localStorage.setItem('aegis-deploy-targets', JSON.stringify(Array.from(selectedHosts)))
    setSelectedHosts(new Set())
    setCurrentPage('deploy')
  }

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Network className="text-cyan-400" /> Aegis Discovery</h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">Network discovery, agent enrollment, and reputation.</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => syncStatusMut.mutate()} disabled={syncStatusMut.isPending} className="btn btn-ghost text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/10">
            <ShieldCheck size={14} /> Sync Agents
          </button>
          <button onClick={() => qc.invalidateQueries()} className="btn btn-ghost border border-[hsl(var(--border))]">
            <RefreshCcw size={14} /> Refresh
          </button>
        </div>
      </div>

      {msg && <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-400 animate-fade-in">{msg}</div>}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Scan Panel */}
        <div className="card p-5 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))] flex items-center gap-2"><Search size={14}/> Discovery Scan</h3>
          <input value={cidr} onChange={e => setCidr(e.target.value)} className="input font-mono" placeholder="192.168.1.0/24" />
          <button onClick={() => scanMut.mutate()} disabled={scanMut.isPending} className="btn btn-primary w-full bg-cyan-600 hover:bg-cyan-500 border-cyan-500 shadow-cyan-500/20 text-white">
            <Search size={16}/> {scanMut.isPending ? 'Scanning...' : 'Scan Network (Docker)'}
          </button>
          
          <div className="border-t border-[hsl(var(--border))] pt-3 space-y-2">
            <p className="text-[10px] uppercase font-semibold text-[hsl(var(--muted-foreground))]">Scan via agent (from host network):</p>
            <div className="flex gap-2">
              <select value={selectedAgentId} onChange={e => setSelectedAgentId(e.target.value)} className="input font-mono text-xs flex-1">
                <option value="">Select active agent...</option>
                {agents.map((a: any) => <option key={a.agent_id} value={a.agent_id}>{a.hostname || a.agent_id.slice(0,12)}</option>)}
              </select>
              <button disabled={scanViaAgentMut.isPending || !selectedAgentId} onClick={() => scanViaAgentMut.mutate()} className="btn btn-primary bg-purple-600 hover:bg-purple-500 border-purple-500 px-3">
                <Search size={14}/>
              </button>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-[hsl(var(--muted-foreground))]">ARP probe:</span>
              <input type="range" min="0.05" max="0.5" step="0.05" value={probeTimeout} onChange={e => setProbeTimeout(parseFloat(e.target.value))} className="flex-1 h-1 accent-purple-500" />
              <span className="text-[10px] font-mono text-purple-400 w-8 text-right">{probeTimeout.toFixed(2)}s</span>
            </div>
          </div>
          
          <div className="border-t border-[hsl(var(--border))] pt-3">
            <p className="text-[10px] uppercase font-semibold text-[hsl(var(--muted-foreground))] mb-2">Add host manually:</p>
            <div className="flex gap-2">
              <input value={manualIp} onChange={e => setManualIp(e.target.value)} placeholder="192.168.1.100" className="input font-mono flex-1" />
              <button onClick={() => addManualHostMut.mutate()} disabled={!manualIp || addManualHostMut.isPending} className="btn btn-ghost bg-[hsl(var(--secondary))]"><Search size={14}/></button>
            </div>
          </div>
          
          <div className="border-t border-[hsl(var(--border))] pt-3 space-y-2">
            <button onClick={() => startDemoMut.mutate()} disabled={startDemoMut.isPending} className="btn btn-primary w-full bg-purple-600 hover:bg-purple-500 border-purple-500">
              <Play size={16}/> Start Demo Mode
            </button>
            <button onClick={() => demoHeartbeatMut.mutate()} disabled={demoHeartbeatMut.isPending} className="btn btn-ghost w-full border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10">
              <ShieldCheck size={16}/> Refresh Demo Heartbeat
            </button>
          </div>
        </div>

        {/* Reputation Panel */}
        <div className="card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))] flex items-center gap-2">
              <ShieldCheck size={14}/> IP Reputation
            </h3>
            <button onClick={() => setShowRepHelp(!showRepHelp)} className="text-[hsl(var(--muted-foreground))] hover:text-white"><Info size={14}/></button>
          </div>
          
          {showRepHelp && (
            <div className="text-xs text-[hsl(var(--muted-foreground))] bg-[hsl(var(--secondary))] rounded-lg p-3 border border-[hsl(var(--border))] leading-relaxed animate-fade-in">
              Tag network IPs as <span className="text-emerald-400 font-semibold">known</span>, <span className="text-yellow-400 font-semibold">suspicious</span> or <span className="text-red-400 font-semibold">malicious</span>.<br/>
              Used by OSINT and AI to prioritize threats.
            </div>
          )}
          
          <input value={selectedIp} onChange={e => setSelectedIp(e.target.value)} placeholder="IP Address (e.g. 192.168.1.20)" className="input font-mono" />
          <select value={repLabel} onChange={e => setRepLabel(e.target.value)} className="input">
            <option value="known">known — trusted host</option>
            <option value="suspicious">suspicious — anomalous behavior</option>
            <option value="malicious">malicious — active threat</option>
            <option value="unknown">unknown — no info</option>
          </select>
          <button onClick={() => saveReputationMut.mutate()} disabled={!selectedIp || saveReputationMut.isPending} className="btn btn-primary w-full bg-emerald-600 hover:bg-emerald-500 border-emerald-500 shadow-emerald-500/20 text-white">Save Reputation</button>
          
          <div className="space-y-2 max-h-48 overflow-y-auto pt-2">
            {reputation.map((item: any) => (
              <button key={item.ip_address} onClick={() => { setSelectedIp(item.ip_address); setRepLabel(item.label) }} className="w-full flex justify-between items-center rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] px-3 py-2 text-xs hover:border-[hsl(var(--primary)/0.5)] transition-colors">
                <span className="font-mono text-white">{item.ip_address}</span>
                <span className={cn('font-bold uppercase tracking-wider text-[10px]', item.label === 'malicious' ? 'text-red-400' : item.label === 'suspicious' ? 'text-yellow-400' : 'text-emerald-400')}>{item.label}</span>
              </button>
            ))}
            {reputation.length === 0 && <p className="text-xs text-[hsl(var(--muted-foreground))] text-center py-4 italic">No reputation tags set.</p>}
          </div>
        </div>

        {/* Plan Panel */}
        <div className="card p-5 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))] flex items-center gap-2"><Terminal size={14}/> Deployment Plan</h3>

          {plan ? (
            <div className="space-y-3 text-sm animate-fade-in">
              <div className="flex justify-between"><span className="text-[hsl(var(--muted-foreground))]">Target</span><span className="font-mono text-white">{plan.ip_address}</span></div>
              <div className="flex justify-between"><span className="text-[hsl(var(--muted-foreground))]">Agent</span><span className="text-white">{plan.agent_type}</span></div>
              <div className="flex justify-between"><span className="text-[hsl(var(--muted-foreground))]">Method</span><span className="text-white">{plan.method}</span></div>
              
              <div className="pt-2 border-t border-[hsl(var(--border))]">
                <div className="text-[10px] uppercase font-bold text-[hsl(var(--muted-foreground))] mb-1">Command to run on target:</div>
                <code className="block rounded-lg bg-[hsl(var(--background))] border border-[hsl(var(--border))] p-3 text-xs text-cyan-400 font-mono whitespace-pre-wrap">{plan.deploy_command || plan.local_command}</code>
              </div>
              <p className="text-[10px] text-[hsl(var(--muted-foreground))]">{plan.note}</p>
              <button onClick={() => setPlan(null)} className="btn btn-ghost w-full text-xs">Clear Plan</button>
            </div>
          ) : (
            <div className="h-48 flex items-center justify-center text-xs text-[hsl(var(--muted-foreground))] border border-dashed border-[hsl(var(--border))] rounded-lg bg-[hsl(var(--secondary)/0.5)]">
              Select a host in the table and click <strong className="text-cyan-400 mx-1">Cmd</strong>
            </div>
          )}
        </div>
      </div>

      {/* Hosts Table */}
      <div className="card overflow-hidden">
        <div className="flex flex-wrap items-center gap-3 px-4 py-3 border-b border-[hsl(var(--border))] bg-[hsl(var(--secondary))]">
          <span className="text-xs font-bold text-white">{selectedHosts.size} selected</span>
          <button
            disabled={selectedHosts.size === 0}
            onClick={handleMassDeploy}
            className="btn btn-primary bg-purple-600 hover:bg-purple-500 border-purple-500 py-1.5 px-3 text-xs shadow-purple-500/20"
          >
            <Upload size={12} /> Mass Deploy
          </button>
          {selectedHosts.size > 0 && <button onClick={() => setSelectedHosts(new Set())} className="text-xs text-[hsl(var(--muted-foreground))] hover:text-white transition-colors">Clear selection</button>}
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] text-xs uppercase tracking-wider">
              <tr>
                <th className="p-3 w-10"><input type="checkbox" className="rounded border-[hsl(var(--border))] bg-transparent" checked={hosts.length > 0 && selectedHosts.size === hosts.length} onChange={toggleAll} /></th>
                <th className="p-3 font-medium">Host</th>
                <th className="p-3 font-medium">Hardware</th>
                <th className="p-3 font-medium">Status</th>
                <th className="p-3 font-medium">OS Guess</th>
                <th className="p-3 font-medium">Open Ports</th>
                <th className="p-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[hsl(var(--border))]">
              {loadingHosts ? (
                <tr><td colSpan={7} className="p-8 text-center text-[hsl(var(--muted-foreground))]">Loading discovery data...</td></tr>
              ) : hosts.length === 0 ? (
                <tr><td colSpan={7} className="p-8 text-center text-[hsl(var(--muted-foreground))] italic">No discovered hosts yet. Run a scan.</td></tr>
              ) : (
                (hosts as any[]).map(host => {
                  const OSIcon = host.os_guess?.includes('windows') ? Monitor : host.os_guess?.includes('android') ? Smartphone : Wifi
                  return (
                    <tr key={host.ip_address} className={cn('hover:bg-[hsl(var(--secondary)/50)] transition-colors', selectedHosts.has(host.ip_address) && 'bg-[hsl(var(--primary)/0.05)]')}>
                      <td className="p-3"><input type="checkbox" className="rounded border-[hsl(var(--border))] bg-transparent" checked={selectedHosts.has(host.ip_address)} onChange={() => toggleSelect(host.ip_address)} /></td>
                      <td className="p-3">
                        <div className="font-mono text-cyan-400 font-semibold">{host.ip_address}</div>
                        <div className="text-[10px] text-[hsl(var(--muted-foreground))] flex items-center gap-1 mt-0.5"><OSIcon size={10}/> {host.hostname || 'unresolved'}</div>
                      </td>
                      <td className="p-3 text-xs">
                        <div className="font-mono text-[hsl(var(--muted-foreground))]">{host.mac_address || '—'}</div>
                        <div className="text-[10px] text-white/60 truncate max-w-[150px]">{host.vendor || '—'}</div>
                      </td>
                      <td className="p-3">
                        <span className={cn('px-2 py-0.5 rounded text-[9px] uppercase font-bold border', host.status === 'reachable' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-slate-500/10 text-slate-400 border-slate-500/20')}>{host.status}</span>
                      </td>
                      <td className="p-3 text-xs text-white">
                        {host.os_guess || 'unknown'} {host.os_confidence && <span className="text-[hsl(var(--muted-foreground))] ml-1">({host.os_confidence}%)</span>}
                      </td>
                      <td className="p-3 font-mono text-[10px] text-[hsl(var(--muted-foreground))] max-w-[120px] truncate" title={(host.open_ports || []).join(', ')}>
                        {(host.open_ports || []).join(', ') || '—'}
                      </td>
                      <td className="p-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button onClick={() => planMut.mutate(host)} className="btn btn-ghost py-1 px-2 text-xs border border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))] hover:text-white" title="Show command"><Terminal size={12}/> Cmd</button>
                          <button onClick={() => { setDeployModal(host); setPlan(null) }} className="btn btn-primary py-1 px-2 text-xs bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/30" title="Deploy agent"><Upload size={12}/> Deploy</button>
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Deploy Modal */}
      {deployModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in" onClick={() => setDeployModal(null)}>
          <div className="w-full max-w-lg bg-[hsl(var(--background))] border border-[hsl(var(--border))] rounded-xl shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
            <div className="px-5 py-4 border-b border-[hsl(var(--border))] flex items-center justify-between bg-[hsl(var(--card))]">
              <h2 className="text-lg font-bold text-white flex items-center gap-2"><Upload className="text-cyan-400" size={18} /> Deploy to {deployModal.ip_address}</h2>
              <button onClick={() => setDeployModal(null)} className="p-1 rounded hover:bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))]"><X size={18}/></button>
            </div>
            
            <div className="p-6 space-y-5 bg-[hsl(var(--background))]">
              <div>
                <label className="text-[10px] uppercase font-bold tracking-widest text-[hsl(var(--muted-foreground))] mb-1.5 block">Select Agent Type</label>
                <select value={deployAgentType} onChange={e => setDeployAgentType(e.target.value)} className="input">
                  <option value="nodetrace">NodeTrace (Python Telemetry)</option>
                  <option value="aegis-guard">Aegis-Guard (Java EDR)</option>
                  <option value="unified">Unified (Guard + NodeTrace)</option>
                </select>
              </div>

              <div className="p-3 rounded-lg border border-purple-500/20 bg-purple-500/10 text-xs text-purple-200">
                <p className="font-semibold mb-1">Recommended: Mass Deploy</p>
                <p className="opacity-80 mb-3">Use the Deployment Manager to roll out via SSH/WinRM safely without saving credentials.</p>
                <button onClick={() => {
                  localStorage.setItem('aegis-deploy-targets', JSON.stringify([deployModal.ip_address]))
                  setDeployModal(null)
                  setCurrentPage('deploy')
                }} className="btn btn-primary bg-purple-600 hover:bg-purple-500 w-full text-xs py-1.5"><Upload size={14} /> Open in Deployment Manager</button>
              </div>

              <div className="flex items-center gap-3 before:h-px before:flex-1 before:bg-[hsl(var(--border))] after:h-px after:flex-1 after:bg-[hsl(var(--border))] text-[10px] uppercase font-bold tracking-widest text-[hsl(var(--muted-foreground))]">
                OR
              </div>

              <button onClick={() => planMut.mutate(deployModal)} disabled={planMut.isPending} className="btn btn-ghost w-full border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 text-xs">
                <Terminal size={14}/> {planMut.isPending ? 'Generating...' : 'Show Manual Installation Command'}
              </button>

              {plan && (
                <div className="p-3 bg-[hsl(var(--secondary))] rounded-lg border border-[hsl(var(--border))] animate-fade-in text-xs space-y-2">
                  <div className="flex justify-between"><span className="text-[hsl(var(--muted-foreground))]">Method:</span><span className="font-semibold text-cyan-400">{plan.method}</span></div>
                  <div>
                    <div className="text-[10px] uppercase text-[hsl(var(--muted-foreground))] font-bold mb-1">Command</div>
                    <code className="block rounded bg-[hsl(var(--background))] border border-[hsl(var(--border))] p-2 font-mono text-emerald-400 whitespace-pre-wrap max-h-32 overflow-y-auto">{plan.deploy_command || plan.local_command}</code>
                  </div>
                  <p className="text-[10px] text-[hsl(var(--muted-foreground))]">{plan.note}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
