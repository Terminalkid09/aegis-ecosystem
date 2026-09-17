import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert, Plus, Trash2, CheckCircle, XCircle, Beaker, Swords, Filter, Eye, EyeOff, Activity, Loader2 } from 'lucide-react'
import { apiClient } from '@/services/api'
import { PermissionGate } from '@/components/common/PermissionGate'
import { cn, asArray } from '@/lib/utils'

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-500/10 text-red-400 border border-red-500/20',
  HIGH: 'bg-orange-500/10 text-orange-400 border border-orange-500/20',
  MEDIUM: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  LOW: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
}

const MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact'
]

const TARGET_FIELDS = [
  { value: 'process_name', label: 'Process Name' },
  { value: 'process_path', label: 'Process Path' },
  { value: 'file_hash', label: 'File Hash / Raw Message' },
  { value: 'ip_address', label: 'IP Address' },
  { value: 'hostname', label: 'Hostname' },
  { value: 'user', label: 'User' },
]

export default function RulesManager() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'custom' | 'static' | 'test'>('custom')
  const [showForm, setShowForm] = useState(false)
  const [newRule, setNewRule] = useState<any>({
    name: '', description: '', target_field: 'process_name', pattern: '', severity: 'MEDIUM',
    mitre_tactic: '', mitre_technique: '', mitre_technique_id: '',
    conditions: null, whitelist: { hostnames: [], ips: [] }, auto_remediation: '',
  })

  const [testEvent, setTestEvent] = useState(JSON.stringify({ process_name: 'powershell.exe', process_path: 'C:\\Users\\test\\AppData\\Local\\Temp\\payload.exe', event_type: 'PROCESS_CREATED', agent_id: 'test', timestamp: new Date().toISOString() }, null, 2))
  const [testResults, setTestResults] = useState<any>(null)

  const { data: rules = [], isLoading: loadingRules, error: rulesError } = useQuery({
    queryKey: ['custom-rules'],
    // Audit schermo-nero: asArray, mai `|| []` su dati non verificati.
    queryFn: () => apiClient.get('/rules/').then(r => asArray(r.data)),
  })

  const { data: staticRules = [], isLoading: loadingStatic } = useQuery({
    queryKey: ['static-rules'],
    queryFn: () => apiClient.get('/rules/static').then(r => asArray(r.data)),
  })

  const createMut = useMutation({
    mutationFn: (payload: any) => apiClient.post('/rules/', payload),
    onSuccess: () => {
      setShowForm(false)
      setNewRule({ name: '', description: '', target_field: 'process_name', pattern: '', severity: 'MEDIUM', mitre_tactic: '', mitre_technique: '', mitre_technique_id: '', conditions: null, whitelist: { hostnames: [], ips: [] }, auto_remediation: '' })
      qc.invalidateQueries({ queryKey: ['custom-rules'] })
    },
    onError: () => alert("Error creating rule.")
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiClient.delete(`/rules/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['custom-rules'] })
  })

  const toggleMut = useMutation({
    mutationFn: (rule: any) => apiClient.patch(`/rules/${rule.id}`, { is_active: !rule.is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['custom-rules'] })
  })

  const testMut = useMutation({
    mutationFn: (event: any) => apiClient.post('/rules/test', { event }),
    onSuccess: (r) => setTestResults(r.data),
    onError: () => alert("Invalid JSON or API error. Check console.")
  })

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault()
    const payload = { ...newRule }
    if (!payload.mitre_tactic) delete payload.mitre_tactic
    if (!payload.mitre_technique) delete payload.mitre_technique
    if (!payload.mitre_technique_id) delete payload.mitre_technique_id
    if (!payload.auto_remediation) delete payload.auto_remediation
    createMut.mutate(payload)
  }

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <ShieldAlert className="text-red-400" /> Detection Rules Engine
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">MITRE ATT&CK-powered threat detection with custom rules</p>
        </div>
        {tab === 'custom' && (
          <button onClick={() => setShowForm(!showForm)} className={cn("btn btn-primary px-4", showForm ? "bg-[hsl(var(--secondary))] border-[hsl(var(--border))]" : "bg-cyan-600 hover:bg-cyan-500 border-cyan-500 shadow-cyan-500/20")}>
            {showForm ? <XCircle size={16}/> : <Plus size={16}/>}
            {showForm ? 'Cancel' : 'New Rule'}
          </button>
        )}
      </div>

      <div className="flex gap-2 border-b border-[hsl(var(--border))] pb-2 overflow-x-auto no-scrollbar shrink-0">
        {[
          { id: 'custom', icon: Filter, label: 'Custom Rules' },
          { id: 'static', icon: Swords, label: 'MITRE ATT&CK Rules' },
          { id: 'test', icon: Beaker, label: 'Rule Tester' },
        ].map(t => (
          <button 
            key={t.id} 
            onClick={() => setTab(t.id as any)} 
            className={cn(
              "px-4 py-2 rounded-t-lg font-bold text-sm flex items-center gap-2 transition-all whitespace-nowrap",
              tab === t.id ? "bg-[hsl(var(--card))] text-cyan-400 border-t border-l border-r border-[hsl(var(--border))] translate-y-[1px]" : "text-[hsl(var(--muted-foreground))] hover:text-white"
            )}
          >
            <t.icon size={16}/> {t.label}
          </button>
        ))}
      </div>

      {tab === 'custom' && (
        <div className="space-y-6">
          {showForm && (
            <div className="card p-6 border-cyan-500/30 shadow-2xl shadow-cyan-500/5 animate-fade-in">
              <h3 className="text-sm font-black uppercase tracking-widest text-cyan-400 mb-5 border-b border-[hsl(var(--border))] pb-2">Create New Detection Rule</h3>
              <form onSubmit={handleCreateRule} className="space-y-5">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Rule Name</label>
                    <input required type="text" value={newRule.name} onChange={e => setNewRule({...newRule, name: e.target.value})} placeholder="e.g. Block Suspicious IP" className="input" />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Severity</label>
                    <select value={newRule.severity} onChange={e => setNewRule({...newRule, severity: e.target.value})} className="input font-bold">
                      <option value="LOW" className="text-emerald-400">LOW</option>
                      <option value="MEDIUM" className="text-yellow-400">MEDIUM</option>
                      <option value="HIGH" className="text-orange-400">HIGH</option>
                      <option value="CRITICAL" className="text-red-400">CRITICAL</option>
                    </select>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Target Field</label>
                    <select value={newRule.target_field} onChange={e => setNewRule({...newRule, target_field: e.target.value})} className="input font-mono text-xs">
                      {TARGET_FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
                    </select>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Regex Pattern</label>
                    <input required type="text" value={newRule.pattern} onChange={e => setNewRule({...newRule, pattern: e.target.value})} placeholder="e.g. .*malware.*" className="input font-mono text-xs text-cyan-400" />
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {/* MITRE Mapping */}
                  <div className="border border-[hsl(var(--border))] rounded-lg p-4 bg-[hsl(var(--secondary))]">
                    <h4 className="text-[10px] font-bold text-cyan-400 uppercase tracking-widest mb-3">MITRE ATT&CK Mapping</h4>
                    <div className="space-y-3">
                      <div>
                        <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest block mb-1">Tactic</label>
                        <select value={newRule.mitre_tactic} onChange={e => setNewRule({...newRule, mitre_tactic: e.target.value})} className="input bg-[hsl(var(--background))]">
                          <option value="">-- None --</option>
                          {MITRE_TACTICS.map(t => <option key={t} value={t}>{t}</option>)}
                        </select>
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest block mb-1">Technique Name</label>
                          <input type="text" value={newRule.mitre_technique} onChange={e => setNewRule({...newRule, mitre_technique: e.target.value})} placeholder="e.g. PowerShell" className="input bg-[hsl(var(--background))]" />
                        </div>
                        <div>
                          <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest block mb-1">Technique ID</label>
                          <input type="text" value={newRule.mitre_technique_id} onChange={e => setNewRule({...newRule, mitre_technique_id: e.target.value})} placeholder="e.g. T1059.001" className="input bg-[hsl(var(--background))] font-mono" />
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    {/* Auto-Remediation */}
                    <div className="border border-[hsl(var(--border))] rounded-lg p-4 bg-[hsl(var(--secondary))]">
                      <h4 className="text-[10px] font-bold text-purple-400 uppercase tracking-widest mb-3">Auto-Remediation</h4>
                      <select value={newRule.auto_remediation} onChange={e => setNewRule({...newRule, auto_remediation: e.target.value})} className="input bg-[hsl(var(--background))]">
                        <option value="">-- None (alert only) --</option>
                        <option value="kill_process">⚡ Kill Process</option>
                        <option value="block_ip">🔒 Block IP</option>
                        <option value="isolate_agent">🛡️ Isolate Agent</option>
                      </select>
                    </div>
                    
                    {/* Whitelist */}
                    <div className="border border-[hsl(var(--border))] rounded-lg p-4 bg-[hsl(var(--secondary))]">
                      <h4 className="text-[10px] font-bold text-emerald-400 uppercase tracking-widest mb-3">Whitelist</h4>
                      <div className="space-y-3">
                        <input type="text" value={(newRule.whitelist?.hostnames || []).join(', ')} onChange={e => setNewRule({...newRule, whitelist: { ...newRule.whitelist, hostnames: e.target.value.split(',').map(s => s.trim()).filter(Boolean) }})} placeholder="Excluded Hostnames (e.g. admin-pc)" className="input bg-[hsl(var(--background))]" />
                        <input type="text" value={(newRule.whitelist?.ips || []).join(', ')} onChange={e => setNewRule({...newRule, whitelist: { ...newRule.whitelist, ips: e.target.value.split(',').map(s => s.trim()).filter(Boolean) }})} placeholder="Excluded IPs (e.g. 127.0.0.1)" className="input bg-[hsl(var(--background))]" />
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Description</label>
                  <input type="text" value={newRule.description} onChange={e => setNewRule({...newRule, description: e.target.value})} placeholder="What does this rule detect?" className="input" />
                </div>

                <div className="pt-2 flex justify-end">
                  <PermissionGate perms={['rules']}>
                    <button type="submit" disabled={createMut.isPending} className="btn btn-primary bg-emerald-600 hover:bg-emerald-500 shadow-emerald-500/20 px-6 py-2">
                      {createMut.isPending ? <Loader2 size={18} className="animate-spin" /> : <CheckCircle size={18} />} 
                      Save Rule
                    </button>
                  </PermissionGate>
                </div>
              </form>
            </div>
          )}

          {loadingRules ? (
            <div className="text-center py-10 text-[hsl(var(--muted-foreground))] italic flex items-center justify-center gap-3">
              <Loader2 size={24} className="animate-spin text-cyan-400" /> Loading custom rules...
            </div>
          ) : rulesError ? (
            <div className="text-center py-10 text-red-400 font-bold border border-red-500/20 bg-red-500/5 rounded-xl">Error loading custom rules</div>
          ) : rules.length === 0 ? (
            <div className="text-center py-16 border-2 border-dashed border-[hsl(var(--border))] bg-[hsl(var(--secondary)/0.3)] rounded-xl text-[hsl(var(--muted-foreground))]">
              <ShieldAlert size={48} className="mx-auto mb-4 opacity-20 text-cyan-400" />
              <p className="text-lg font-bold text-white">No custom rules configured</p>
              <p className="text-sm mt-1">Click 'New Rule' to define custom threats tailored to your environment.</p>
            </div>
          ) : (
            <div className="card overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm whitespace-nowrap">
                  <thead className="bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] text-xs uppercase tracking-wider">
                    <tr>
                      <th className="p-4 font-medium">Rule</th>
                      <th className="p-4 font-medium">MITRE</th>
                      <th className="p-4 font-medium">Target</th>
                      <th className="p-4 font-medium">Severity</th>
                      <th className="p-4 font-medium text-center">Triggers</th>
                      <th className="p-4 font-medium text-center">Status</th>
                      <th className="p-4 font-medium text-center">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[hsl(var(--border))]">
                    {rules.map((rule: any) => (
                      <tr key={rule.id} className="hover:bg-[hsl(var(--secondary)/50)] transition-colors">
                        <td className="p-4">
                          <div className="font-bold text-cyan-400">{rule.name}</div>
                          {rule.description && <div className="text-xs text-[hsl(var(--muted-foreground))] mt-0.5 truncate max-w-xs">{rule.description}</div>}
                          <div className="flex gap-1.5 mt-2">
                            {rule.auto_remediation && (
                              <span className="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-widest bg-purple-500/10 text-purple-400 border border-purple-500/20">
                                {rule.auto_remediation === 'kill_process' ? '⚡ Kill' : rule.auto_remediation === 'block_ip' ? '🔒 Block' : rule.auto_remediation === 'isolate_agent' ? '🛡️ Isolate' : rule.auto_remediation}
                              </span>
                            )}
                            {(rule.whitelist?.hostnames?.length > 0 || rule.whitelist?.ips?.length > 0) && (
                              <span className="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-widest bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">✓ Whitelist</span>
                            )}
                          </div>
                        </td>
                        <td className="p-4">
                          {rule.mitre_technique_id ? (
                            <div className="flex flex-col gap-1">
                              {rule.mitre_tactic && <span className="text-[10px] text-[hsl(var(--muted-foreground))] uppercase font-bold">{rule.mitre_tactic}</span>}
                              <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 text-[10px] font-mono font-bold border border-blue-500/20 w-fit">
                                {rule.mitre_technique_id} {rule.mitre_technique || ''}
                              </span>
                            </div>
                          ) : <span className="text-[hsl(var(--muted-foreground))] text-xs italic">—</span>}
                        </td>
                        <td className="p-4"><span className="px-2 py-1 rounded bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] text-[10px] font-mono text-[hsl(var(--muted-foreground))]">{rule.target_field}</span></td>
                        <td className="p-4">
                          <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest', SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.MEDIUM)}>
                            {rule.severity}
                          </span>
                        </td>
                        <td className="p-4 text-center">
                          <div className="flex items-center justify-center gap-1.5 text-xs font-bold text-[hsl(var(--muted-foreground))]">
                            <Activity size={14} className={rule.trigger_count > 0 ? 'text-cyan-400' : ''} />
                            {rule.trigger_count || 0}
                          </div>
                          {rule.last_triggered && <div className="text-[9px] text-[hsl(var(--muted-foreground))] mt-1 font-mono">{new Date(rule.last_triggered).toLocaleTimeString()}</div>}
                        </td>
                        <td className="p-4 text-center">
                          <PermissionGate perms={['rules']}>
                            <button onClick={() => toggleMut.mutate(rule)} className={cn('p-1.5 rounded transition-colors', rule.is_active ? 'text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20' : 'text-[hsl(var(--muted-foreground))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--border))]')}>
                              {rule.is_active ? <Eye size={16} /> : <EyeOff size={16} />}
                            </button>
                          </PermissionGate>
                        </td>
                        <td className="p-4 text-center">
                          <PermissionGate perms={['rules']}>
                            <button onClick={() => { if(confirm("Delete rule?")) deleteMut.mutate(rule.id) }} className="p-1.5 text-[hsl(var(--muted-foreground))] hover:text-red-400 hover:bg-red-500/10 rounded transition-colors" title="Delete Rule">
                              <Trash2 size={16} />
                            </button>
                          </PermissionGate>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'static' && (
        <div className="card overflow-hidden animate-fade-in">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] text-xs uppercase tracking-wider">
                <tr>
                  <th className="p-4 font-medium">Rule Name</th>
                  <th className="p-4 font-medium">MITRE ATT&CK</th>
                  <th className="p-4 font-medium">Severity</th>
                  <th className="p-4 font-medium w-full">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[hsl(var(--border))]">
                {loadingStatic ? (
                  <tr><td colSpan={4} className="p-8 text-center text-[hsl(var(--muted-foreground))] italic">Loading static rules...</td></tr>
                ) : staticRules.map((rule: any, i: number) => (
                  <tr key={i} className="hover:bg-[hsl(var(--secondary)/50)] transition-colors">
                    <td className="p-4 font-bold text-white">{rule.name}</td>
                    <td className="p-4">
                      <div className="flex flex-col gap-1">
                        <span className="text-[10px] text-[hsl(var(--muted-foreground))] uppercase font-bold">{rule.mitre_tactic}</span>
                        <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 text-[10px] font-mono font-bold border border-blue-500/20 w-fit">
                          {rule.mitre_technique_id} {rule.mitre_technique}
                        </span>
                      </div>
                    </td>
                    <td className="p-4">
                      <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest', SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.MEDIUM)}>
                        {rule.severity}
                      </span>
                    </td>
                    <td className="p-4 text-xs text-[hsl(var(--muted-foreground))] truncate max-w-md">{rule.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'test' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-fade-in">
          <div className="card p-5 h-fit">
            <h3 className="font-bold mb-4 flex items-center gap-2 text-white"><Beaker size={18} className="text-purple-400" /> Test Event (JSON)</h3>
            <textarea 
              value={testEvent} 
              onChange={e => setTestEvent(e.target.value)} 
              className="input h-[300px] font-mono text-[10px] sm:text-xs text-emerald-400 resize-none bg-[hsl(var(--background))]" 
            />
            <PermissionGate perms={['rules']}>
            <button 
              onClick={() => {
                try { JSON.parse(testEvent); testMut.mutate(JSON.parse(testEvent)) } catch { alert("Invalid JSON") }
              }} 
              disabled={testMut.isPending}
              className="btn btn-primary w-full mt-4 bg-purple-600 hover:bg-purple-500 border-purple-500 shadow-purple-500/20"
            >
              {testMut.isPending ? <Loader2 size={16} className="animate-spin" /> : <Beaker size={16} />}
              {testMut.isPending ? 'Testing...' : 'Run Against All Rules'}
            </button>
            </PermissionGate>
          </div>
          
          <div className="card p-5 h-fit">
            <h3 className="font-bold mb-4 flex items-center gap-2 text-white"><ShieldAlert size={18} className="text-red-400" /> Detection Results</h3>
            {testResults === null ? (
              <div className="h-[300px] flex items-center justify-center text-center text-[hsl(var(--muted-foreground))] text-sm border-2 border-dashed border-[hsl(var(--border))] rounded-lg bg-[hsl(var(--secondary)/0.3)]">
                Click "Run Against All Rules" to test.
              </div>
            ) : testResults.length === 0 ? (
              <div className="h-[300px] flex flex-col items-center justify-center text-center border-2 border-dashed border-emerald-500/30 rounded-lg bg-emerald-500/5">
                <CheckCircle size={48} className="text-emerald-500 mb-3" />
                <p className="font-bold text-emerald-400 text-lg">No rules matched</p>
                <p className="text-xs text-emerald-500/70 mt-1">The test event is clean.</p>
              </div>
            ) : (
              <div className="space-y-3 h-[300px] overflow-y-auto pr-2">
                {testResults.map((r: any, i: number) => (
                  <div key={i} className={cn('p-4 rounded-xl border', r.severity === 'CRITICAL' ? 'bg-red-500/10 border-red-500/20' : r.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/20' : 'bg-yellow-500/10 border-yellow-500/20')}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-bold text-sm text-white">{r.rule_name}</span>
                      <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest', SEVERITY_COLORS[r.severity])}>{r.severity}</span>
                    </div>
                    <p className="text-xs text-[hsl(var(--muted-foreground))]">{r.description}</p>
                    {r.mitre_technique_id && <span className="text-[10px] text-blue-400 font-mono font-bold mt-2 inline-block bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">{r.mitre_technique_id}</span>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
