import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Rocket, KeyRound, Package, ClipboardCopy, RefreshCcw, Play, Ban, CheckCircle2, XCircle, Clock, Server, HelpCircle } from 'lucide-react'
import { deployAPI } from '@/services/api'
import { useAppStore } from '@/store/appStore'
import { cn } from '@/lib/utils'

function copyText(t: string, done?: () => void) {
  navigator.clipboard.writeText(t).then(() => done?.()).catch(() => {
    const ta = document.createElement('textarea')
    ta.value = t
    document.body.appendChild(ta)
    ta.select()
    try { document.execCommand('copy') } catch {}
    document.body.removeChild(ta)
    done?.()
  })
}

export default function DeployManager() {
  const qc = useQueryClient()
  const { setCurrentPage } = useAppStore()

  // Token Form
  const [tokenLabel, setTokenLabel] = useState('')
  const [tokenAgent, setTokenAgent] = useState('aegis-guard')
  const [lastToken, setLastToken] = useState<any>(null)
  const [copied, setCopied] = useState('')

  // Job Form
  const [agentType, setAgentType] = useState('nodetrace')
  const [method, setMethod] = useState('oneline')
  const [ipText, setIpText] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  // OTA Form
  const [otaAgent, setOtaAgent] = useState('')
  const [otaVersion, setOtaVersion] = useState('latest')
  const [otaResult, setOtaResult] = useState<any>(null)

  const [msg, setMsg] = useState('')

  // Queries
  const { data: tokens = [] } = useQuery({ queryKey: ['deploy-tokens'], queryFn: () => deployAPI.listTokens().then(r => r.data.items || []), refetchInterval: 10000 })
  const { data: artifacts = [] } = useQuery({ queryKey: ['deploy-artifacts'], queryFn: () => deployAPI.listArtifacts().then(r => r.data.items || []) })
  const { data: jobs = [] } = useQuery({ queryKey: ['deploy-jobs'], queryFn: () => deployAPI.listJobs().then(r => r.data.items || []), refetchInterval: 5000 })

  // Mutations
  const createTokenMut = useMutation({
    mutationFn: () => deployAPI.createToken({ label: tokenLabel || undefined, agent_type: tokenAgent }),
    onSuccess: (res) => {
      setLastToken(res.data)
      setTokenLabel('')
      setMsg('Single-use token created (expires in 15m). Do not commit this.')
      qc.invalidateQueries({ queryKey: ['deploy-tokens'] })
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Token creation failed.')
  })

  const revokeTokenMut = useMutation({
    mutationFn: (id: number) => deployAPI.revokeToken(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deploy-tokens'] })
  })

  const createJobMut = useMutation({
    mutationFn: (ips: string[]) => deployAPI.createJob({
      agent_type: agentType,
      agent_version: 'latest',
      method_default: method,
      targets: ips.map(ip => ({ ip_address: ip, method })),
      username: username || undefined,
      password: password || undefined,
    }),
    onSuccess: (res, ips) => {
      setPassword('') // wipe password
      setMsg(`Job #${res.data.job_id} queued for ${ips.length} hosts. Passwords were NOT saved.`)
      qc.invalidateQueries({ queryKey: ['deploy-jobs'] })
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Job creation failed.')
  })

  const otaMut = useMutation({
    mutationFn: () => deployAPI.pushUpdate(otaAgent.trim(), otaVersion.trim() || 'latest'),
    onSuccess: (r) => {
      setOtaResult(r.data)
      setMsg(r.data.queued ? `UPDATE_AGENT queued (sha ${r.data.command.sha256.slice(0, 12)}…)` : 'Queue offline — payload signed and ready for manual delivery.')
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'OTA Push failed.')
  })

  useEffect(() => {
    try {
      const sel = JSON.parse(localStorage.getItem('aegis-deploy-targets') || '[]')
      if (Array.isArray(sel) && sel.length) {
        setIpText(sel.join('\n'))
        setMsg(`${sel.length} hosts imported from Discovery. Complete form and start rollout.`)
        localStorage.removeItem('aegis-deploy-targets')
      }
    } catch {}
  }, [])

  const handleCreateJob = () => {
    const ips = ipText.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean)
    if (!ips.length) { setMsg('Please enter at least one target IP.'); return }
    setMsg('')
    createJobMut.mutate(ips)
  }

  const StatusIcon = ({ s }: { s: string }) => {
    if (s === 'ok') return <CheckCircle2 size={14} className="text-emerald-400" />
    if (s === 'failed') return <XCircle size={14} className="text-red-400" />
    if (s === 'running') return <Clock size={14} className="text-yellow-400 animate-pulse" />
    if (s === 'waiting_approval') return <HelpCircle size={14} className="text-purple-400 animate-pulse" />
    return <Clock size={14} className="text-[hsl(var(--muted-foreground))]" />
  }

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Rocket className="text-cyan-400" /> Deployment Manager</h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">Enterprise rollout via job queues, SSH/WinRM, and one-liners</p>
        </div>
      </div>

      {msg && (
        <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-400 animate-fade-in">
          {msg}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Enroll tokens */}
        <div className="card p-5 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))] flex items-center gap-2"><KeyRound size={14} /> One-time Enrollment Token</h3>
          <div className="flex gap-2">
            <input value={tokenLabel} onChange={e => setTokenLabel(e.target.value)} placeholder="Label (e.g. office-rollout)" className="input flex-1" />
            <select value={tokenAgent} onChange={e => setTokenAgent(e.target.value)} className="input">
              <option value="aegis-guard">Aegis-Guard</option>
              <option value="nodetrace">NodeTrace</option>
              <option value="unified">Unified (Guard + NodeTrace)</option>
            </select>
          </div>
          <button onClick={() => createTokenMut.mutate()} disabled={createTokenMut.isPending} className="btn btn-primary w-full">
            {createTokenMut.isPending ? 'Generating...' : 'Generate 15m Token'}
          </button>
          
          {lastToken && (
            <div className="space-y-3 text-xs bg-[hsl(var(--secondary))] p-3 rounded-lg border border-[hsl(var(--border))] animate-fade-in">
              <div className="font-mono text-emerald-400 break-all bg-[hsl(var(--background))] p-2 rounded border border-[hsl(var(--border))]">{lastToken.token}</div>
              <div>
                <p className="text-[hsl(var(--muted-foreground))] uppercase font-semibold mb-1 text-[10px]">Windows PowerShell</p>
                <code className="block rounded bg-[hsl(var(--background))] p-2 font-mono text-cyan-400 break-all border border-[hsl(var(--border))]">{lastToken.oneline_windows}</code>
                <button onClick={() => copyText(lastToken.oneline_windows, () => setCopied('win'))} className="mt-2 text-cyan-400 hover:text-white flex items-center gap-1 transition-colors"><ClipboardCopy size={12} /> {copied === 'win' ? 'Copied!' : 'Copy Command'}</button>
              </div>
              <div>
                <p className="text-[hsl(var(--muted-foreground))] uppercase font-semibold mb-1 text-[10px]">Linux Bash</p>
                <code className="block rounded bg-[hsl(var(--background))] p-2 font-mono text-cyan-400 break-all border border-[hsl(var(--border))]">{lastToken.oneline_linux}</code>
                <button onClick={() => copyText(lastToken.oneline_linux, () => setCopied('lin'))} className="mt-2 text-cyan-400 hover:text-white flex items-center gap-1 transition-colors"><ClipboardCopy size={12} /> {copied === 'lin' ? 'Copied!' : 'Copy Command'}</button>
              </div>
            </div>
          )}

          <div className="space-y-2 max-h-48 overflow-y-auto pt-2">
            {tokens.map((t: any) => (
              <div key={t.id} className="flex flex-col gap-1 rounded bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] px-3 py-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white">#{t.id} {t.label || '(no label)'}</span>
                  {!t.revoked && !t.used_at && (
                    <button onClick={() => revokeTokenMut.mutate(t.id)} className="text-red-400 hover:text-red-300 flex items-center gap-1 transition-colors"><Ban size={12} /> Revoke</button>
                  )}
                </div>
                <div className="flex items-center justify-between text-[10px] text-[hsl(var(--muted-foreground))]">
                  <span className="uppercase">{t.agent_type}</span>
                  <span className={cn('px-1.5 py-0.5 rounded font-bold uppercase', t.revoked ? 'bg-red-500/10 text-red-400' : t.used_at ? 'bg-blue-500/10 text-blue-400' : 'bg-emerald-500/10 text-emerald-400')}>
                    {t.revoked ? 'Revoked' : t.used_at ? 'Used' : 'Active'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Mass job */}
        <div className="card p-5 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))] flex items-center gap-2"><Play size={14} /> Mass Deploy Job</h3>
          <div className="flex gap-2">
            <select value={agentType} onChange={e => setAgentType(e.target.value)} className="input flex-1">
              <option value="nodetrace">NodeTrace (Telemetry)</option>
              <option value="aegis-guard">Aegis-Guard (EDR)</option>
              <option value="unified">Unified (Guard + NodeTrace)</option>
            </select>
            <select value={method} onChange={e => setMethod(e.target.value)} className="input">
              <option value="ssh" disabled>SSH (executor pending)</option>
              <option value="winrm" disabled>WinRM (executor pending)</option>
              <option value="interactive" disabled>Interactive (executor pending)</option>
              <option value="oneline">One-liner (Manual)</option>
            </select>
          </div>
          
          <textarea 
            value={ipText} 
            onChange={e => setIpText(e.target.value)} 
            rows={4} 
            placeholder={"192.168.1.20\n192.168.1.21"} 
            className="input font-mono text-sm resize-none" 
          />
          
          {(method === 'ssh' || method === 'winrm' || method === 'interactive') && (
            <div className="space-y-2 bg-[hsl(var(--secondary))] p-3 rounded-lg border border-[hsl(var(--border))]">
              <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" className="input bg-[hsl(var(--background))]" autoComplete="off" />
              <input value={password} onChange={e => setPassword(e.target.value)} type="password" placeholder="Password" className="input bg-[hsl(var(--background))]" autoComplete="new-password" />
              <p className="text-[10px] text-yellow-500 leading-tight">Credentials live only in worker memory and are wiped instantly. They are never saved to DB or logs.</p>
              {method === 'interactive' && (
                <p className="text-[10px] text-purple-400 leading-tight">Interactive mode will prompt the remote user to enter a PIN to approve the deployment.</p>
              )}
            </div>
          )}
          {method === 'oneline' && (
            <p className="text-[10px] text-cyan-400 leading-tight">Remote password execution is disabled. Generate a short-lived enrollment token above and run the signed installer on the target host.</p>
          )}
          
          <button onClick={handleCreateJob} disabled={createJobMut.isPending} className="btn btn-primary w-full bg-purple-600 hover:bg-purple-500 border-purple-500 text-white shadow-purple-500/20">
            {createJobMut.isPending ? 'Queuing...' : 'Start Rollout'}
          </button>
          
          <button onClick={() => setCurrentPage('discovery')} className="w-full text-xs text-[hsl(var(--muted-foreground))] hover:text-white transition-colors flex items-center justify-center gap-1">
            <Server size={12} /> Select hosts from Discovery instead
          </button>
        </div>

        {/* Artifacts */}
        <div className="card p-5 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))] flex items-center gap-2"><Package size={14} /> Artifacts & OTA</h3>
          <button onClick={() => qc.invalidateQueries({ queryKey: ['deploy-artifacts'] })} className="btn btn-ghost text-xs py-1.5 w-full">
            <RefreshCcw size={14} /> Refresh Artifacts
          </button>
          
          <div className="space-y-2 max-h-40 overflow-y-auto">
            {artifacts.length === 0 ? (
              <p className="text-xs text-[hsl(var(--muted-foreground))] p-2 text-center border border-dashed border-[hsl(var(--border))] rounded">No bundles in ARTIFACT_DIR.</p>
            ) : (
              artifacts.map((a: any) => (
                <div key={a.name} className="flex justify-between items-center rounded bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] px-3 py-2 text-xs font-mono">
                  <span className="text-white truncate" title={a.name}>{a.name}</span>
                  <span className="text-[hsl(var(--muted-foreground))] shrink-0 pl-2">{(a.size / 1024 / 1024).toFixed(1)} MB</span>
                </div>
              ))
            )}
          </div>
          
          <div className="border-t border-[hsl(var(--border))] pt-4 space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-[hsl(var(--muted-foreground))] mb-2">Signed OTA Update Push</p>
            <input value={otaAgent} onChange={e => setOtaAgent(e.target.value)} placeholder="Target Agent ID (UUID)" className="input font-mono text-xs" />
            <div className="flex gap-2">
              <input value={otaVersion} onChange={e => setOtaVersion(e.target.value)} placeholder="Version (e.g. latest)" className="input font-mono text-xs flex-1" />
              <button onClick={() => otaMut.mutate()} disabled={otaMut.isPending} className="btn btn-primary px-3 py-1.5 text-xs">Push</button>
            </div>
            
            {otaResult && (
              <div className="rounded bg-[hsl(var(--secondary))] p-2 border border-[hsl(var(--border))] font-mono text-[10px] text-[hsl(var(--muted-foreground))] break-all">
                <span className="text-emerald-400">sha256:</span> {otaResult.command?.sha256?.slice(0, 32)}…<br/>
                <span className="text-purple-400">sig:</span> {otaResult.command?.signature?.slice(0, 16)}…<br/>
                <span className="text-cyan-400">queued:</span> {String(otaResult.queued)}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Jobs Table */}
      <div className="card overflow-hidden">
        <div className="px-5 py-4 border-b border-[hsl(var(--border))] flex items-center justify-between">
          <h3 className="text-sm font-bold text-white flex items-center gap-2"><Clock size={16} className="text-cyan-400"/> Rollout Jobs</h3>
          <span className="text-[10px] uppercase font-bold text-[hsl(var(--muted-foreground))] bg-[hsl(var(--secondary))] px-2 py-1 rounded">Polling: 5s</span>
        </div>
        
        <table className="w-full text-left text-sm">
          <thead className="bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] text-xs uppercase tracking-wider">
            <tr>
              <th className="p-4 font-medium">Job ID</th>
              <th className="p-4 font-medium">Agent</th>
              <th className="p-4 font-medium">Status</th>
              <th className="p-4 font-medium">Target IPs</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[hsl(var(--border))]">
            {jobs.map((j: any) => (
              <tr key={j.id} className="hover:bg-[hsl(var(--secondary))/50] transition-colors align-top">
                <td className="p-4">
                  <div className="font-mono font-medium text-white">#{j.id}</div>
                  <div className="text-[10px] text-[hsl(var(--muted-foreground))] mt-1">{j.created_at?.slice(0, 19).replace('T', ' ')}</div>
                </td>
                <td className="p-4 text-xs">
                  <span className="font-semibold text-cyan-400">{j.agent_type}</span>
                  <span className="text-[hsl(var(--muted-foreground))] ml-1">· {j.agent_version}</span>
                </td>
                <td className="p-4 text-xs">
                  <span className={cn('px-2 py-1 rounded font-bold uppercase tracking-wider border', 
                    j.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                    j.status === 'failed' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                    j.status === 'running' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20 animate-pulse' :
                    'bg-slate-500/10 text-slate-400 border-slate-500/20'
                  )}>
                    {j.status}
                  </span>
                </td>
                <td className="p-4">
                  <div className="space-y-1.5 max-h-32 overflow-y-auto pr-2">
                    {Object.entries(j.results || {}).map(([ip, r]: [string, any]) => (
                      <div key={ip} className="flex items-center gap-2 text-xs font-mono bg-[hsl(var(--background))] p-1.5 rounded border border-[hsl(var(--border))]">
                        <StatusIcon s={r.status} />
                        <span className="font-mono">{ip}</span>
                        <div className="flex items-center gap-1">
                          <span className={cn('uppercase font-bold tracking-widest',
                            r.status === 'ok' ? 'text-emerald-400' : 
                            r.status === 'failed' ? 'text-red-400' :
                            r.status === 'waiting_approval' ? 'text-purple-400' :
                            'text-yellow-400'
                          )}>{r.status}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
            {jobs.length === 0 && (
              <tr><td colSpan={4} className="p-8 text-center text-[hsl(var(--muted-foreground))] italic">No deployment jobs found.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
