import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Globe, Search, History, ShieldAlert, Zap, MapPin, AlertCircle } from 'lucide-react'
import { osintAPI } from '@/services/api'

export default function SentinelX() {
  const qc = useQueryClient()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState<'ip' | 'domain'>('ip')
  const [result, setResult] = useState<any>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  const { data: history = [] } = useQuery({
    queryKey: ['osint-history'],
    queryFn: () => osintAPI.getHistory({ limit: 10 }).then(r => r.data.items || []),
  })

  const scanMut = useMutation({
    mutationFn: (args: { target: string, type: 'ip'|'domain' }) => {
      const forceScan = true
      return args.type === 'ip' ? osintAPI.ipLookup(args.target, forceScan) : osintAPI.domainLookup(args.target, forceScan)
    },
    onSuccess: (res) => {
      setResult(res.data.data)
      setErrorMsg(null)
      qc.invalidateQueries({ queryKey: ['osint-history'] })
    },
    onError: (err: any) => {
      setResult(null)
      const status = err?.response?.status
      if (status === 401) setErrorMsg('Authentication required to start live OSINT scans. Please log in.')
      else if (status === 403) setErrorMsg('Insufficient role to trigger live OSINT scans.')
      else if (status === 503) setErrorMsg(err?.response?.data?.detail || 'OSINT provider not configured. Check server .env for API keys.')
      else setErrorMsg(err?.response?.data?.detail || 'Scan failed. Check backend logs.')
    }
  })

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim() || scanMut.isPending) return
    scanMut.mutate({ target, type: scanType })
  }

  return (
    <div className="space-y-8 animate-slide-in">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
          <Globe className="text-purple-400" /> SentinelX Intelligence
        </h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">Cross-reference indicators with global OSINT providers</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        {/* Search Panel */}
        <div className="xl:col-span-1 space-y-6">
          <div className="card p-5">
            <h3 className="text-xs font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest mb-4">New Investigation</h3>
            <form onSubmit={handleScan} className="space-y-4">
              <div className="flex bg-[hsl(var(--secondary))] p-1 rounded-lg border border-[hsl(var(--border))]">
                <button
                  type="button"
                  onClick={() => setScanType('ip')}
                  className={`flex-1 py-1.5 text-xs font-bold rounded-md transition-all ${scanType === 'ip' ? 'bg-[hsl(var(--card))] text-white shadow' : 'text-[hsl(var(--muted-foreground))] hover:text-white'}`}
                >IP</button>
                <button
                  type="button"
                  onClick={() => setScanType('domain')}
                  className={`flex-1 py-1.5 text-xs font-bold rounded-md transition-all ${scanType === 'domain' ? 'bg-[hsl(var(--card))] text-white shadow' : 'text-[hsl(var(--muted-foreground))] hover:text-white'}`}
                >DOMAIN</button>
              </div>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" size={14}/>
                <input
                  type="text"
                  placeholder={scanType === 'ip' ? '8.8.8.8' : 'example.com'}
                  className="input pl-9"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  required
                />
              </div>
              <button
                type="submit"
                disabled={scanMut.isPending}
                className="btn btn-primary w-full bg-purple-600 hover:bg-purple-500 border-purple-500 shadow-purple-500/20 py-2.5 justify-center text-white font-bold"
              >
                {scanMut.isPending ? (
                  <span className="flex items-center gap-2">
                    <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.4 0 0 5.4 0 12h4z" />
                    </svg>
                    Querying...
                  </span>
                ) : (
                  <span className="flex items-center gap-2"><Zap size={16}/> Start Scan</span>
                )}
              </button>
            </form>
          </div>

          <div className="card p-5">
            <h3 className="text-xs font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest mb-4 flex items-center gap-2">
              <History size={14}/> Recent Queries
            </h3>
            <div className="space-y-2">
              {history.map((h: any, i: number) => (
                <div key={i} className="flex items-center justify-between p-2 rounded-lg hover:bg-[hsl(var(--secondary))] transition-colors cursor-pointer border border-transparent hover:border-[hsl(var(--border))]" onClick={() => { setTarget(h.query); setScanType(h.source as 'ip'|'domain'); }}>
                  <span className="text-xs font-mono text-white truncate pr-2">{h.query}</span>
                  <span className="text-[9px] bg-[hsl(var(--background))] border border-[hsl(var(--border))] px-1.5 py-0.5 rounded text-[hsl(var(--muted-foreground))] uppercase font-bold shrink-0">{h.source}</span>
                </div>
              ))}
              {history.length === 0 && <p className="text-xs text-[hsl(var(--muted-foreground))] italic">No recent history.</p>}
            </div>
          </div>
        </div>

        {/* Results Panel */}
        <div className="xl:col-span-3">
          {!result && !scanMut.isPending ? (
            <div className="h-full min-h-[400px] border-2 border-dashed border-[hsl(var(--border))] rounded-xl flex flex-col items-center justify-center text-[hsl(var(--muted-foreground))] bg-[hsl(var(--secondary)/0.3)]">
              <Globe size={48} className="mb-4 opacity-20"/>
              {errorMsg ? (
                <div className="flex items-center gap-2 text-red-400 bg-red-500/10 px-4 py-2 rounded-lg border border-red-500/20"><AlertCircle size={16}/> {errorMsg}</div>
              ) : (
                <p>No active investigation. Enter an indicator to begin.</p>
              )}
            </div>
          ) : scanMut.isPending ? (
            <div className="h-full min-h-[400px] bg-[hsl(var(--secondary)/0.3)] border border-[hsl(var(--border))] rounded-xl flex flex-col items-center justify-center">
              <div className="relative">
                <div className="w-16 h-16 border-4 border-purple-500/20 border-t-purple-500 rounded-full animate-spin"/>
                <Globe className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-purple-400 animate-pulse" size={24}/>
              </div>
              <p className="mt-4 text-[hsl(var(--muted-foreground))] animate-pulse font-mono text-sm tracking-tighter">Querying Global OSINT Mesh...</p>
            </div>
          ) : (
            <div className="animate-fade-in space-y-6">
              {errorMsg && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-lg flex items-start gap-3">
                  <AlertCircle size={16} className="shrink-0 mt-0.5" />
                  <span className="text-sm font-medium">{errorMsg}</span>
                </div>
              )}
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* AbuseIPDB Card */}
                <div className="card p-6">
                  <div className="flex justify-between items-center mb-6">
                    <h4 className="font-bold text-orange-400 flex items-center gap-2 uppercase text-xs tracking-widest">
                      <ShieldAlert size={16}/> AbuseIPDB Reputation
                    </h4>
                    <span className="text-[10px] uppercase font-bold text-[hsl(var(--muted-foreground))] bg-[hsl(var(--secondary))] px-2 py-1 rounded">
                      Conf: {result.sources?.abuseipdb?.abuseConfidenceScore ?? '—'}%
                    </span>
                  </div>
                  <div className="text-center py-6">
                    <div className="text-6xl font-black text-white mb-2">
                      {result.sources?.abuseipdb?.abuseConfidenceScore || 0}<span className="text-2xl text-[hsl(var(--muted-foreground))]">%</span>
                    </div>
                    <p className="text-[10px] text-[hsl(var(--muted-foreground))] uppercase font-bold tracking-[0.2em]">Malicious Confidence Score</p>
                  </div>
                  <div className="grid grid-cols-2 gap-4 mt-6 pt-4 border-t border-[hsl(var(--border))]">
                    <div className="bg-[hsl(var(--secondary))] p-3 rounded-lg border border-[hsl(var(--border))]">
                      <div className="text-[9px] font-bold text-[hsl(var(--muted-foreground))] uppercase mb-1">Country</div>
                      <div className="text-sm font-bold text-white flex items-center gap-1.5"><MapPin size={12}/> {result.sources?.shodan?.country || 'N/A'}</div>
                    </div>
                    <div className="bg-[hsl(var(--secondary))] p-3 rounded-lg border border-[hsl(var(--border))]">
                      <div className="text-[9px] font-bold text-[hsl(var(--muted-foreground))] uppercase mb-1">Total Reports</div>
                      <div className="text-sm font-bold text-white">{result.sources?.abuseipdb?.totalReports || 0}</div>
                    </div>
                  </div>
                </div>

                {/* Shodan Card */}
                <div className="card p-6">
                  <div className="flex justify-between items-center mb-6">
                    <h4 className="font-bold text-cyan-400 flex items-center gap-2 uppercase text-xs tracking-widest">
                      <Globe size={16}/> Shodan Intelligence
                    </h4>
                    <span className="text-[10px] uppercase font-bold text-[hsl(var(--muted-foreground))] bg-[hsl(var(--secondary))] px-2 py-1 rounded">Indexed via API</span>
                  </div>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center bg-[hsl(var(--secondary))] p-3 rounded-lg border border-[hsl(var(--border))]">
                      <span className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase">ISP / Org</span>
                      <span className="text-sm font-bold text-white">{result.sources?.shodan?.isp || 'Unknown'}</span>
                    </div>
                    <div className="flex justify-between items-center bg-[hsl(var(--secondary))] p-3 rounded-lg border border-[hsl(var(--border))]">
                      <span className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase">OS</span>
                      <span className="text-sm font-bold text-white">{result.sources?.shodan?.os || 'Unknown'}</span>
                    </div>
                    <div className="flex justify-between items-center bg-[hsl(var(--secondary))] p-3 rounded-lg border border-[hsl(var(--border))]">
                      <span className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase shrink-0">Open Ports</span>
                      <div className="flex gap-1 flex-wrap justify-end pl-4">
                        {(result.sources?.shodan?.ports || []).map((p: any) => (
                          <span key={p} className="px-2 py-0.5 bg-cyan-500/10 text-cyan-400 rounded text-[10px] font-mono font-bold border border-cyan-500/20">{p}</span>
                        ))}
                        {!(result.sources?.shodan?.ports?.length) && <span className="text-xs text-[hsl(var(--muted-foreground))] italic">None detected</span>}
                      </div>
                    </div>
                  </div>
                </div>

                {/* VirusTotal Card */}
                <div className="md:col-span-2 card p-6">
                  <div className="flex justify-between items-center mb-6">
                    <h4 className="font-bold text-emerald-400 flex items-center gap-2 uppercase text-xs tracking-widest">
                      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg> VirusTotal Analysis
                    </h4>
                    <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded ${result.sources?.virustotal?.malicious ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))]'}`}>
                      {result.sources?.virustotal ? 'Scanned' : 'No API key'}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="text-center p-4 rounded-xl bg-red-500/5 border border-red-500/20">
                      <div className="text-3xl font-black text-red-400 mb-1">{result.sources?.virustotal?.malicious || 0}</div>
                      <div className="text-[10px] font-bold text-red-400/80 uppercase tracking-widest">Malicious</div>
                    </div>
                    <div className="text-center p-4 rounded-xl bg-orange-500/5 border border-orange-500/20">
                      <div className="text-3xl font-black text-orange-400 mb-1">{result.sources?.virustotal?.suspicious || 0}</div>
                      <div className="text-[10px] font-bold text-orange-400/80 uppercase tracking-widest">Suspicious</div>
                    </div>
                    <div className="text-center p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20">
                      <div className="text-3xl font-black text-emerald-400 mb-1">{result.sources?.virustotal?.harmless || 0}</div>
                      <div className="text-[10px] font-bold text-emerald-400/80 uppercase tracking-widest">Harmless</div>
                    </div>
                    <div className="text-center p-4 rounded-xl bg-[hsl(var(--secondary))] border border-[hsl(var(--border))]">
                      <div className="text-3xl font-black text-white mb-1">{result.sources?.virustotal?.undetected || 0}</div>
                      <div className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Undetected</div>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 pt-4 border-t border-[hsl(var(--border))]">
                    {result.sources?.virustotal?.reputation !== undefined && (
                      <div className="flex justify-between items-center bg-[hsl(var(--secondary))] p-3 rounded-lg border border-[hsl(var(--border))]">
                        <span className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase">Reputation</span>
                        <span className={`text-sm font-bold ${result.sources.virustotal.reputation >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                          {result.sources.virustotal.reputation}
                        </span>
                      </div>
                    )}
                    {result.sources?.virustotal?.as_owner && (
                      <div className="flex justify-between items-center bg-[hsl(var(--secondary))] p-3 rounded-lg border border-[hsl(var(--border))]">
                        <span className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase">AS Owner</span>
                        <span className="text-sm font-bold text-white truncate ml-4" title={result.sources.virustotal.as_owner}>{result.sources.virustotal.as_owner}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
