import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Monitor, Shield, Search, RefreshCw, Ban, CheckCircle2, AlertTriangle, Server } from 'lucide-react'
import { statsAPI, fleetAPI, pkiAPI } from '@/services/api'
import { cn, timeAgo, asArray } from '@/lib/utils'

const STATUS_STYLE: Record<string, string> = {
  online: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  stale: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  offline: 'bg-red-500/10 text-red-400 border-red-500/20',
  unknown: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
}

export default function AgentsList() {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [siteFilter, setSiteFilter] = useState('')
  const [msg, setMsg] = useState('')

  const { data: agents = [], isLoading, refetch } = useQuery({
    queryKey: ['agents', siteFilter],
    queryFn: () => statsAPI.getAgents(siteFilter ? { site: siteFilter } : {}).then(r => asArray(r.data)),
    refetchInterval: 15000,
  })

  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: () => statsAPI.getStats().then(r => r.data),
    refetchInterval: 15000,
  })

  const isolateMut = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => statsAPI.isolateAgent(id, reason),
    onSuccess: () => { setMsg('Isolate queued.'); qc.invalidateQueries({ queryKey: ['agents'] }) },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Isolate failed.'),
  })

  const releaseMut = useMutation({
    mutationFn: (id: string) => statsAPI.releaseAgent(id),
    onSuccess: () => { setMsg('Release queued.'); qc.invalidateQueries({ queryKey: ['agents'] }) },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Release failed.'),
  })

  const siteMut = useMutation({
    mutationFn: ({ id, site }: { id: string; site: string }) => fleetAPI.assignSite(id, site),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['agents'] }); setMsg('Site updated.') },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Site update failed.'),
  })

  const revokeMut = useMutation({
    mutationFn: (id: string) => pkiAPI.revokeAgent(id, 'fleet-revoke'),
    onSuccess: () => { setMsg('Certificate revoked.'); qc.invalidateQueries({ queryKey: ['agents'] }) },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Revoke failed.'),
  })

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return (agents as any[]).filter(a => {
      if (siteFilter && (a.site || 'default') !== siteFilter) return false
      if (!q) return true
      return [a.hostname, a.agent_id, a.os_type, a.agent_version, a.site].some(v => String(v || '').toLowerCase().includes(q))
    })
  }, [agents, search, siteFilter])

  const sites = useMemo(() => {
    const s = new Set((agents as any[]).map(a => a.site || 'default'))
    return Array.from(s).sort()
  }, [agents])

  const degraded = (agents as any[]).filter(a => a.status === 'stale' || a.status === 'offline' || a.quality?.startsWith('degraded')).length

  return (
    <div className="space-y-5 animate-slide-in">
      <div className="flex flex-col md:flex-row justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Monitor className="text-cyan-400" /> Fleet</h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">Hostname · OS · version · mTLS · last activity · coverage · actions</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-[hsl(var(--muted-foreground))]">{filtered.length} agents · {degraded} degraded</span>
          <button onClick={() => refetch()} className="btn btn-ghost"><RefreshCw size={14} /> Refresh</button>
        </div>
      </div>

      {msg && <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-4 py-2 text-sm text-cyan-400">{msg}</div>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="card p-4"><p className="text-xs text-[hsl(var(--muted-foreground))]">Active</p><p className="text-2xl font-bold text-white">{stats?.active_agents ?? 0}</p></div>
        <div className="card p-4"><p className="text-xs text-[hsl(var(--muted-foreground))]">Stale</p><p className="text-2xl font-bold text-yellow-400">{stats?.stale_agents ?? 0}</p></div>
        <div className="card p-4"><p className="text-xs text-[hsl(var(--muted-foreground))]">Offline</p><p className="text-2xl font-bold text-red-400">{stats?.offline_agents ?? 0}</p></div>
        <div className="card p-4"><p className="text-xs text-[hsl(var(--muted-foreground))]">Isolated</p><p className="text-2xl font-bold text-orange-400">{stats?.isolated_agents ?? 0}</p></div>
      </div>

      <div className="card p-3 flex flex-wrap gap-2 items-center">
        <div className="relative flex-1 min-w-48">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
          <input className="input pl-9" placeholder="Search hostname, OS, version, site…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <select value={siteFilter} onChange={e => setSiteFilter(e.target.value)} className="input min-w-32">
          <option value="">All sites</option>
          {sites.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="text-xs text-[hsl(var(--muted-foreground))] flex items-center gap-1"><Server size={12} /> {sites.length} sites</span>
      </div>

      <div className="card overflow-hidden">
        {isLoading ? <div className="p-8 text-center text-[hsl(var(--muted-foreground))]">Loading fleet…</div> : filtered.length === 0 ? (
          <div className="p-10 text-center text-[hsl(var(--muted-foreground))]"><Shield size={28} className="mx-auto mb-2 opacity-30" />No agents match.</div>
        ) : (
          <div className="divide-y divide-[hsl(var(--border))]">
            {filtered.map((a: any) => (
              <div key={a.agent_id} className="flex flex-wrap items-center gap-3 px-4 py-3 hover:bg-[hsl(var(--secondary))] transition-colors">
                <span className={cn('badge border text-[10px] uppercase font-bold', STATUS_STYLE[a.status] || STATUS_STYLE.unknown)}>{a.status || 'unknown'}</span>
                <div className="flex-1 min-w-[160px]">
                  <p className="text-sm font-semibold text-white truncate">{a.hostname || a.agent_id.slice(0, 8)}</p>
                  <p className="text-xs text-[hsl(var(--muted-foreground))]">{a.os_type || 'unknown'} · {a.agent_version || '—'} · site:{a.site || 'default'}</p>
                </div>
                <div className="text-xs text-[hsl(var(--muted-foreground))] min-w-[120px]">
                  <p>last: {timeAgo(a.last_seen)}</p>
                  <p className="font-mono text-[10px]">{a.agent_id.slice(0, 8)}… · {a.isolated ? 'isolated' : 'ok'}</p>
                </div>
                <div className="flex flex-wrap gap-1 shrink-0">
                  {a.site !== 'hq' && <button onClick={() => siteMut.mutate({ id: a.agent_id, site: 'hq' })} className="btn btn-ghost text-xs py-1 px-2">→ hq</button>}
                  {a.isolated ? (
                    <button onClick={() => releaseMut.mutate(a.agent_id)} className="btn btn-ghost text-xs py-1 px-2 text-emerald-400"><CheckCircle2 size={12} /> Release</button>
                  ) : (
                    <button onClick={() => { const r = prompt('Reason for isolate?') || 'SOC contain'; isolateMut.mutate({ id: a.agent_id, reason: r }) }} className="btn btn-ghost text-xs py-1 px-2 text-orange-400"><Ban size={12} /> Isolate</button>
                  )}
                  <button onClick={() => { if (confirm(`Revoke cert for ${a.hostname}?`)) revokeMut.mutate(a.agent_id) }} className="btn btn-ghost text-xs py-1 px-2 text-red-400" title="Revoke mTLS cert"><AlertTriangle size={12} /> Revoke</button>
                </div>
                <div className="w-full text-[10px] text-[hsl(var(--muted-foreground))]">coverage: {a.capabilities?.sensor_mode || a.provenance || '—'} {a.quality ? `· ${a.quality}` : ''} · cert: {a.capabilities?.device_cert_sha256 ? 'bound' : 'none'}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
