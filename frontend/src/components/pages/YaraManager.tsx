import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Binary, Plus, Trash2, Loader2, Eye, EyeOff, FolderSearch, Server, Rss, RefreshCw, ShieldCheck, AlertTriangle } from 'lucide-react'
import { yaraAPI, fimAPI, statsAPI } from '@/services/api'
import { useAppStore } from '@/store/appStore'
import { PermissionGate } from '@/components/common/PermissionGate'
import { cn, asArray } from '@/lib/utils'

interface YaraRule {
  id: number
  name: string
  content: string
  is_active: boolean
  severity?: string
  source?: string
  source_version?: string | null
  managed?: boolean
  tags?: string[]
  created_at?: string | null
}

interface FeedSource {
  url: string
  configured: boolean
  feed_id?: string | null
  last_success_at?: string | null
  last_checked_at?: string | null
  last_error?: string | null
  bundle_version?: string | null
  rules_count?: number
}

export default function YaraManager() {
  const qc = useQueryClient()
  const user = useAppStore((s) => s.user)

  // ── rules ───────────────────────────────────────────────────────────
  const { data: rules = [], isLoading: rulesLoading } = useQuery({
    queryKey: ['yara-rules'],
    queryFn: () => yaraAPI.list().then(r => (r.data?.items ?? []) as YaraRule[]),
    refetchInterval: 30000,
  })

  const [newName, setNewName] = useState('')
  const [newContent, setNewContent] = useState(
    'rule Example_Suspicious_String\n{\n  strings:\n    $s = "aegis-demo" nocase\n  condition:\n    $s\n}'
  )
  const [newSeverity, setNewSeverity] = useState('high')

  const createMut = useMutation({
    mutationFn: () => yaraAPI.create({
      name: newName, content: newContent, is_active: true, severity: newSeverity,
    }),
    onSuccess: () => { setNewName(''); qc.invalidateQueries({ queryKey: ['yara-rules'] }) },
  })
  const toggleMut = useMutation({
    mutationFn: (r: YaraRule) => yaraAPI.update(r.id, { is_active: !r.is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yara-rules'] }),
  })
  const deleteMut = useMutation({
    mutationFn: (id: number) => yaraAPI.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yara-rules'] }),
  })

  // ── signed feeds ─────────────────────────────────────────────────────
  const { data: feedStatus, isLoading: feedsLoading } = useQuery({
    queryKey: ['yara-feeds'],
    queryFn: () => yaraAPI.feedStatus().then(r => r.data),
    refetchInterval: 60000,
  })
  const [feedMsg, setFeedMsg] = useState('')
  const syncFeedsMut = useMutation({
    mutationFn: () => yaraAPI.syncFeeds(),
    onSuccess: (r) => {
      const result = r.data || {}
      const ok = (result.results || []).filter((x: any) => x.ok).length
      const total = (result.results || []).length
      setFeedMsg(result.ok ? `Sync complete: ${ok}/${total} feed(s) updated.` : (result.note || result.skipped || `Sync incomplete: ${ok}/${total} feed(s) updated.`))
      qc.invalidateQueries({ queryKey: ['yara-rules'] })
      qc.invalidateQueries({ queryKey: ['yara-feeds'] })
    },
    onError: (e: any) => setFeedMsg(e?.response?.data?.detail || 'Feed sync failed.'),
  })
  const canManage = (user?.role || '').toLowerCase() === 'admin'

  // ── endpoints (for the watchlist) ───────────────────────────────────
  // `asArray` and not `as any[]`: on the first render (and on any failed
  // request) `agentsData` is undefined, and `undefined.filter(...)` crashed
  // the whole page — that was the "YARA & FIM never loads" bug.
  const { data: agentsData, isLoading: agentsLoading, isError: agentsError } = useQuery({
    queryKey: ['agents'],
    queryFn: () => statsAPI.getAgents().then(r => asArray(r.data)),
    refetchInterval: 30000,
  })
  const agents = asArray<any>(agentsData)
  const realAgents = agents.filter(a => !a.is_demo)
  // A watchlist can only be applied to an endpoint that declares the FIM
  // capability: without this the dropdown mixes in stale/soak-test enrollments
  // that will never answer the command. Agents enrolled before capabilities
  // were reported don't declare one, so if nobody does we keep the full list
  // instead of hiding every endpoint.
  const capableAgents = realAgents.filter(a => a?.capabilities?.fim === true)
  const selectableAgents = capableAgents.length > 0 ? capableAgents : realAgents
  const [selectedAgent, setSelectedAgent] = useState('')

  // ── watchlist ───────────────────────────────────────────────────────
  const { data: watchlist } = useQuery({
    queryKey: ['fim-watchlist', selectedAgent],
    queryFn: () => fimAPI.get(selectedAgent).then(r => r.data),
    enabled: !!selectedAgent,
  })
  const [pathsText, setPathsText] = useState('')
  const [recursive, setRecursive] = useState(true)
  const [fimMsg, setFimMsg] = useState('')
  useEffect(() => {
    if (watchlist) {
      setPathsText((watchlist.paths || []).join('\n'))
      setRecursive(watchlist.recursive !== false)
    }
  }, [watchlist])

  const watchMut = useMutation({
    mutationFn: () => fimAPI.set(selectedAgent, pathsText.split('\n').map(s => s.trim()).filter(Boolean), recursive),
    onSuccess: (r) => setFimMsg(`Saved (${r.data?.count ?? 0} paths) — command ${r.data?.command_queued ? 'delivered to the agent' : 'queued until the agent restarts'}.`),
    onError: (e: any) => setFimMsg(e?.response?.data?.detail || 'Save failed.'),
  })

  return (
    <div className="space-y-6 animate-slide-in">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
          <Binary size={20} className="text-cyan-400" /> YARA &amp; FIM
        </h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">
          YARA signatures for on-demand scans, and per-endpoint File Integrity Monitoring watchlists.
        </p>
      </div>

      {/* ── signed feeds ───────────────────────────────────────────── */}
      <div className="card p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="font-bold flex items-center gap-2 text-white">
              <Rss size={16} className="text-cyan-400" /> Signed signature feeds
              {feedStatus?.enabled ? (
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">AUTO</span>
              ) : (
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-500/10 text-slate-400 border border-slate-500/20">OFF</span>
              )}
            </h3>
            <p className="text-xs text-[hsl(var(--muted-foreground))] mt-1 max-w-3xl">
              Ed25519-signed bundles only. A bad signature or a rule-name collision rejects the whole bundle; previously imported rules stay active.
            </p>
          </div>
          {canManage && (
            <button
              onClick={() => syncFeedsMut.mutate()}
              disabled={!feedStatus?.enabled || syncFeedsMut.isPending}
              className="btn btn-primary bg-cyan-600 hover:bg-cyan-500 border-cyan-500 disabled:opacity-40"
            >
              {syncFeedsMut.isPending ? <Loader2 size={15} className="animate-spin" /> : <RefreshCw size={15} />}
              Sync now
            </button>
          )}
        </div>

        {feedsLoading ? (
          <div className="flex justify-center py-4"><Loader2 className="animate-spin" size={18} /></div>
        ) : (
          <div className="mt-3 space-y-2">
            {(feedStatus?.sources || []).length === 0 ? (
              <p className="text-xs text-[hsl(var(--muted-foreground))] italic">No feed configured. Set YARA_FEED_URLS and YARA_FEED_PUBLIC_KEY_B64 on the Brain.</p>
            ) : (feedStatus?.sources || []).map((s: FeedSource) => (
              <div key={s.url} className="flex flex-wrap items-center gap-2 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] px-3 py-2 text-xs">
                {s.last_error ? <AlertTriangle size={14} className="text-red-400 shrink-0" /> : <ShieldCheck size={14} className="text-emerald-400 shrink-0" />}
                <span className="font-mono text-white truncate max-w-[420px]" title={s.url}>{s.url}</span>
                {s.feed_id && <span className="text-[hsl(var(--muted-foreground))]">feed:{s.feed_id}</span>}
                <span className="text-[hsl(var(--muted-foreground))]">v{s.bundle_version || '—'} · {s.rules_count ?? 0} rules</span>
                {!s.configured && <span className="text-orange-400">not configured</span>}
                {s.last_error && <span className="text-red-400 truncate max-w-[420px]" title={s.last_error}>{s.last_error}</span>}
                {!s.last_error && s.last_success_at && <span className="text-emerald-400/80">last sync {new Date(s.last_success_at).toLocaleString()}</span>}
              </div>
            ))}
            {feedMsg && <p className="text-xs text-cyan-300">{feedMsg}</p>}
            {!feedStatus?.enabled && (
              <p className="text-[10px] text-[hsl(var(--muted-foreground))]">
                Disabled by configuration. The Brain never imports unsigned rules; the public key and feed URL are deployment decisions.
              </p>
            )}
          </div>
        )}
      </div>

      {/* ── YARA rules ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="card p-5">
          <h3 className="font-bold mb-4 flex items-center gap-2 text-white"><Binary size={16} className="text-cyan-400" /> Rules ({rules.length})</h3>
          {rulesLoading ? (
            <div className="flex justify-center py-8"><Loader2 className="animate-spin" size={20} /></div>
          ) : rules.length === 0 ? (
            <p className="text-sm text-[hsl(var(--muted-foreground))] py-6 text-center">No rules yet — create one on the right.</p>
          ) : (
            <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
              {rules.map((r) => (
                <div key={r.id} className="flex items-center gap-2 rounded bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] px-3 py-2">
                  <span className={cn('text-xs font-semibold flex-1 truncate', r.is_active ? 'text-white' : 'text-[hsl(var(--muted-foreground))]')}>{r.name}</span>
                  <span className={cn('text-[9px] uppercase font-bold px-1.5 py-0.5 rounded border', r.severity === 'critical' ? 'text-red-300 border-red-500/30 bg-red-500/10' : r.severity === 'high' ? 'text-orange-300 border-orange-500/30 bg-orange-500/10' : 'text-slate-300 border-slate-500/30 bg-slate-500/10')}>{r.severity || 'high'}</span>
                  {r.managed && <span className="text-[9px] uppercase font-bold text-cyan-400 border border-cyan-500/20 bg-cyan-500/10 px-1.5 py-0.5 rounded" title={r.source || 'feed'}>feed</span>}
                  <PermissionGate perms={['rules']}>
                    <button onClick={() => toggleMut.mutate(r)} title={r.is_active ? 'Disable' : 'Enable'}
                      className={cn('p-1.5 rounded', r.is_active ? 'text-emerald-400' : 'text-[hsl(var(--muted-foreground))]')}>
                      {r.is_active ? <Eye size={14} /> : <EyeOff size={14} />}
                    </button>
                    <button onClick={() => { if (confirm(`Delete rule ${r.name}?`)) deleteMut.mutate(r.id) }}
                      className="p-1.5 rounded text-[hsl(var(--muted-foreground))] hover:text-red-400">
                      <Trash2 size={14} />
                    </button>
                  </PermissionGate>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card p-5">
          <h3 className="font-bold mb-4 flex items-center gap-2 text-white"><Plus size={16} className="text-emerald-400" /> New rule</h3>
          <PermissionGate perms={['rules']}>
            <input className="input mb-2" placeholder="Rule name (e.g. Maze_Ransomware_Note)" value={newName} onChange={e => setNewName(e.target.value)} />
            <select className="input mb-2" value={newSeverity} onChange={e => setNewSeverity(e.target.value)}>
              <option value="low">Low — context only (10)</option>
              <option value="medium">Medium — suspicious (25)</option>
              <option value="high">High — significant (40)</option>
              <option value="critical">Critical — direct evidence (60)</option>
            </select>
            <textarea className="input h-[220px] font-mono text-[11px] text-emerald-400 resize-none bg-[hsl(var(--background))]" value={newContent} onChange={e => setNewContent(e.target.value)} />
            <button onClick={() => createMut.mutate()} disabled={!newName || createMut.isPending}
              className="btn btn-primary w-full mt-3 bg-cyan-600 hover:bg-cyan-500 border-cyan-500">
              {createMut.isPending ? <Loader2 size={16} className="animate-spin" /> : 'Save rule'}
            </button>
          </PermissionGate>
        </div>
      </div>

      {/* ── FIM watchlist ───────────────────────────────────────────── */}
      <div className="card p-5">
        <h3 className="font-bold mb-4 flex items-center gap-2 text-white">
          <FolderSearch size={16} className="text-orange-400" /> File Integrity Monitoring — per-endpoint watchlist
        </h3>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div className="space-y-3">
            <div>
              <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Endpoint</label>
              <div className="flex items-center gap-2 mt-1">
                <Server size={14} className="text-[hsl(var(--muted-foreground))]" />
                <select className="input" value={selectedAgent} onChange={e => setSelectedAgent(e.target.value)}
                  disabled={agentsLoading}>
                  <option value="">
                    {agentsLoading ? 'Loading endpoints…' : agentsError ? 'Endpoints unavailable' : selectableAgents.length === 0 ? 'No endpoints enrolled' : 'Select an endpoint…'}
                  </option>
                  {selectableAgents.map((a: any) => (
                    <option key={a.agent_id} value={a.agent_id}>{a.hostname || a.agent_id?.slice(0, 8)}</option>
                  ))}
                </select>
              </div>
            </div>
            <PermissionGate perms={['manage']}>
              <div className="flex items-center gap-2 text-sm text-[hsl(var(--muted-foreground))]">
                <input type="checkbox" checked={recursive} onChange={e => setRecursive(e.target.checked)} className="accent-orange-500" />
                Monitor subfolders recursively
              </div>
              <button onClick={() => watchMut.mutate()} disabled={!selectedAgent || watchMut.isPending}
                className="btn btn-primary w-full bg-orange-600 hover:bg-orange-500 border-orange-500">
                {watchMut.isPending ? <Loader2 size={16} className="animate-spin" /> : 'Apply watchlist'}
              </button>
            </PermissionGate>
            {fimMsg && <p className="text-xs text-cyan-300">{fimMsg}</p>}
            <p className="text-[10px] text-[hsl(var(--muted-foreground))]">
              Every change to a monitored file produces a FIM event: an alert with MITRE mapping (persistence T1543/T1547)
              plus a searchable entry in Log Search. The agent computes the SHA-256 hash for files up to 8 MB.
            </p>
          </div>
          <div className="space-y-2">
            <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">
              Paths to monitor (one per line)
            </label>
            <textarea className="input h-[190px] font-mono text-[11px] resize-none bg-[hsl(var(--background))]"
              placeholder={'C:\\Windows\\System32\\drivers\\etc\\hosts\nC:\\Windows\\System32\\Tasks\n/etc/cron.d'}
              value={pathsText} onChange={e => setPathsText(e.target.value)} disabled={!selectedAgent} />
            <div className="flex flex-wrap gap-1.5">
              {(watchlist?.suggested || []).map((s: string) => (
                <button key={s} onClick={() => setPathsText(t => (t ? t + '\n' : '') + s)}
                  className="px-2 py-0.5 rounded border border-[hsl(var(--border))] text-[10px] text-[hsl(var(--muted-foreground))] hover:text-white hover:border-white/30 transition-colors truncate max-w-[220px]"
                  title={s}>
                  + {s}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
