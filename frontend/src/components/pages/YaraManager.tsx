import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Binary, Plus, Trash2, Loader2, Eye, EyeOff, FolderSearch, Server } from 'lucide-react'
import { yaraAPI, fimAPI, statsAPI } from '@/services/api'
import { useAppStore } from '@/store/appStore'
import { PermissionGate } from '@/components/common/PermissionGate'
import { cn, asArray } from '@/lib/utils'

interface YaraRule {
  id: number
  name: string
  content: string
  is_active: boolean
  created_at?: string | null
}

export default function YaraManager() {
  const qc = useQueryClient()
  const user = useAppStore((s) => s.user)
  const canEdit = ['analyst', 'admin'].includes((user?.role || '').toLowerCase())

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

  const createMut = useMutation({
    mutationFn: () => yaraAPI.create({ name: newName, content: newContent, is_active: true }),
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
