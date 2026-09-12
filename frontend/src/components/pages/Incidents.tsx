import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Siren, UserCheck, RefreshCcw, Plus, ChevronDown, ChevronRight, CheckCircle2, ShieldAlert } from 'lucide-react'
import { incidentsAPI } from '@/services/api'
import { cn } from '@/lib/utils'

const STATUS_COLOR: Record<string, string> = {
  open: 'bg-red-500/10 text-red-400 border-red-500/20',
  investigating: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  contained: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  resolved: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  closed: 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]',
}

export default function Incidents() {
  const qc = useQueryClient()
  
  const [filter, setFilter] = useState('')
  const [openId, setOpenId] = useState<number | null>(null)
  const [msg, setMsg] = useState('')
  const [title, setTitle] = useState('')
  const [alertIds, setAlertIds] = useState('')

  const { data: items = [], isLoading } = useQuery({
    queryKey: ['incidents', filter],
    queryFn: () => incidentsAPI.list(filter ? { status: filter } : {}).then(r => r.data.items || []),
  })

  const createMut = useMutation({
    mutationFn: (payload: any) => incidentsAPI.create(payload),
    onSuccess: (_, variables) => {
      setTitle('')
      setAlertIds('')
      setMsg(`Incident created (${variables.alert_ids.length} alerts).`)
      qc.invalidateQueries({ queryKey: ['incidents'] })
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Create failed.')
  })

  const updateStatusMut = useMutation({
    mutationFn: ({ id, status }: { id: number, status: string }) => incidentsAPI.update(id, { status }),
    onSuccess: (_, variables) => {
      setMsg(`Incident #${variables.id} → ${variables.status}.`)
      qc.invalidateQueries({ queryKey: ['incidents'] })
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Update failed.')
  })

  const autoGroupMut = useMutation({
    mutationFn: () => incidentsAPI.autoGroup(),
    onSuccess: (r) => {
      setMsg(`Auto-group: ${r.data.created} incidents created from orphaned alerts.`)
      qc.invalidateQueries({ queryKey: ['incidents'] })
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Auto-group failed.')
  })

  const handleCreate = () => {
    if (!title.trim()) return setMsg('Title is required.')
    const ids = alertIds.split(/[\s,;]+/).map(s => parseInt(s, 10)).filter(n => !isNaN(n))
    createMut.mutate({ title: title.trim(), alert_ids: ids })
  }

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 shrink-0">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <Siren className="text-red-400" /> Incidents
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">SOC Triage: Grouped alerts, status tracking, assignee, and timeline.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select value={filter} onChange={e => setFilter(e.target.value)} className="input py-1.5 px-3 min-w-[140px]">
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>
          <button onClick={() => autoGroupMut.mutate()} disabled={autoGroupMut.isPending} className="btn btn-primary bg-purple-600 hover:bg-purple-500 border-purple-500 shadow-purple-500/20 py-1.5 px-3">
            Auto-group Orphans
          </button>
          <button onClick={() => qc.invalidateQueries({ queryKey: ['incidents'] })} className="btn btn-ghost py-1.5 px-3 border border-[hsl(var(--border))]">
            <RefreshCcw size={14} /> Refresh
          </button>
        </div>
      </div>

      {msg && (
        <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-400 flex items-center gap-2 animate-fade-in shadow-sm">
          <CheckCircle2 size={16} /> {msg}
        </div>
      )}

      <div className="card p-4 flex flex-col md:flex-row gap-3 shadow-md">
        <input 
          value={title} 
          onChange={e => setTitle(e.target.value)} 
          placeholder="Incident Title (e.g. Intrusion WEB-03)" 
          className="input flex-1 bg-[hsl(var(--background))]" 
        />
        <input 
          value={alertIds} 
          onChange={e => setAlertIds(e.target.value)} 
          placeholder="Alert IDs (csv, optional)" 
          className="input md:w-64 font-mono bg-[hsl(var(--background))]" 
        />
        <button onClick={handleCreate} disabled={createMut.isPending} className="btn btn-primary bg-cyan-600 hover:bg-cyan-500 border-cyan-500 shadow-cyan-500/20 px-6">
          <Plus size={16} /> Create
        </button>
      </div>

      <div className="space-y-3">
        {isLoading ? (
          <div className="py-10 text-center text-[hsl(var(--muted-foreground))] italic">Loading incidents...</div>
        ) : items.length === 0 ? (
          <div className="py-12 text-center border-2 border-dashed border-[hsl(var(--border))] bg-[hsl(var(--secondary)/0.3)] rounded-xl text-[hsl(var(--muted-foreground))]">
            <ShieldAlert size={32} className="mx-auto mb-3 opacity-20 text-cyan-400" />
            <p className="font-bold text-white mb-1">No incidents found</p>
            <p className="text-sm">Create the first one or run auto-group to group orphaned alerts.</p>
          </div>
        ) : items.map((inc: any) => (
          <div key={inc.id} className={cn("card overflow-hidden transition-all duration-200 border", openId === inc.id ? "border-[hsl(var(--primary)/0.3)] shadow-lg" : "border-[hsl(var(--border))] hover:border-[hsl(var(--primary)/0.2)]")}>
            <button onClick={() => setOpenId(openId === inc.id ? null : inc.id)} className={cn("w-full flex flex-wrap sm:flex-nowrap items-center gap-3 p-4 text-left transition-colors", openId === inc.id ? "bg-[hsl(var(--primary)/0.05)]" : "hover:bg-[hsl(var(--secondary)/0.5)]")}>
              {openId === inc.id ? <ChevronDown size={18} className="text-cyan-400 shrink-0" /> : <ChevronRight size={18} className="text-[hsl(var(--muted-foreground))] shrink-0" />}
              
              <span className="font-mono text-cyan-400 text-sm font-semibold w-12 shrink-0">#{inc.id}</span>
              <span className="font-bold text-white flex-1 text-base truncate min-w-[200px]">{inc.title}</span>
              
              <div className="flex items-center gap-4 w-full sm:w-auto mt-2 sm:mt-0 ml-7 sm:ml-0">
                <span className="font-mono text-xs text-[hsl(var(--muted-foreground))] shrink-0"><span className="text-white">{inc.severity}</span> • {inc.alert_count} alerts</span>
                {inc.assignee && <span className="inline-flex items-center gap-1.5 text-xs text-purple-400 font-medium shrink-0 bg-purple-500/10 px-2 py-1 rounded-md border border-purple-500/20"><UserCheck size={14} />{inc.assignee}</span>}
                <span className={cn('px-2.5 py-1 rounded-md border text-[10px] uppercase font-bold tracking-widest shrink-0 ml-auto sm:ml-0', STATUS_COLOR[inc.status] || STATUS_COLOR.open)}>{inc.status}</span>
              </div>
            </button>

            {openId === inc.id && (
              <div className="border-t border-[hsl(var(--border))] p-5 space-y-5 bg-[hsl(var(--background))] animate-in slide-in-from-top-2 duration-200">
                <div className="flex items-center gap-3 text-xs font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">
                  Change Status:
                  <div className="flex flex-wrap gap-2">
                    {['open', 'investigating', 'contained', 'resolved', 'closed'].map(s => (
                      <button 
                        key={s} 
                        disabled={inc.status === s || updateStatusMut.isPending} 
                        onClick={() => updateStatusMut.mutate({ id: inc.id, status: s })} 
                        className={cn("rounded-md border px-3 py-1.5 transition-colors", inc.status === s ? "bg-[hsl(var(--secondary))] border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))] opacity-50 cursor-not-allowed" : "border-[hsl(var(--border))] text-white hover:border-[hsl(var(--primary)/0.5)] hover:bg-[hsl(var(--primary)/0.1)] hover:text-cyan-400")}
                      >
                        → {s}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest mb-3 border-b border-[hsl(var(--border))] pb-2">Timeline</h4>
                  <div className="space-y-1.5 max-h-[300px] overflow-y-auto pr-2">
                    {(inc.timeline || []).map((t: any) => (
                      <div key={t.id} className="flex items-center gap-3 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] px-4 py-2.5 text-xs hover:border-[hsl(var(--primary)/0.3)] transition-colors">
                        <span className="font-mono text-[hsl(var(--muted-foreground))] shrink-0">{t.timestamp?.slice(11, 19)}</span>
                        <span className="font-mono text-cyan-400 font-semibold shrink-0 w-32 truncate">{t.process_name}</span>
                        <span className="text-slate-300 truncate flex-1">{t.description}</span>
                        <span className={cn('font-bold uppercase tracking-widest text-[9px] px-2 py-0.5 rounded border shrink-0', t.severity === 'CRITICAL' ? 'text-red-400 bg-red-500/10 border-red-500/20' : t.severity === 'HIGH' ? 'text-orange-400 bg-orange-500/10 border-orange-500/20' : 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20')}>{t.severity}</span>
                      </div>
                    ))}
                    {(inc.timeline || []).length === 0 && <p className="text-xs text-[hsl(var(--muted-foreground))] italic text-center py-4 border border-dashed border-[hsl(var(--border))] rounded-lg">No alerts linked to this incident.</p>}
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
