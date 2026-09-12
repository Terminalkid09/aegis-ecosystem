import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Filter, Trash2, RefreshCw, ChevronDown, ChevronUp, Search } from 'lucide-react'
import { alertsAPI } from '@/services/api'
import { cn, severityBadge, timeAgo } from '@/lib/utils'

export default function AlertsTable() {
  const qc = useQueryClient()
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [search, setSearch] = useState('')
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL')
  const [filterResolved, setFilterResolved] = useState<string>('UNRESOLVED')

  const { data: alerts = [], isLoading } = useQuery({
    queryKey: ['alerts', filterSeverity, filterResolved],
    queryFn: () => alertsAPI.getAlerts({
      severity: filterSeverity !== 'ALL' ? filterSeverity : undefined,
      resolved: filterResolved === 'RESOLVED' ? true : filterResolved === 'UNRESOLVED' ? false : undefined,
      limit: 200,
    }).then(r => r.data?.items ?? r.data ?? []),
    refetchInterval: 20000,
  })

  const resolveMut = useMutation({
    mutationFn: ({ id, resolved }: { id: number; resolved: boolean }) =>
      alertsAPI.resolveAlert(id, resolved),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })

  const resolveAllMut = useMutation({
    mutationFn: () => alertsAPI.resolveAll(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })

  const deleteAllMut = useMutation({
    mutationFn: () => alertsAPI.deleteAll(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })

  const filtered = (alerts as any[]).filter(a => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      (a.process_name ?? '').toLowerCase().includes(q) ||
      (a.description ?? '').toLowerCase().includes(q) ||
      (a.mitre_tactic_name ?? '').toLowerCase().includes(q)
    )
  })

  const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  const RESOLVED_FILTERS = [
    { value: 'UNRESOLVED', label: 'Unresolved' },
    { value: 'RESOLVED', label: 'Resolved' },
    { value: 'ALL', label: 'All' },
  ]

  return (
    <div className="space-y-5 animate-slide-in">
      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <AlertTriangle size={20} className="text-red-400" /> Alerts
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">{filtered.length} matching alerts</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => qc.invalidateQueries({ queryKey: ['alerts'] })}
            className="btn btn-ghost"
          >
            <RefreshCw size={14} />
          </button>
          <button
            onClick={() => { if (confirm('Resolve all unresolved alerts?')) resolveAllMut.mutate() }}
            className="btn btn-ghost"
          >
            <CheckCircle2 size={14} /> Resolve All
          </button>
          <button
            onClick={() => { if (confirm('Delete ALL alerts? This is irreversible.')) deleteAllMut.mutate() }}
            className="btn btn-danger"
          >
            <Trash2 size={14} /> Clear
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4 flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-48">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
          <input
            className="input pl-9"
            placeholder="Search by process, description, MITRE…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <div className="flex gap-1">
          {SEVERITIES.map(s => (
            <button
              key={s}
              onClick={() => setFilterSeverity(s)}
              className={cn(
                'px-3 py-1 rounded text-xs font-semibold uppercase border transition-all',
                filterSeverity === s
                  ? s === 'ALL' ? 'bg-white/10 border-white/20 text-white' : cn(severityBadge(s))
                  : 'border-transparent text-[hsl(var(--muted-foreground))] hover:border-[hsl(var(--border))]'
              )}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex gap-1">
          {RESOLVED_FILTERS.map(f => (
            <button
              key={f.value}
              onClick={() => setFilterResolved(f.value)}
              className={cn(
                'px-3 py-1 rounded text-xs font-medium border transition-all',
                filterResolved === f.value
                  ? 'bg-white/10 border-white/20 text-white'
                  : 'border-transparent text-[hsl(var(--muted-foreground))] hover:border-[hsl(var(--border))]'
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-[hsl(var(--muted-foreground))]">Loading alerts…</div>
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center">
            <CheckCircle2 size={32} className="text-emerald-400 mx-auto mb-3 opacity-50" />
            <p className="text-[hsl(var(--muted-foreground))]">No alerts matching current filters.</p>
          </div>
        ) : (
          <div className="divide-y divide-[hsl(var(--border))]">
            {filtered.map((alert: any) => (
              <div key={alert.id} className="group">
                <div
                  onClick={() => setExpandedId(expandedId === alert.id ? null : alert.id)}
                  className={cn(
                    'flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-[hsl(var(--secondary))] transition-colors',
                    alert.is_resolved && 'opacity-50'
                  )}
                >
                  {/* Severity */}
                  <span className={cn('badge shrink-0', severityBadge(alert.severity))}>
                    {alert.severity}
                  </span>

                  {/* Process + description */}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-white truncate">
                      {alert.process_name || 'Unknown process'}
                    </p>
                    <p className="text-xs text-[hsl(var(--muted-foreground))] truncate">
                      {alert.description}
                    </p>
                  </div>

                  {/* MITRE */}
                  {alert.mitre_technique_id && (
                    <span className="badge badge-info shrink-0 hidden lg:inline-flex">
                      {alert.mitre_technique_id}
                    </span>
                  )}

                  {/* Time */}
                  <span className="text-xs text-[hsl(var(--muted-foreground))] shrink-0">
                    {timeAgo(alert.timestamp)}
                  </span>

                  {/* Actions */}
                  <div className="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={e => { e.stopPropagation(); resolveMut.mutate({ id: alert.id, resolved: !alert.is_resolved }) }}
                      className={cn(
                        'p-1.5 rounded text-xs transition-colors',
                        alert.is_resolved
                          ? 'text-[hsl(var(--muted-foreground))] hover:text-white hover:bg-[hsl(var(--secondary))]'
                          : 'text-emerald-400 hover:bg-emerald-400/10'
                      )}
                      title={alert.is_resolved ? 'Re-open' : 'Resolve'}
                    >
                      <CheckCircle2 size={14} />
                    </button>
                  </div>
                  {expandedId === alert.id ? <ChevronUp size={14} className="text-[hsl(var(--muted-foreground))] shrink-0" /> : <ChevronDown size={14} className="text-[hsl(var(--muted-foreground))] shrink-0" />}
                </div>

                {/* Expanded detail */}
                {expandedId === alert.id && (
                  <div className="px-4 pb-4 bg-[hsl(var(--secondary))] border-t border-[hsl(var(--border))] animate-fade-in">
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 pt-3 text-xs">
                      {[
                        ['Alert ID', alert.id],
                        ['Agent ID', alert.agent_id],
                        ['PID', alert.pid || 'N/A'],
                        ['Parent PID', alert.parent_pid || 'N/A'],
                        ['Parent Process', alert.parent_process_name || 'N/A'],
                        ['Process Path', alert.process_path || 'N/A'],
                        ['User', (alert as any).user || (alert as any).username || 'N/A'],
                        ['Host', (alert as any).hostname || (alert as any).agent_id?.slice(0,8) || 'N/A'],
                        ['Event Type', alert.event_type || 'N/A'],
                        ['Network', (alert as any).network_connections ? JSON.stringify((alert as any).network_connections).slice(0,120) : ((alert as any).remote || 'N/A')],
                        ['Rule', (alert as any).rule_id || (alert as any).rule_name || alert.mitre_technique_id || 'N/A'],
                        ['Confidence', ((): string => { const m = String(alert.description||'').match(/Confidence=([a-z]+)/i); return m ? m[1] : ((alert as any).confidence || 'medium') })()],
                        ['Severity', alert.severity],
                        ['Evidence', ((): string => { const m = String(alert.description||'').match(/TrustedSigned=([a-z]+)/i); const p = String(alert.description||'').match(/Prevalence=([^|]+)/); const l = String(alert.description||'').match(/Lineage=([^|]+)/); return [m?`trusted=${m[1]}`:'', p?p[1].trim():'', l?`lineage ${l[1].trim()}`:''].filter(Boolean).join(' · ') || '—' })()],
                        ['Reason', ((): string => { const m = String(alert.description||'').match(/Reason: ([^|]+)/); return m ? m[1].trim() : String(alert.description||'').slice(0,160) })()],
                        ['MITRE Tactic', `${alert.mitre_tactic_id ?? ''} ${alert.mitre_tactic_name ?? ''}`.trim() || 'N/A'],
                        ['MITRE Technique', `${alert.mitre_technique_id ?? ''} ${alert.mitre_technique_name ?? ''}`.trim() || 'N/A'],
                        ['Timestamp', new Date(alert.timestamp).toLocaleString()],
                        ['Status', alert.is_resolved ? 'Resolved' : 'Unresolved'],
                      ].map(([k, v]) => (
                        <div key={String(k)}>
                          <p className="text-[hsl(var(--muted-foreground))] uppercase tracking-wider mb-0.5">{k}</p>
                          <p className="text-white font-mono break-all">{String(v)}</p>
                        </div>
                      ))}
                    </div>
                    <div className="mt-3 pt-3 border-t border-[hsl(var(--border))]">
                      <p className="text-[hsl(var(--muted-foreground))] text-xs uppercase tracking-wider mb-1">Description</p>
                      <p className="text-white text-xs">{alert.description}</p>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
