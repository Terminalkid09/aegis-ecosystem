import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Filter, Trash2, RefreshCw, ChevronDown, ChevronUp, Search } from 'lucide-react'
import { alertsAPI } from '@/services/api'
import { PermissionGate } from '@/components/common/PermissionGate'
import { cn, severityBadge, timeAgo } from '@/lib/utils'
import { useAppStore } from '@/store/appStore'

export default function AlertsTable() {
  const qc = useQueryClient()
  const setLiveStats = useAppStore(state => state.setLiveStats)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [search, setSearch] = useState('')
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL')
  const [filterResolved, setFilterResolved] = useState<string>('UNRESOLVED')
  const [resolveFeedback, setResolveFeedback] = useState<string | null>(null)

  const { data: alerts = [], isLoading, isFetching, isError, refetch } = useQuery({
    queryKey: ['alerts', filterSeverity, filterResolved],
    queryFn: () => alertsAPI.getAlerts({
      severity: filterSeverity !== 'ALL' ? filterSeverity : undefined,
      is_resolved: filterResolved === 'RESOLVED' ? true : filterResolved === 'UNRESOLVED' ? false : undefined,
      limit: 200,
    }).then(r => r.data?.items ?? r.data ?? []),
    refetchInterval: 20000,
  })

  const resolveMut = useMutation({
    mutationFn: ({ id, resolved }: { id: number; resolved: boolean }) =>
      alertsAPI.resolveAlert(id, resolved),
    onMutate: async ({ id, resolved }) => {
      await qc.cancelQueries({ queryKey: ['alerts'] })
      const previous = qc.getQueriesData({ queryKey: ['alerts'] })
      qc.setQueriesData({ queryKey: ['alerts'] }, (current: any) => {
        if (!Array.isArray(current)) return current
        if (filterResolved === 'UNRESOLVED' && resolved) {
          return current.filter((alert: any) => alert.id !== id)
        }
        return current.map((alert: any) =>
          alert.id === id ? { ...alert, is_resolved: resolved } : alert
        )
      })
      const live = useAppStore.getState().liveStats
      if (live && resolved && filterResolved === 'UNRESOLVED') {
        setLiveStats({
          ...live,
          unresolved_alerts: Math.max(0, (live.unresolved_alerts ?? 1) - 1),
        })
      }
      return { previous }
    },
    onSuccess: (res, { resolved }) => {
      const data = res?.data
      if (!resolved) {
        setResolveFeedback('Alert re-opened — similar detections can appear again.')
        return
      }
      const days = data?.triage_muted_seconds
        ? Math.round(data.triage_muted_seconds / 86400)
        : 0
      const killed = data?.process_killed
      const parts = ['Marked resolved.']
      if (days > 0) parts.push(`Similar alerts muted ~${days} days on this host.`)
      if (killed) parts.push('Kill command queued to the agent.')
      else if (data?.pid) parts.push('No kill (needs respond permission or event type).')
      setResolveFeedback(parts.join(' '))
    },
    onError: (_error, _variables, context) => {
      context?.previous.forEach(([key, data]) => qc.setQueryData(key, data))
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['stats'] })
    },
  })

  const resolveAllMut = useMutation({
    mutationFn: () => alertsAPI.resolveAll(),
    onMutate: async () => {
      await qc.cancelQueries({ queryKey: ['alerts'] })
      const previous = qc.getQueriesData({ queryKey: ['alerts'] })
      qc.setQueriesData({ queryKey: ['alerts'] }, (current: any) => {
        if (!Array.isArray(current)) return current
        return current.map(alert => ({ ...alert, is_resolved: true }))
      })
      const currentLiveStats = useAppStore.getState().liveStats
      if (currentLiveStats) {
        setLiveStats({ ...currentLiveStats, unresolved_alerts: 0,
          current_critical_alerts: 0, current_high_alerts: 0, current_medium_alerts: 0 })
      }
      return { previous }
    },
    onError: (_error, _variables, context) => {
      context?.previous.forEach(([key, data]) => qc.setQueryData(key, data))
    },
    onSuccess: (res) => {
      const n = res?.data?.resolved
      const detail = res?.data?.detail
      setResolveFeedback(
        typeof detail === 'string' && detail
          ? detail
          : `Resolved ${n ?? 'all'} alerts. Similar patterns muted ~7 days on each host.`
      )
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['stats'] })
    },
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
            onClick={() => refetch()}
            disabled={isFetching}
            className="btn btn-ghost"
            title="Refresh alerts"
          >
            <RefreshCw size={14} className={isFetching ? 'animate-spin' : undefined} />
          </button>
          <PermissionGate perms={['triage', 'rules']} mode="hide">
            <button
              onClick={() => { if (confirm('Resolve all unresolved alerts?')) resolveAllMut.mutate() }}
              disabled={resolveAllMut.isPending}
              className="btn btn-ghost disabled:opacity-50"
            >
              <CheckCircle2 size={14} className={resolveAllMut.isPending ? 'animate-pulse' : undefined} />
              {resolveAllMut.isPending ? 'Resolving…' : 'Resolve All'}
            </button>
          </PermissionGate>
          <PermissionGate perms={['manage']} mode="hide">
            <button
              onClick={() => { if (confirm('Delete ALL alerts? This is irreversible.')) deleteAllMut.mutate() }}
              className="btn btn-danger"
            >
              <Trash2 size={14} /> Clear
            </button>
          </PermissionGate>
        </div>
      </div>

      {isError && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-2 text-xs text-red-300">
          <span>Alerts could not be loaded. Your existing view is still available.</span>
          <button onClick={() => refetch()} className="text-white underline underline-offset-2">Retry</button>
        </div>
      )}
      {(resolveMut.isError || resolveAllMut.isError) && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-2 text-xs text-red-300">
          The change could not be saved. The alert state was restored.
        </div>
      )}
      {resolveFeedback && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2 text-xs text-emerald-200">
          <span>{resolveFeedback}</span>
          <button type="button" onClick={() => setResolveFeedback(null)} className="text-emerald-400/80 hover:text-white">
            Dismiss
          </button>
        </div>
      )}

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
                    <PermissionGate perms={['triage', 'respond']} mode="disable">
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
                    </PermissionGate>
                  </div>
                  {expandedId === alert.id ? <ChevronUp size={14} className="text-[hsl(var(--muted-foreground))] shrink-0" /> : <ChevronDown size={14} className="text-[hsl(var(--muted-foreground))] shrink-0" />}
                </div>

                {/* Expanded detail */}
                {expandedId === alert.id && (
                  <div className="px-4 pb-4 bg-[hsl(var(--secondary))] border-t border-[hsl(var(--border))] animate-fade-in">
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 pt-3 text-xs">
                      {[
                        ['Alert ID', alert.id],
                        ['Host', (alert as any).agent_hostname || (alert as any).hostname || String(alert.agent_id).slice(0, 8)],
                        ['Agent ID', alert.agent_id],
                        ['PID', alert.pid ?? 'N/A'],
                        ['Parent PID', alert.parent_pid ?? 'N/A'],
                        ['Parent Process', alert.parent_process_name || 'N/A'],
                        ['Process Path', alert.process_path || 'N/A'],
                        ['Event Type', alert.event_type || 'N/A'],
                        ['Rule', (alert as any).rule_id || (alert as any).rule_name || alert.mitre_technique_id || 'N/A'],
                        ['Confidence', ((): string => { const m = String(alert.description||'').match(/Confidence=([a-z]+)/i); return m ? m[1] : ((alert as any).confidence || 'medium') })()],
                        ['Severity', alert.severity],
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
                    {/* Evidence strutturata: i fatti dell'alert (endpoint remoto,
                        conteggio connessioni, processi, CLI, utente) — non piu'
                        righe N/A per campi che quel tipo di alert non ha mai avuto. */}
                    {(() => {
                      const ev = (alert as any).evidence as Record<string, any> | null | undefined
                      if (!ev || typeof ev !== 'object') return null
                      const ip = ev.ip || ev.endpoint || null
                      const owners = Array.isArray(ev.processes) ? ev.processes : []
                      const rows: Array<[string, string]> = []
                      if (ip) rows.push(['Remote endpoint', `${ip}${ev.connection_count ? ` · ${ev.connection_count} connections in window` : ''}`])
                      if (owners.length) rows.push(['Owning processes', owners.map((o: any) => `${o.name} (${o.connections})`).join(', ')])
                      if (ev.command_line) rows.push(['Command line', String(ev.command_line)])
                      if (ev.process) rows.push(['Process', String(ev.process)])
                      if (ev.pid != null) rows.push(['PID', String(ev.pid)])
                      if (ev.memory_percent != null) rows.push(['Memory', `${ev.memory_percent}%`])
                      if (ev.cpu_percent != null) rows.push(['CPU', `${ev.cpu_percent}%`])
                      if (ev.user) rows.push(['User', String(ev.user)])
                      if (ev.detail) rows.push(['Detail', String(ev.detail)])
                      if (!rows.length) return null
                      return (
                        <div className="mt-3 pt-3 border-t border-[hsl(var(--border))]">
                          <p className="text-[hsl(var(--muted-foreground))] text-xs uppercase tracking-wider mb-1">Evidence</p>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {rows.map(([k, v]) => (
                              <div key={k} className="bg-[hsl(var(--background))] rounded p-2">
                                <p className="text-[hsl(var(--muted-foreground))] text-[10px] uppercase tracking-wider mb-0.5">{k}</p>
                                <p className="text-white font-mono text-xs break-all">{v}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )
                    })()}
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
