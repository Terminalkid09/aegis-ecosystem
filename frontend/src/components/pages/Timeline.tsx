import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, AlertTriangle, Bug, Clock3, ExternalLink, Loader2, RefreshCcw, SearchCode } from 'lucide-react'
import { timelineAPI } from '@/services/api'
import { type Page, useAppStore } from '@/store/appStore'
import { cn, timeAgo } from '@/lib/utils'

type Source = 'siem' | 'deception' | 'alert' | 'incident' | 'telemetry'

type TimelineItem = {
  id: string
  source: Source
  time: string | null
  severity: string
  title: string
  detail: string
  host: string | null
  ip: string | null
  link: { page: Page; id: string | number }
}

const SOURCES: { id: Source; label: string; icon: React.ElementType; color: string }[] = [
  { id: 'siem', label: 'SIEM', icon: SearchCode, color: 'text-cyan-400' },
  { id: 'deception', label: 'Deception', icon: Bug, color: 'text-rose-400' },
  { id: 'alert', label: 'Alerts', icon: AlertTriangle, color: 'text-orange-400' },
  { id: 'incident', label: 'Incidents', icon: Activity, color: 'text-purple-400' },
  { id: 'telemetry', label: 'Telemetry', icon: Clock3, color: 'text-emerald-400' },
]

const SEVERITY: Record<string, string> = {
  CRITICAL: 'text-red-400 border-red-500/30 bg-red-500/10',
  HIGH: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
  MEDIUM: 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10',
  LOW: 'text-sky-400 border-sky-500/30 bg-sky-500/10',
  INFO: 'text-slate-400 border-slate-500/30 bg-slate-500/10',
}

const ROW_HEIGHT = 62
const VIEW_HEIGHT = 560

export default function Timeline() {
  const setCurrentPage = useAppStore((state) => state.setCurrentPage)
  const [hours, setHours] = useState(24)
  const [selected, setSelected] = useState<Source[]>(SOURCES.map((source) => source.id))
  const [scrollTop, setScrollTop] = useState(0)

  const sources = useMemo(
    () => SOURCES.map((source) => source.id).filter((id) => selected.includes(id)),
    [selected]
  )

  const { data, isFetching, refetch } = useQuery({
    queryKey: ['timeline', hours, sources],
    queryFn: () => timelineAPI.query({ hours, limit: 500, sources: sources.join(',') }).then((res) => res.data),
    refetchInterval: 30000,
  })

  const items: TimelineItem[] = data?.items || []
  const start = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - 5)
  const end = Math.min(items.length, start + Math.ceil(VIEW_HEIGHT / ROW_HEIGHT) + 10)
  const visible = items.slice(start, end)

  function toggleSource(source: Source) {
    setSelected((current) => {
      if (current.includes(source)) {
        return current.length === 1 ? current : current.filter((value) => value !== source)
      }
      return [...current, source]
    })
    setScrollTop(0)
  }

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <Clock3 className="text-emerald-400" /> Unified Timeline
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">
            SIEM, deception, alerts, incidents and telemetry in one ordered investigation view.
            Kraken operations remain in the Kraken UI.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select className="input w-40" value={hours} onChange={(event) => setHours(Number(event.target.value))}>
            <option value={1}>Last hour</option>
            <option value={6}>Last 6 hours</option>
            <option value={24}>Last 24 hours</option>
            <option value={72}>Last 3 days</option>
            <option value={168}>Last 7 days</option>
          </select>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="btn btn-ghost py-1.5 px-3 border border-[hsl(var(--border))]"
          >
            {isFetching ? <Loader2 size={14} className="animate-spin" /> : <RefreshCcw size={14} />} Refresh
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {SOURCES.map(({ id, label, icon: Icon, color }) => {
          const active = selected.includes(id)
          return (
            <button
              key={id}
              onClick={() => toggleSource(id)}
              className={cn(
                'flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors',
                active
                  ? 'border-[hsl(var(--primary)/0.4)] bg-[hsl(var(--primary)/0.12)] text-white'
                  : 'border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))] hover:text-white'
              )}
            >
              <Icon size={12} className={active ? color : ''} />
              {label}
              <span className="font-mono text-[10px] opacity-70">{data?.counts?.[id] ?? 0}</span>
            </button>
          )
        })}
        <span className="ml-auto text-xs text-[hsl(var(--muted-foreground))]">
          {items.length.toLocaleString()} events · virtualised list
        </span>
      </div>

      <div className="card overflow-hidden">
        {isFetching && items.length === 0 ? (
          <div className="py-20 flex items-center justify-center gap-2 text-[hsl(var(--muted-foreground))]">
            <Loader2 size={20} className="animate-spin text-emerald-400" /> Loading timeline…
          </div>
        ) : items.length === 0 ? (
          <div className="py-20 text-center text-sm text-[hsl(var(--muted-foreground))] italic">
            No events in this window and source selection.
          </div>
        ) : (
          <div
            className="overflow-y-auto"
            style={{ height: VIEW_HEIGHT }}
            onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
            data-testid="timeline-viewport"
          >
            <div style={{ height: items.length * ROW_HEIGHT, position: 'relative' }}>
              {visible.map((item, index) => {
                const source = SOURCES.find((entry) => entry.id === item.source)!
                const Icon = source.icon
                return (
                  <button
                    key={item.id}
                    onClick={() => setCurrentPage(item.link.page)}
                    className="absolute left-0 right-0 flex items-center gap-3 border-b border-[hsl(var(--border))] px-4 text-left hover:bg-[hsl(var(--secondary)/0.55)] transition-colors"
                    style={{ top: (start + index) * ROW_HEIGHT, height: ROW_HEIGHT }}
                    title={`Open ${item.link.page}`}
                  >
                    <span className="w-24 shrink-0 text-[10px] font-mono text-[hsl(var(--muted-foreground))]">
                      {item.time ? new Date(item.time).toLocaleString() : '—'}
                    </span>
                    <span className={cn('flex w-24 shrink-0 items-center gap-1.5 text-[10px] font-bold uppercase tracking-wide', source.color)}>
                      <Icon size={12} /> {source.label}
                    </span>
                    <span className={cn('shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-bold', SEVERITY[item.severity] || SEVERITY.INFO)}>
                      {item.severity}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium text-white">{item.title}</span>
                      <span className="block truncate text-[11px] text-[hsl(var(--muted-foreground))]">
                        {item.host || item.ip || '—'}{item.detail ? ` · ${item.detail}` : ''}
                      </span>
                    </span>
                    <span className="hidden shrink-0 text-[10px] text-[hsl(var(--muted-foreground))] sm:block">
                      {item.time ? timeAgo(item.time) : ''}
                    </span>
                    <ExternalLink size={12} className="shrink-0 text-[hsl(var(--muted-foreground))]" />
                  </button>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
