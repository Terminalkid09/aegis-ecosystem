import { Fragment, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  SearchCode, Loader2, RefreshCcw, Filter, ChevronDown, ChevronRight,
  Database, Activity, X,
} from 'lucide-react'
import { siemAPI } from '@/services/api'
import { cn } from '@/lib/utils'

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/20',
  HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  LOW: 'bg-sky-500/10 text-sky-400 border-sky-500/20',
  INFO: 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]',
}

const FILTER_FIELDS = ['source', 'source_type', 'severity', 'hostname', 'src_ip', 'dst_ip', 'user', 'process_name'] as const

interface EventRow {
  id: number
  time: string | null
  source: string | null
  source_type: string | null
  severity: string | null
  hostname: string | null
  user: string | null
  src_ip: string | null
  src_port: number | null
  dst_ip: string | null
  dst_port: number | null
  process_name: string | null
  message: string | null
  [key: string]: unknown
}

const PAGE_SIZE = 100

export default function Search() {
  const [text, setText] = useState('')
  const [hours, setHours] = useState<number>(24)
  const [filters, setFilters] = useState<Record<string, string>>({})
  const [order, setOrder] = useState<'desc' | 'asc'>('desc')
  const [page, setPage] = useState(0)
  const [expanded, setExpanded] = useState<number | null>(null)

  // Filtri attivi (solo quelli valorizzati) — inviati al backend come allowlist.
  const activeFilters = useMemo(
    () => Object.fromEntries(
      Object.entries(filters).map(([k, v]) => [k, v.trim()]).filter(([, v]) => v !== '')
    ),
    [filters]
  )

  const { data, isFetching, refetch } = useQuery({
    queryKey: ['siem-search', text, hours, activeFilters, order, page],
    queryFn: () => siemAPI.search({
      text: text.trim() || undefined,
      hours,
      filters: activeFilters,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
      order,
    }).then(r => r.data),
  })

  const { data: stats } = useQuery({
    queryKey: ['siem-search-stats', hours],
    queryFn: () => siemAPI.getEventStats(hours).then(r => r.data),
    staleTime: 30_000,
  })

  const { data: fieldCatalog } = useQuery({
    queryKey: ['siem-search-fields'],
    queryFn: () => siemAPI.getFields().then(r => r.data),
    staleTime: 10 * 60_000,
  })

  const items: EventRow[] = data?.items || []
  const total: number = data?.total || 0
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  function reset() {
    setText('')
    setHours(24)
    setFilters({})
    setOrder('desc')
    setPage(0)
  }

  const descByField = useMemo(() => {
    const map: Record<string, string> = {}
    for (const f of fieldCatalog?.fields || []) map[f.field] = f.description
    return map
  }, [fieldCatalog])

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <SearchCode className="text-emerald-400" /> Log Search
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">
            Ricerca sugli eventi normalizzati da tutte le sorgenti. I campi filtrabili sono
            validati lato server: nessuna query libera arriva al database.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="btn btn-ghost py-1.5 px-3 border border-[hsl(var(--border))]"
        >
          {isFetching ? <Loader2 size={14} className="animate-spin" /> : <RefreshCcw size={14} />}
          Refresh
        </button>
      </div>

      {/* Barra di ricerca */}
      <div className="card p-5 space-y-4">
        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <SearchCode size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
            <input
              className="input pl-9"
              placeholder="Ricerca libera su messaggio e campi indicizzati…"
              value={text}
              onChange={e => { setText(e.target.value); setPage(0) }}
              onKeyDown={e => { if (e.key === 'Enter') refetch() }}
            />
          </div>
          <select
            className="input md:w-40"
            value={hours}
            onChange={e => { setHours(Number(e.target.value)); setPage(0) }}
          >
            <option value={1}>Ultima ora</option>
            <option value={6}>Ultime 6 ore</option>
            <option value={24}>Ultime 24 ore</option>
            <option value={72}>Ultimi 3 giorni</option>
            <option value={168}>Ultimi 7 giorni</option>
            <option value={720}>Ultimi 30 giorni</option>
          </select>
          <select
            className="input md:w-40"
            value={order}
            onChange={e => { setOrder(e.target.value as 'desc' | 'asc'); setPage(0) }}
          >
            <option value="desc">Più recenti</option>
            <option value="asc">Più vecchi</option>
          </select>
        </div>

        {/* Filtri per campo */}
        <div>
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-[hsl(var(--muted-foreground))] mb-2">
            <Filter size={12} /> Filtri
            {Object.values(filters).some(v => v) && (
              <button onClick={reset} className="ml-auto flex items-center gap-1 text-emerald-400 hover:text-emerald-300 normal-case">
                <X size={12} /> Azzera
              </button>
            )}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {FILTER_FIELDS.map(field => (
              <input
                key={field}
                className="input text-xs"
                placeholder={field}
                title={descByField[field] || field}
                value={filters[field] || ''}
                onChange={e => { setFilters(f => ({ ...f, [field]: e.target.value })); setPage(0) }}
              />
            ))}
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs text-[hsl(var(--muted-foreground))]">
          <span><span className="text-white font-semibold">{total.toLocaleString()}</span> eventi trovati</span>
          {stats && <>
            <span className="flex items-center gap-1"><Database size={12} /> {Object.keys(stats.by_source_type || {}).length} tipi sorgente</span>
            <span className="flex items-center gap-1"><Activity size={12} /> {stats.events_per_second} eps ({hours}h)</span>
          </>}
        </div>
      </div>

      {/* Risultati */}
      <div className="card overflow-hidden">
        {isFetching && items.length === 0 ? (
          <div className="py-16 flex items-center justify-center gap-3 text-[hsl(var(--muted-foreground))]">
            <Loader2 size={24} className="animate-spin text-emerald-400" /> Ricerca in corso…
          </div>
        ) : items.length === 0 ? (
          <div className="py-16 text-center text-[hsl(var(--muted-foreground))] italic border border-dashed border-[hsl(var(--border))] rounded-lg m-4">
            <SearchCode size={32} className="mx-auto mb-3 opacity-20 text-emerald-400" />
            Nessun evento corrisponde ai filtri. Prova ad ampliare la finestra temporale.
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] text-xs uppercase tracking-wider">
                  <tr>
                    <th className="p-3 font-medium w-8"></th>
                    <th className="p-3 font-medium">Timestamp</th>
                    <th className="p-3 font-medium">Severity</th>
                    <th className="p-3 font-medium">Sorgente</th>
                    <th className="p-3 font-medium">Host / Utente</th>
                    <th className="p-3 font-medium">Rete</th>
                    <th className="p-3 font-medium w-full">Messaggio</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[hsl(var(--border))]">
                  {items.map(ev => (
                    <Fragment key={ev.id}>
                      <tr
                        onClick={() => setExpanded(expanded === ev.id ? null : ev.id)}
                        className="hover:bg-[hsl(var(--secondary)/50)] transition-colors cursor-pointer"
                      >
                        <td className="p-3 text-[hsl(var(--muted-foreground))]">
                          {expanded === ev.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        </td>
                        <td className="p-3 text-xs text-[hsl(var(--muted-foreground))] font-mono whitespace-nowrap">
                          {ev.time ? new Date(ev.time).toLocaleString() : '—'}
                        </td>
                        <td className="p-3">
                          <span className={cn('px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-widest border',
                            SEVERITY_STYLE[ev.severity || 'INFO'] || SEVERITY_STYLE.INFO)}>
                            {ev.severity || 'INFO'}
                          </span>
                        </td>
                        <td className="p-3 text-white text-xs font-mono whitespace-nowrap">{ev.source || '—'}</td>
                        <td className="p-3 text-xs text-[hsl(var(--muted-foreground))] whitespace-nowrap">
                          {ev.hostname || '—'}{ev.user ? ` · ${ev.user}` : ''}
                        </td>
                        <td className="p-3 text-xs font-mono text-[hsl(var(--muted-foreground))] whitespace-nowrap">
                          {ev.src_ip ? `${ev.src_ip}${ev.src_port ? ':' + ev.src_port : ''}` : '—'}
                          {ev.dst_ip ? <>&nbsp;→&nbsp;{ev.dst_ip}{ev.dst_port ? ':' + ev.dst_port : ''}</> : null}
                        </td>
                        <td className="p-3 text-xs text-[hsl(var(--muted-foreground))] max-w-2xl truncate" title={ev.message || ''}>
                          {ev.message || '—'}
                        </td>
                      </tr>
                      {expanded === ev.id && (
                        <tr className="bg-[hsl(var(--secondary)/40)]">
                          <td colSpan={7} className="p-4">
                            <pre className="bg-[hsl(var(--secondary))] p-3 rounded font-mono text-[11px] max-h-80 overflow-auto text-[hsl(var(--muted-foreground))]">
                              {JSON.stringify(ev, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Paginazione */}
            <div className="flex items-center justify-between p-4 border-t border-[hsl(var(--border))] text-sm">
              <span className="text-[hsl(var(--muted-foreground))]">
                {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} di {total.toLocaleString()}
              </span>
              <div className="flex items-center gap-2">
                <button
                  className="btn btn-ghost py-1.5 px-3 text-xs border border-[hsl(var(--border))] disabled:opacity-40"
                  disabled={page === 0}
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                >
                  Precedente
                </button>
                <span className="text-xs text-[hsl(var(--muted-foreground))]">{page + 1} / {pages}</span>
                <button
                  className="btn btn-ghost py-1.5 px-3 text-xs border border-[hsl(var(--border))] disabled:opacity-40"
                  disabled={page + 1 >= pages}
                  onClick={() => setPage(p => p + 1)}
                >
                  Successiva
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
