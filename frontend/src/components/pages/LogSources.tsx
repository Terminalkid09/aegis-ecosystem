import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Database, Loader2, RefreshCcw, Plus, ShieldCheck, Activity,
  FlaskConical, AlertTriangle, CheckCircle2,
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

interface SourceRow {
  id: number
  name: string
  source_type: string
  parser: string
  description: string | null
  enabled: boolean
  events_total: number
  events_invalid: number
  last_event_at: string | null
  last_error: string | null
}

function fmt(value?: string | null) {
  return value ? new Date(value).toLocaleString() : '—'
}

export default function LogSources() {
  const qc = useQueryClient()
  const [newSource, setNewSource] = useState({ name: '', parser: 'auto', description: '' })
  const [testPayload, setTestPayload] = useState({ parser: 'auto', payload: '' })
  const [testResult, setTestResult] = useState<any>(null)
  const [formError, setFormError] = useState<string | null>(null)

  const { data: sources = [], isLoading } = useQuery<SourceRow[]>({
    queryKey: ['siem-sources'],
    queryFn: () => siemAPI.getSources().then(r => r.data?.items || []),
    refetchInterval: 20000,
  })

  const { data: catalog } = useQuery({
    queryKey: ['siem-catalog'],
    queryFn: () => siemAPI.getCatalog().then(r => r.data),
    staleTime: 5 * 60_000,
  })

  const { data: stats } = useQuery({
    queryKey: ['siem-stats'],
    queryFn: () => siemAPI.getStats(24).then(r => r.data),
    refetchInterval: 30000,
  })

  const { data: coverage } = useQuery({
    queryKey: ['siem-coverage'],
    queryFn: () => siemAPI.getDetectionCoverage().then(r => r.data),
    staleTime: 60_000,
  })

  const createSource = useMutation({
    mutationFn: () => siemAPI.createSource({
      name: newSource.name.trim(),
      parser: newSource.parser,
      description: newSource.description || undefined,
    }),
    onSuccess: () => {
      setNewSource({ name: '', parser: 'auto', description: '' })
      setFormError(null)
      qc.invalidateQueries({ queryKey: ['siem-sources'] })
    },
    onError: (err: any) => setFormError(err?.response?.data?.detail?.toString() || 'Source creation failed'),
  })

  const testParser = useMutation({
    mutationFn: () => {
      let payload: unknown = testPayload.payload
      // NDJSON/JSON valido → oggetto; altrimenti la riga grezza (syslog, Zeek TSV…)
      try { payload = JSON.parse(testPayload.payload) } catch { /* resta stringa */ }
      return siemAPI.testParser({ parser: testPayload.parser, payload }).then(r => r.data)
    },
    onSuccess: data => setTestResult(data),
    onError: (err: any) => setTestResult({ errors: [err?.response?.data?.detail?.toString() || err.message] }),
  })

  const totalEvents = stats?.total ?? 0
  const eps = stats?.events_per_second ?? 0
  const healthy = sources.filter(s => !s.last_error).length

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <Database className="text-emerald-400" /> Log Sources
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">
            Multi-source ingestion: syslog, Windows Event Log, Zeek, Suricata, firewall, proxy.
            Ingest endpoint: <code className="text-emerald-400">POST /api/v1/ingest/&lt;source&gt;</code>
          </p>
        </div>
        <button
          onClick={() => qc.invalidateQueries()}
          className="btn btn-ghost py-1.5 px-3 border border-[hsl(var(--border))]"
        >
          <RefreshCcw size={14} /> Refresh
        </button>
      </div>

      {/* KPI */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
            <Activity size={14} /> Events 24h
          </div>
          <div className="text-2xl font-bold text-white mt-2">{totalEvents.toLocaleString()}</div>
          <div className="text-xs text-[hsl(var(--muted-foreground))]">{eps} avg events/s</div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
            <Database size={14} /> Sources
          </div>
          <div className="text-2xl font-bold text-white mt-2">{sources.length}</div>
          <div className="text-xs text-[hsl(var(--muted-foreground))]">{healthy} with no errors</div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
            <ShieldCheck size={14} /> Active Sigma rules
          </div>
          <div className="text-2xl font-bold text-white mt-2">
            {stats?.detection?.sigma_rules ?? '—'}
            <span className="text-sm text-[hsl(var(--muted-foreground))]">/{stats?.detection?.sigma_rules_total ?? '—'}</span>
          </div>
          <div className="text-xs text-[hsl(var(--muted-foreground))]">compilable / loaded</div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
            <ShieldCheck size={14} /> Active correlations
          </div>
          <div className="text-2xl font-bold text-white mt-2">
            {stats?.detection?.correlation_rules ?? '—'}
            <span className="text-sm text-[hsl(var(--muted-foreground))]">/{stats?.detection?.correlation_rules_total ?? '—'}</span>
          </div>
          <div className="text-xs text-[hsl(var(--muted-foreground))]">threshold + sequence</div>
        </div>
      </div>

      {/* Catalogo parser + form sorgente */}
      <div className="grid lg:grid-cols-2 gap-4">
        <div className="card p-5 space-y-3">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Plus size={16} className="text-emerald-400" /> Register a source
          </h2>
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
            Registering a source before its logs arrive lets you track its health.
            With <code>auto</code> the parser is chosen from the payload shape.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <input
              className="input"
              placeholder="name (e.g. fw-hq-01)"
              value={newSource.name}
              onChange={e => setNewSource(s => ({ ...s, name: e.target.value }))}
            />
            <select
              className="input"
              value={newSource.parser}
              onChange={e => setNewSource(s => ({ ...s, parser: e.target.value }))}
            >
              <option value="auto">auto</option>
              {(catalog?.parsers || []).map((p: any) => (
                <option key={p.name} value={p.name}>{p.name} ({p.source_type})</option>
              ))}
            </select>
          </div>
          <input
            className="input"
            placeholder="descrizione (opzionale)"
            value={newSource.description}
            onChange={e => setNewSource(s => ({ ...s, description: e.target.value }))}
          />
          {formError && <div className="text-xs text-red-400">{formError}</div>}
          <button
            className="btn btn-primary py-2 px-4 text-sm"
            disabled={!newSource.name.trim() || createSource.isPending}
            onClick={() => createSource.mutate()}
          >
            {createSource.isPending ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
            Add source
          </button>
        </div>

        <div className="card p-5 space-y-3">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <FlaskConical size={16} className="text-purple-400" /> Prova un parser
          </h2>
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
Nothing is stored: this only validates the format of a new source.
          </p>
          <select
            className="input"
            value={testPayload.parser}
            onChange={e => setTestPayload(s => ({ ...s, parser: e.target.value }))}
          >
            <option value="auto">auto</option>
            {(catalog?.parsers || []).map((p: any) => (
              <option key={p.name} value={p.name}>{p.name} ({p.source_type})</option>
            ))}
          </select>
          <textarea
            className="input font-mono text-xs h-24"
            placeholder={'<134>1 2026-09-15T12:00:01Z web-01 sshd - Failed password for root from 203.0.113.9 port 51234 ssh2'}
            value={testPayload.payload}
            onChange={e => setTestPayload(s => ({ ...s, payload: e.target.value }))}
          />
          <button
            className="btn btn-ghost py-2 px-4 text-sm border border-[hsl(var(--border))]"
            disabled={!testPayload.payload || testParser.isPending}
            onClick={() => testParser.mutate()}
          >
            {testParser.isPending ? <Loader2 size={14} className="animate-spin" /> : <FlaskConical size={14} />}
            Analizza
          </button>
          {testResult && (
            <div className="text-xs space-y-1">
              <div className="flex items-center gap-2">
                {testResult.events?.length
                  ? <CheckCircle2 size={14} className="text-emerald-400" />
                  : <AlertTriangle size={14} className="text-yellow-400" />}
                <span className="text-white">
                  parser: {testResult.parser || 'none'} · events: {testResult.events?.length ?? 0}
                  {testResult.unparsed ? ` · unrecognized: ${testResult.unparsed}` : ''}
                </span>
              </div>
              {testResult.errors?.length > 0 && (
                <div className="text-yellow-400 font-mono">{testResult.errors.join(' | ')}</div>
              )}
              <pre className="bg-[hsl(var(--secondary))] p-2 rounded max-h-40 overflow-auto font-mono text-[10px]">
                {JSON.stringify(testResult.events?.[0] ?? testResult, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>

      {/* Coverage detection */}
      <div className="card p-5">
        <h2 className="font-semibold text-white flex items-center gap-2 mb-3">
          <ShieldCheck size={16} className="text-emerald-400" /> Copertura detection
        </h2>
        <div className="grid md:grid-cols-3 gap-4 text-sm">
          <div>
            <div className="text-xs uppercase tracking-wider text-[hsl(var(--muted-foreground))] mb-2">Sigma by level</div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(coverage?.sigma?.by_level || {}).map(([level, count]) => (
                <span key={level} className={cn('px-2 py-0.5 rounded text-[10px] font-bold border', SEVERITY_STYLE[level] || SEVERITY_STYLE.INFO)}>
                  {level}: {count as number}
                </span>
              ))}
            </div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-[hsl(var(--muted-foreground))] mb-2">Correlation</div>
            <div className="text-[hsl(var(--muted-foreground))]">
              threshold: {coverage?.correlation?.by_type?.threshold ?? 0} · sequence: {coverage?.correlation?.by_type?.sequence ?? 0}
            </div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-[hsl(var(--muted-foreground))] mb-2">MITRE coperti</div>
            <div className="text-white">{(coverage?.sigma?.mitre_techniques?.length || 0) + (coverage?.correlation?.mitre_techniques?.length || 0)} tecniche</div>
          </div>
        </div>
        {((coverage?.sigma?.excluded?.length || 0) + (coverage?.correlation?.excluded?.length || 0)) > 0 && (
          <div className="mt-3 text-xs text-yellow-400">
            Excluded rules (not executable): {[...(coverage?.sigma?.excluded || []), ...(coverage?.correlation?.excluded || [])]
              .map((r: any) => `${r.id} (${(r.reason || []).join(', ')})`).join(' · ')}
          </div>
        )}
      </div>

      {/* Tabella sorgenti */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex items-center justify-center gap-3 text-[hsl(var(--muted-foreground))]">
            <Loader2 size={24} className="animate-spin text-emerald-400" /> Loading sources…
          </div>
        ) : sources.length === 0 ? (
          <div className="py-16 text-center text-[hsl(var(--muted-foreground))] italic border border-dashed border-[hsl(var(--border))] rounded-lg m-4">
            <Database size={32} className="mx-auto mb-3 opacity-20 text-emerald-400" />
            No log sources yet. Point rsyslog, Filebeat or
            <code className="mx-1">scripts/winevent-collector.ps1</code> at the ingestion endpoint.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] text-xs uppercase tracking-wider">
                <tr>
                  <th className="p-4 font-medium">Source</th>
                  <th className="p-4 font-medium">Type</th>
                  <th className="p-4 font-medium">Parser</th>
                  <th className="p-4 font-medium">Events</th>
                  <th className="p-4 font-medium">Unparsed</th>
                  <th className="p-4 font-medium">Last event</th>
                  <th className="p-4 font-medium w-full">Last error</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[hsl(var(--border))]">
                {sources.map(src => (
                  <tr key={src.id} className="hover:bg-[hsl(var(--secondary)/50)] transition-colors">
                    <td className="p-4 text-white font-medium">{src.name}</td>
                    <td className="p-4 text-[hsl(var(--muted-foreground))]">{src.source_type}</td>
                    <td className="p-4 font-mono text-xs text-emerald-400">{src.parser}</td>
                    <td className="p-4 text-white">{src.events_total.toLocaleString()}</td>
                    <td className={cn('p-4', src.events_invalid > 0 ? 'text-yellow-400' : 'text-[hsl(var(--muted-foreground))]')}>
                      {src.events_invalid.toLocaleString()}
                    </td>
                    <td className="p-4 text-xs text-[hsl(var(--muted-foreground))] font-mono">{fmt(src.last_event_at)}</td>
                    <td className="p-4 text-xs text-red-400 max-w-md truncate" title={src.last_error || ''}>
                      {src.last_error || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
