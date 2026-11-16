import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Bug, ExternalLink, RefreshCcw, ShieldAlert, Siren, Radio, Globe2,
} from 'lucide-react'
import { deceptionAPI } from '@/services/api'
import { cn, timeAgo } from '@/lib/utils'

type KrakenEvent = {
  id: number
  time?: string | null
  src_ip?: string | null
  process_name?: string | null
  category?: string | null
  message?: string | null
  severity?: string | null
  event_id?: string | null
}

type KrakenAlert = {
  id: number
  timestamp?: string | null
  severity?: string | null
  description?: string | null
  process_name?: string | null
  is_resolved?: boolean
}

type KrakenIncident = {
  id: number
  title: string
  severity?: string | null
  status?: string | null
  updated_at?: string | null
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/20',
  HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  MEDIUM: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  LOW: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  INFO: 'text-slate-400 bg-slate-500/10 border-slate-500/20',
}

function StatCard({
  label, value, hint, icon: Icon, tone,
}: {
  label: string
  value: number | string
  hint: string
  icon: React.ElementType
  tone: string
}) {
  return (
    <div className="card p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[10px] uppercase tracking-widest font-bold text-[hsl(var(--muted-foreground))]">{label}</p>
          <p className={cn('text-3xl font-bold mt-2 tabular-nums', tone)}>{value}</p>
          <p className="text-xs text-[hsl(var(--muted-foreground))] mt-1">{hint}</p>
        </div>
        <div className={cn('p-2 rounded-lg border', tone.replace('text-', 'border-').replace(/ .*/, ''))}>
          <Icon size={18} />
        </div>
      </div>
    </div>
  )
}

export default function Kraken() {
  const [msg, setMsg] = useState('')

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ['kraken-overview'],
    queryFn: () => deceptionAPI.overview(24).then(r => r.data),
    refetchInterval: 30000,
  })

  const stats = data?.stats ?? {}
  const events: KrakenEvent[] = data?.events ?? []
  const alerts: KrakenAlert[] = data?.alerts ?? []
  const incidents: KrakenIncident[] = data?.incidents ?? []

  async function openKraken() {
    setMsg('')
    // Open synchronously so the popup keeps the user gesture; the assertion
    // itself is fetched after, so it never appears in Aegis history/logs.
    const popup = window.open('about:blank', '_blank')
    try {
      const { data: sso } = await deceptionAPI.ssoToken()
      const url = `${sso.sso_url || '/kraken/sso'}#token=${encodeURIComponent(sso.token)}`
      if (popup) {
        popup.opener = null
        popup.location.replace(url)
      } else {
        window.location.assign(url)
      }
    } catch (e: any) {
      popup?.close()
      setMsg(e?.response?.data?.detail || 'Kraken SSO is not available.')
    }
  }

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <Bug className="text-rose-400" /> Kraken Deception
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">
            Read-only correlation of deception events ingested from the separate Kraken service.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="btn btn-ghost py-1.5 px-3 border border-[hsl(var(--border))]"
          >
            <RefreshCcw size={14} /> Refresh
          </button>
          <button
            data-testid="open-kraken"
            onClick={openKraken}
            disabled={data?.sso_enabled === false}
            title={data?.sso_enabled === false ? 'Kraken SSO is not configured' : 'Open the Kraken UI with delegated sign-in'}
            className="btn btn-primary py-1.5 px-3 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <ExternalLink size={14} /> Open Kraken UI
          </button>
        </div>
      </div>

      {msg && (
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
          {msg}
        </div>
      )}

      {isLoading ? (
        <div className="py-16 text-center text-[hsl(var(--muted-foreground))] italic">Loading Kraken correlation…</div>
      ) : isError ? (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-6 text-red-300">
          <p className="font-semibold">Kraken overview is unavailable.</p>
          <p className="text-sm mt-1">The Aegis API did not return the read-only deception view.</p>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4">
            <StatCard label="Events 24h" value={stats.events ?? 0} hint="normalised deception events" icon={Radio} tone="text-cyan-400" />
            <StatCard label="Source IPs" value={stats.unique_source_ips ?? 0} hint="distinct attackers" icon={Globe2} tone="text-blue-400" />
            <StatCard label="Deception alerts" value={stats.deception_alerts ?? 0} hint="in the last 24h" icon={ShieldAlert} tone="text-orange-400" />
            <StatCard label="Open alerts" value={stats.open_deception_alerts ?? 0} hint="unresolved deception alerts" icon={Siren} tone="text-red-400" />
            <StatCard label="Incidents" value={stats.incidents ?? 0} hint="Kraken-linked incidents" icon={Bug} tone="text-purple-400" />
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2 card overflow-hidden">
              <div className="px-4 py-3 border-b border-[hsl(var(--border))] flex items-center justify-between">
                <h2 className="text-sm font-bold text-white flex items-center gap-2"><Radio size={15} className="text-cyan-400" /> Recent deception events</h2>
                <span className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">source: kraken</span>
              </div>
              {events.length === 0 ? (
                <p className="p-8 text-center text-sm text-[hsl(var(--muted-foreground))] italic">No Kraken events ingested in the last 24 hours.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead className="bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] uppercase tracking-widest text-[10px]">
                      <tr>
                        <th className="text-left px-4 py-2 font-bold">Time</th>
                        <th className="text-left px-4 py-2 font-bold">Source IP</th>
                        <th className="text-left px-4 py-2 font-bold">Sensor / process</th>
                        <th className="text-left px-4 py-2 font-bold">Category</th>
                        <th className="text-left px-4 py-2 font-bold">Message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {events.map(e => (
                        <tr key={e.id} className="border-t border-[hsl(var(--border))] hover:bg-[hsl(var(--secondary)/0.4)]">
                          <td className="px-4 py-2.5 font-mono text-[hsl(var(--muted-foreground))] whitespace-nowrap">{e.time ? timeAgo(e.time) : '—'}</td>
                          <td className="px-4 py-2.5 font-mono text-cyan-400 whitespace-nowrap">{e.src_ip || '—'}</td>
                          <td className="px-4 py-2.5 text-slate-300 whitespace-nowrap">{e.process_name || '—'}</td>
                          <td className="px-4 py-2.5 text-slate-400 whitespace-nowrap">{e.category || '—'}</td>
                          <td className="px-4 py-2.5 text-slate-300 max-w-[320px] truncate" title={e.message || ''}>{e.message || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="space-y-6">
              <div className="card">
                <h2 className="text-sm font-bold text-white flex items-center gap-2 mb-3"><ShieldAlert size={15} className="text-orange-400" /> Linked alerts</h2>
                {alerts.length === 0 ? (
                  <p className="text-xs text-[hsl(var(--muted-foreground))] italic">No deception alerts in the last 24 hours.</p>
                ) : (
                  <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                    {alerts.map(a => (
                      <div key={a.id} className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] p-2.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className={cn('text-[9px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded border', SEVERITY_COLOR[a.severity || 'INFO'] || SEVERITY_COLOR.INFO)}>{a.severity || 'INFO'}</span>
                          <span className="text-[10px] font-mono text-[hsl(var(--muted-foreground))]">{a.timestamp ? timeAgo(a.timestamp) : '—'}</span>
                        </div>
                        <p className="text-xs text-slate-300 mt-1.5 line-clamp-3">{a.description || a.process_name || 'Deception alert'}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="card">
                <h2 className="text-sm font-bold text-white flex items-center gap-2 mb-3"><Siren size={15} className="text-red-400" /> Kraken incidents</h2>
                {incidents.length === 0 ? (
                  <p className="text-xs text-[hsl(var(--muted-foreground))] italic">No Kraken incidents.</p>
                ) : (
                  <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                    {incidents.map(i => (
                      <div key={i.id} className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] p-2.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[10px] font-mono text-cyan-400">#{i.id}</span>
                          <span className="text-[9px] font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))]">{i.status}</span>
                        </div>
                        <p className="text-xs text-slate-200 mt-1 line-clamp-2">{i.title}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          <p className="text-[11px] text-[hsl(var(--muted-foreground))]">
            Operational Kraken data (sessions, credentials, sensors, sandbox) stays in the Kraken UI. This page never
            exposes credentials and provides no write action against Kraken.
          </p>
        </>
      )}
    </div>
  )
}
