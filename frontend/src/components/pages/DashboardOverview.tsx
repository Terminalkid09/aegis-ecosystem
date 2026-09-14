import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  AlertTriangle, Shield, Activity, TrendingUp,
  Cpu, HardDrive, Monitor, CheckCircle2,
} from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import { statsAPI, incidentsAPI, healthAPI } from '@/services/api'
import { useAppStore } from '@/store/appStore'
import { cn, formatDisk, timeAgo, asArray } from '@/lib/utils'

export default function DashboardOverview() {
  const { liveStats } = useAppStore()

  const { data: statsData } = useQuery({
    queryKey: ['stats'],
    queryFn: () => statsAPI.getStats().then(r => r.data),
    refetchInterval: 30000,
  })

  const { data: telemetry = [] } = useQuery({
    queryKey: ['telemetry-recent'],
    // Audit schermo-nero: asArray, mai `|| []` (un oggetto truthy non-array
    // crashava i .filter a valle).
    queryFn: () => statsAPI.getRecentTelemetry({ limit: 60 }).then(r => asArray(r.data)),
    refetchInterval: 15000,
  })

  const { data: activity = [] } = useQuery({
    queryKey: ['activity'],
    queryFn: () => statsAPI.getActivity({ limit: 15 }).then(r => asArray(r.data)),
    refetchInterval: 15000,
  })

  const { data: agents = [] } = useQuery({
    queryKey: ['agents-overview'],
    queryFn: () => statsAPI.getAgents({ limit: 200 }).then(r => asArray(r.data)),
    refetchInterval: 30000,
  })

  const { data: incidentsData } = useQuery({
    queryKey: ['incidents-overview'],
    queryFn: () => incidentsAPI.list({}).then(r => r.data),
    refetchInterval: 30000,
  })

  const { data: healthData } = useQuery({
    queryKey: ['pipeline-health'],
    // Audit F4+E2E: /health/ready al root via healthAPI (l'URL /api/v1/...
    // non esiste sul brain e dava 404 -> strip sempre "unknown").
    queryFn: () => healthAPI.ready().then(r => r.data).catch(() => null),
    refetchInterval: 20000,
  })

  // Merge WS live data with REST stats
  const stats = useMemo(() => ({ ...statsData, ...liveStats }), [statsData, liveStats])

  const threatLevel = useMemo(() => {
    const critical = stats?.current_critical_alerts ?? 0
    const high = stats?.current_high_alerts ?? 0
    const medium = stats?.current_medium_alerts ?? 0
    const unresolved = stats?.unresolved_alerts ?? 0
    if (critical > 0) return { label: 'CRITICAL', color: 'text-red-400', glow: 'shadow-red-500/20', bg: 'from-red-950/60 to-red-900/20 border-red-800/40' }
    if (high > 2 || unresolved > 20) return { label: 'WARNING', color: 'text-orange-400', glow: 'shadow-orange-500/20', bg: 'from-orange-950/60 to-orange-900/20 border-orange-800/40' }
    if (high > 0 || medium > 5 || unresolved > 5) return { label: 'ELEVATED', color: 'text-yellow-400', glow: 'shadow-yellow-500/20', bg: 'from-yellow-950/60 to-yellow-900/20 border-yellow-800/40' }
    if (unresolved > 0) return { label: 'GUARDED', color: 'text-blue-400', glow: 'shadow-blue-500/20', bg: 'from-blue-950/60 to-blue-900/20 border-blue-800/40' }
    return { label: 'NORMAL', color: 'text-emerald-400', glow: 'shadow-emerald-500/20', bg: 'from-emerald-950/60 to-emerald-900/20 border-emerald-800/40' }
  }, [stats])

  const chartData = useMemo(() =>
    (telemetry as any[])
      .filter(t => t.cpu_usage !== null && t.ram_usage !== null)
      .map(t => ({
        time: new Date(t.timestamp).getTime(),
        timeLabel: new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        cpu: Number(t.cpu_usage ?? 0).toFixed(1),
        ram: Number(t.ram_usage ?? 0).toFixed(1),
        host: t.hostname || t.agent_id,
      }))
      .sort((a, b) => a.time - b.time)
      .slice(-40),
    [telemetry]
  )

  const incidents = (incidentsData as any)?.items ?? (Array.isArray(incidentsData) ? incidentsData : [])
  const degradedCount = (agents as any[]).filter((a: any) => a.status === 'stale' || a.status === 'offline' || (a.quality && String(a.quality).startsWith('degraded'))).length
  const eventsLost = (stats?.events_seq_gaps ?? 0) + (stats?.events_duplicated ?? 0)

  const healthItems = useMemo(() => {
    const checks = (healthData as any)?.checks ?? {}
    const order = ['database', 'redis', 'pipeline', 'pki', 'mtls']
    return order.map((name) => {
      const c = checks[name]
      const status = c?.status ?? (healthData ? 'unknown' : 'unreachable')
      const color = status === 'healthy' ? 'text-emerald-400' : status === 'degraded' ? 'text-yellow-400' : 'text-red-400'
      return { name, status, color }
    })
  }, [healthData])
  const riskBySite = useMemo(() => {
    const m: Record<string, number> = {}
    ;(agents as any[]).forEach((a: any) => {
      const s = a.site || 'default'
      if (a.status === 'offline' || a.isolated) m[s] = (m[s] || 0) + 3
      else if (a.status === 'stale') m[s] = (m[s] || 0) + 1
    })
    ;(incidents as any[]).forEach((inc: any) => {
      if (inc.status === 'open' || inc.status === 'investigating') {
        const s = inc.agent_id ? ((agents as any[]).find((a: any) => a.agent_id === inc.agent_id)?.site || 'default') : 'default'
        m[s] = (m[s] || 0) + (inc.severity === 'CRITICAL' ? 5 : inc.severity === 'HIGH' ? 3 : 1)
      }
    })
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 5)
  }, [agents, incidents])

  const STAT_CARDS = [
    { label: 'Total Alerts',    value: stats?.total_alerts ?? 0,            icon: AlertTriangle, gradient: 'from-red-500 to-rose-600',    text: 'text-red-400' },
    { label: 'Unresolved',      value: stats?.unresolved_alerts ?? 0,        icon: Shield,        gradient: 'from-orange-500 to-amber-600', text: 'text-orange-400' },
    { label: 'Active Agents',   value: stats?.active_agents ?? 0,            icon: Monitor,       gradient: 'from-emerald-500 to-teal-600', text: 'text-emerald-400' },
    { label: 'Critical Threats',value: stats?.current_critical_alerts ?? 0,  icon: TrendingUp,    gradient: 'from-purple-500 to-violet-600',text: 'text-purple-400' },
  ]

  return (
    <div className="space-y-6 animate-slide-in">
      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">Real-time threat monitoring</p>
        </div>
        {liveStats && (
          <div className="flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-400/10 border border-emerald-400/20 px-2.5 py-1 rounded-full">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Live
          </div>
        )}
      </div>

      {/* Threat Level */}
      <div className={cn('rounded-xl border bg-gradient-to-br p-6 shadow-lg', threatLevel.bg, threatLevel.glow)}>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-widest text-white/50 mb-2">Threat Level</p>
            <p className={cn('text-5xl font-black tracking-tight', threatLevel.color)}>{threatLevel.label}</p>
          </div>
          <AlertTriangle className={cn('opacity-15', threatLevel.color)} size={72} strokeWidth={1.5} />
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        {STAT_CARDS.map(({ label, value, icon: Icon, gradient, text }) => (
          <div key={label} className="card p-5 hover:border-[hsl(var(--primary)/0.3)] transition-all duration-200 group">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-[hsl(var(--muted-foreground))] mb-2">{label}</p>
                <p className="text-4xl font-bold text-white">{value}</p>
              </div>
              <div className={cn('p-2.5 rounded-lg bg-gradient-to-br opacity-80 group-hover:opacity-100 transition-opacity', gradient)}>
                <Icon size={20} className="text-white" />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* SOC Health Strip */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="card p-3">
          <p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Online / Stale / Offline</p>
          <p className="text-sm font-mono text-white mt-1">{stats?.active_agents ?? 0} / {stats?.stale_agents ?? 0} / {stats?.offline_agents ?? 0}</p>
        </div>
        <div className="card p-3">
          <p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Events lost (gaps)</p>
          <p className="text-sm font-mono text-white mt-1">{eventsLost} · dup {stats?.events_duplicated ?? 0}</p>
        </div>
        <div className="card p-3">
          <p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Sensors degraded</p>
          <p className="text-sm font-mono text-yellow-400 mt-1">{degradedCount}</p>
        </div>
        <div className="card p-3">
          <p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Incidents open</p>
          <p className="text-sm font-mono text-white mt-1">{(incidents as any[]).filter((i: any) => i.status === 'open' || i.status === 'investigating').length}</p>
        </div>
        <div className="card p-3">
          <p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Risk by site</p>
          <div className="text-xs font-mono text-white mt-1 space-y-0.5">
            {riskBySite.length === 0 ? <span className="text-[hsl(var(--muted-foreground))]">—</span> : riskBySite.map(([s, v]) => (
              <div key={s} className="flex justify-between"><span>{s}</span><span className={cn(v > 5 ? 'text-red-400' : v > 2 ? 'text-yellow-400' : 'text-emerald-400')}>{v}</span></div>
            ))}
          </div>
        </div>
      </div>

      {/* Pipeline Health Strip */}
      <div className="card p-3 flex items-center gap-2 flex-wrap">
        <p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))] mr-1">Pipeline</p>
        {healthItems.map(({ name, status, color }) => (
          <span key={name} className={cn('text-xs font-mono px-2 py-0.5 rounded border', {
            'text-emerald-400 border-emerald-400/20 bg-emerald-400/5': status === 'healthy',
            'text-yellow-400 border-yellow-400/20 bg-yellow-400/5': status === 'degraded',
            'text-red-400 border-red-400/20 bg-red-400/5': status === 'unhealthy' || status === 'unreachable',
          })}>
            <span className={cn('w-1.5 h-1.5 rounded-full inline-block mr-1 align-middle', color)} />
            {name}:{status}
          </span>
        ))}
        {!healthData && (
          <span className="text-xs text-[hsl(var(--muted-foreground))] italic">health endpoint unreachable</span>
        )}
      </div>

      {/* Chart */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-5">
          <h3 className="font-semibold text-white">System Performance</h3>
          <div className="flex items-center gap-4 text-xs text-[hsl(var(--muted-foreground))]">
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyan-400 inline-block" />CPU</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-purple-400 inline-block" />RAM</span>
          </div>
        </div>
        <div className="h-64">
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 5, right: 5, bottom: 5, left: 0 }}>
                <defs>
                  <linearGradient id="cpu" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#22d3ee" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="ram" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#a855f7" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#a855f7" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(222 47% 14%)" />
                <XAxis dataKey="timeLabel" tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} axisLine={false} unit="%" domain={[0, 100]} width={32} />
                <Tooltip
                  contentStyle={{ background: 'hsl(222,47%,8%)', border: '1px solid hsl(222,47%,14%)', borderRadius: '8px', fontSize: '12px' }}
                  labelStyle={{ color: '#94a3b8' }}
                  formatter={(v: any) => [`${Number(v).toFixed(1)}%`]}
                />
                <Area type="monotone" dataKey="cpu" stroke="#22d3ee" strokeWidth={2} fill="url(#cpu)" dot={false} name="CPU" />
                <Area type="monotone" dataKey="ram" stroke="#a855f7" strokeWidth={2} fill="url(#ram)" dot={false} name="RAM" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-[hsl(var(--muted-foreground))] text-sm">
              No telemetry data yet — agents will populate this chart.
            </div>
          )}
        </div>
      </div>

      {/* Bottom Grid: Telemetry + Activity */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Live Telemetry */}
        <div className="card p-6">
          <h3 className="font-semibold text-white mb-4 flex items-center gap-2">
            <Cpu size={15} className="text-cyan-400" /> Live Telemetry
          </h3>
          <div className="space-y-2 max-h-72 overflow-y-auto">
            {(telemetry as any[]).slice(0, 12).map((row: any, i: number) => (
              <div key={row.id ?? i} className="flex items-center gap-3 p-2.5 rounded-lg bg-[hsl(var(--secondary))] border border-[hsl(var(--border))]">
                <Monitor size={12} className="text-[hsl(var(--muted-foreground))] shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold text-white truncate">{row.hostname || row.agent_id}</p>
                  <p className="text-[10px] text-[hsl(var(--muted-foreground))] uppercase">{row.agent_type || 'agent'}</p>
                </div>
                <div className="flex items-center gap-2 text-xs shrink-0">
                  <span className="text-cyan-400">{Number(row.cpu_usage ?? 0).toFixed(0)}% CPU</span>
                  <span className="text-purple-400">{Number(row.ram_usage ?? 0).toFixed(0)}% RAM</span>
                  <span className="text-[hsl(var(--muted-foreground))]">{formatDisk(row.disk_free)}</span>
                </div>
              </div>
            ))}
            {telemetry.length === 0 && (
              <p className="text-sm text-[hsl(var(--muted-foreground))] italic">No telemetry received yet.</p>
            )}
          </div>
        </div>

        {/* Activity Stream */}
        <div className="card p-6">
          <h3 className="font-semibold text-white mb-4 flex items-center gap-2">
            <Activity size={15} className="text-purple-400" /> Activity Stream
          </h3>
          <div className="space-y-2 max-h-72 overflow-y-auto">
            {(activity as any[]).map((item: any, index: number) => (
              <div key={`${item.type}-${item.timestamp}-${index}`} className="flex items-start gap-3 p-2.5 rounded-lg bg-[hsl(var(--secondary))] border border-[hsl(var(--border))]">
                <div className={cn('mt-1 w-2 h-2 rounded-full shrink-0', item.type === 'alert' ? 'bg-red-400 animate-pulse' : 'bg-emerald-400')} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-white">{item.summary}</p>
                  <p className="text-[10px] text-[hsl(var(--muted-foreground))] mt-0.5">
                    {item.hostname || item.agent_id} · {timeAgo(item.timestamp)}
                  </p>
                </div>
              </div>
            ))}
            {activity.length === 0 && (
              <p className="text-sm text-[hsl(var(--muted-foreground))] italic">No agent activity yet.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
