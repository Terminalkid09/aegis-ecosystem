import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, RefreshCcw, Loader2 } from 'lucide-react'
import { syslogAPI } from '@/services/api'
import { cn } from '@/lib/utils'

const SEVERITY_LABELS: Record<number, string> = { 0:'Emerg', 1:'Alert', 2:'Crit', 3:'Error', 4:'Warn', 5:'Notice', 6:'Info', 7:'Debug' }

export default function SyslogViewer() {
  const qc = useQueryClient()

  const { data: events = [], isLoading } = useQuery({
    queryKey: ['syslog-events'],
    queryFn: () => syslogAPI.getEvents({ limit: 200 }).then(r => r.data || []),
    refetchInterval: 15000,
  })

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <Activity className="text-purple-400" /> Syslog Events
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">Centralized network telemetry via UDP 1514.</p>
        </div>
        <button 
          onClick={() => qc.invalidateQueries({ queryKey: ['syslog-events'] })}
          disabled={isLoading}
          className="btn btn-ghost py-1.5 px-3 border border-[hsl(var(--border))]"
        >
          {isLoading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCcw size={14} />}
          Refresh
        </button>
      </div>

      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex flex-col items-center justify-center text-[hsl(var(--muted-foreground))] italic gap-4">
            <Loader2 size={32} className="animate-spin text-purple-400" />
            Loading syslog events...
          </div>
        ) : events.length === 0 ? (
          <div className="py-16 text-center text-[hsl(var(--muted-foreground))] italic border border-dashed border-[hsl(var(--border))] rounded-lg m-4 bg-[hsl(var(--secondary)/0.5)]">
            <Activity size={32} className="mx-auto mb-3 opacity-20 text-purple-400" />
            No syslog events received yet. Ensure aegis-link is forwarding syslog on UDP 1514.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] text-xs uppercase tracking-wider">
                <tr>
                  <th className="p-4 font-medium">Timestamp</th>
                  <th className="p-4 font-medium">Severity</th>
                  <th className="p-4 font-medium">Hostname</th>
                  <th className="p-4 font-medium">App</th>
                  <th className="p-4 font-medium w-full">Message</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[hsl(var(--border))]">
                {events.map((e: any) => (
                  <tr key={e.id} className="hover:bg-[hsl(var(--secondary)/50)] transition-colors">
                    <td className="p-4 text-xs text-[hsl(var(--muted-foreground))] font-mono">
                      {new Date(e.timestamp).toLocaleString()}
                    </td>
                    <td className="p-4">
                      <span className={cn(
                        'px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-widest border',
                        e.severity <= 1 ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                        e.severity <= 3 ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                        e.severity <= 5 ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' :
                        'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]'
                      )}>
                        {SEVERITY_LABELS[e.severity] || e.severity}
                      </span>
                    </td>
                    <td className="p-4 text-white font-medium">
                      {e.hostname || '-'}
                    </td>
                    <td className="p-4 text-slate-300">
                      {e.app_name || '-'}
                    </td>
                    <td className="p-4 text-[hsl(var(--muted-foreground))] text-xs font-mono max-w-xl truncate" title={e.message}>
                      {e.message}
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
