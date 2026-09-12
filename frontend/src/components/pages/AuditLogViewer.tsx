import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ClipboardList, RefreshCcw, Loader2 } from 'lucide-react'
import { auditAPI } from '@/services/api'
import { cn } from '@/lib/utils'

export default function AuditLogViewer() {
  const qc = useQueryClient()

  const { data: logs = [], isLoading } = useQuery({
    queryKey: ['audit-logs'],
    queryFn: () => auditAPI.getLogs({ limit: 200 }).then(r => r.data || []),
  })

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <ClipboardList className="text-cyan-400" /> Audit Log
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">Immutable record of system and user actions.</p>
        </div>
        <button 
          onClick={() => qc.invalidateQueries({ queryKey: ['audit-logs'] })}
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
            <Loader2 size={32} className="animate-spin text-cyan-400" />
            Loading audit logs...
          </div>
        ) : logs.length === 0 ? (
          <div className="py-16 text-center text-[hsl(var(--muted-foreground))] italic border border-dashed border-[hsl(var(--border))] rounded-lg m-4 bg-[hsl(var(--secondary)/0.5)]">
            <ClipboardList size={32} className="mx-auto mb-3 opacity-20 text-cyan-400" />
            No audit log entries yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] text-xs uppercase tracking-wider">
                <tr>
                  <th className="p-4 font-medium">Time</th>
                  <th className="p-4 font-medium">User</th>
                  <th className="p-4 font-medium">Action</th>
                  <th className="p-4 font-medium">Resource</th>
                  <th className="p-4 font-medium w-full">Details</th>
                  <th className="p-4 font-medium">IP Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[hsl(var(--border))]">
                {logs.map((l: any) => (
                  <tr key={l.id} className="hover:bg-[hsl(var(--secondary)/50)] transition-colors">
                    <td className="p-4 text-xs text-[hsl(var(--muted-foreground))] font-mono">
                      {new Date(l.created_at).toLocaleString()}
                    </td>
                    <td className="p-4 text-white font-medium">
                      {l.username || 'system'}
                    </td>
                    <td className="p-4">
                      <span className={cn(
                        "px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-widest border",
                        l.action.includes('delete') || l.action.includes('remove') ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                        l.action.includes('create') || l.action.includes('add') ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                        l.action.includes('login') || l.action.includes('auth') ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' :
                        'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'
                      )}>
                        {l.action}
                      </span>
                    </td>
                    <td className="p-4 text-slate-300">
                      {l.resource}
                      {l.resource_id && <span className="text-[hsl(var(--muted-foreground))] font-mono text-xs ml-1">#{l.resource_id}</span>}
                    </td>
                    <td className="p-4 text-[hsl(var(--muted-foreground))] text-xs font-mono max-w-md truncate">
                      {l.details ? JSON.stringify(l.details) : '-'}
                    </td>
                    <td className="p-4 text-xs text-[hsl(var(--muted-foreground))] font-mono">
                      {l.ip_address || '-'}
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
