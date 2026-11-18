import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CalendarClock, Loader2, ShieldOff, Trash2 } from 'lucide-react'
import { suppressionsAPI } from '@/services/api'
import { cn } from '@/lib/utils'

type Suppression = {
  id: number
  rule_id: string
  scope: Record<string, unknown>
  reason: string
  expires_at: string
  state: string
  suppressed_count: number
  last_suppressed_at: string | null
}

export default function Suppressions() {
  const queryClient = useQueryClient()
  const [ruleId, setRuleId] = useState('')
  const [hostname, setHostname] = useState('')
  const [reason, setReason] = useState('')
  const [hours, setHours] = useState(24)
  const [error, setError] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['suppressions'],
    queryFn: () => suppressionsAPI.list().then((r) => r.data),
  })
  const items: Suppression[] = data?.items || []

  const create = useMutation({
    mutationFn: () => suppressionsAPI.create({
      rule_id: ruleId.trim(),
      reason: reason.trim(),
      expires_at: new Date(Date.now() + hours * 3600_000).toISOString(),
      scope: hostname.trim() ? { hostname: hostname.trim() } : {},
    }),
    onSuccess: () => {
      setRuleId(''); setHostname(''); setReason(''); setError('')
      queryClient.invalidateQueries({ queryKey: ['suppressions'] })
    },
    onError: (err: any) => setError(err?.response?.data?.detail || 'Could not create suppression'),
  })
  const revoke = useMutation({
    mutationFn: (id: number) => suppressionsAPI.revoke(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['suppressions'] }),
  })

  return (
    <div className="space-y-6 animate-slide-in">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2 text-white"><ShieldOff className="text-orange-400" /> Governed Suppressions</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">A suppression needs a reason and expires within 90 days. The rule stays enabled and every hidden alert is counted.</p>
      </div>

      <div className="card p-5 space-y-3">
        <h2 className="font-semibold text-white">New suppression</h2>
        <div className="grid md:grid-cols-4 gap-3">
          <input className="input" placeholder="Rule ID" value={ruleId} onChange={(e) => setRuleId(e.target.value)} />
          <input className="input" placeholder="Hostname (optional scope)" value={hostname} onChange={(e) => setHostname(e.target.value)} />
          <input className="input" type="number" min={1} max={2160} value={hours} onChange={(e) => setHours(Number(e.target.value))} title="TTL hours" />
          <button className="btn btn-primary" disabled={!ruleId.trim() || reason.trim().length < 8 || create.isPending} onClick={() => create.mutate()}>
            {create.isPending ? <Loader2 className="animate-spin" size={14} /> : <CalendarClock size={14} />} Create
          </button>
        </div>
        <input className="input w-full" placeholder="Reason (at least 8 characters)" value={reason} onChange={(e) => setReason(e.target.value)} />
        {error && <p className="text-xs text-red-400">{error}</p>}
      </div>

      <div className="card overflow-hidden">
        {isLoading ? <div className="p-10 text-center text-sm text-[hsl(var(--muted-foreground))]">Loading…</div> : items.length === 0 ? (
          <div className="p-10 text-center text-sm text-[hsl(var(--muted-foreground))] italic">No active suppressions.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-[hsl(var(--secondary))] text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">
              <tr><th className="p-3 text-left">Rule</th><th className="p-3 text-left">Scope</th><th className="p-3 text-left">Reason</th><th className="p-3 text-left">Expires</th><th className="p-3 text-left">Hidden</th><th className="p-3" /></tr>
            </thead>
            <tbody className="divide-y divide-[hsl(var(--border))]">
              {items.map((item) => (
                <tr key={item.id}>
                  <td className="p-3 font-mono text-xs text-cyan-400">{item.rule_id}</td>
                  <td className="p-3 text-xs text-[hsl(var(--muted-foreground))]">{Object.entries(item.scope).map(([k, v]) => `${k}=${String(v)}`).join(', ') || 'global'}</td>
                  <td className="p-3 text-xs">{item.reason}</td>
                  <td className="p-3 text-xs"><span className={cn(item.state === 'active' ? 'text-emerald-400' : 'text-yellow-400')}>{new Date(item.expires_at).toLocaleString()}</span></td>
                  <td className="p-3 font-mono text-xs">{item.suppressed_count}</td>
                  <td className="p-3 text-right"><button className="text-red-400 hover:text-red-300" title="Revoke" onClick={() => revoke.mutate(item.id)}><Trash2 size={14} /></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
