import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download, Loader2, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { detectionsAPI } from '@/services/api'
import { cn } from '@/lib/utils'

type Rule = { id: string; title: string; engine: string }
type Technique = {
  technique_id: string
  technique: string
  tactic: string
  platforms: string[]
  rules: Rule[]
  covered: boolean
}

export default function AttackCoverage() {
  const [platform, setPlatform] = useState('all')
  const { data, isLoading, isError } = useQuery({
    queryKey: ['attack-coverage', platform],
    queryFn: () => detectionsAPI.coverage(platform === 'all' ? undefined : platform).then((r) => r.data),
  })
  const items: Technique[] = data?.items || []
  const covered = useMemo(() => items.filter((item) => item.covered).length, [items])

  function exportJson() {
    const blob = new Blob([JSON.stringify(data || {}, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `aegis-attack-coverage-${platform}.json`
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <ShieldCheck className="text-emerald-400" /> ATT&amp;CK Coverage
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">
            The matrix is generated from the same Sigma, correlation and built-in engines that create alerts.
            Missing techniques stay visible.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select className="input w-44" value={platform} onChange={(event) => setPlatform(event.target.value)}>
            {(data?.platforms || ['all']).map((value: string) => (
              <option key={value} value={value}>{value === 'all' ? 'All platforms' : value}</option>
            ))}
          </select>
          <button onClick={exportJson} className="btn btn-ghost py-1.5 px-3 border border-[hsl(var(--border))]">
            <Download size={14} /> Export JSON
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="card p-4"><p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Techniques covered</p><p className="text-3xl font-bold text-emerald-400 mt-1">{covered}</p></div>
        <div className="card p-4"><p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Visible gaps</p><p className="text-3xl font-bold text-yellow-400 mt-1">{items.length - covered}</p></div>
        <div className="card p-4"><p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Rules represented</p><p className="text-3xl font-bold text-white mt-1">{data?.rules_total ?? 0}</p></div>
        <div className="card p-4"><p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Sigma executable</p><p className="text-3xl font-bold text-cyan-400 mt-1">{data?.engines?.sigma?.rules_executable ?? 0}</p></div>
      </div>

      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex items-center justify-center gap-2 text-[hsl(var(--muted-foreground))]"><Loader2 className="animate-spin" size={18} /> Building matrix…</div>
        ) : isError ? (
          <div className="p-6 text-sm text-red-300">Coverage endpoint unavailable.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-[hsl(var(--secondary))] text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">
                <tr><th className="p-3 text-left">Technique</th><th className="p-3 text-left">Tactic</th><th className="p-3 text-left">Platforms</th><th className="p-3 text-left">Rules</th><th className="p-3 text-left">Status</th></tr>
              </thead>
              <tbody className="divide-y divide-[hsl(var(--border))]">
                {items.map((item) => (
                  <tr key={item.technique_id} className="hover:bg-[hsl(var(--secondary)/0.4)]">
                    <td className="p-3"><span className="font-mono text-xs text-cyan-400">{item.technique_id}</span><span className="block text-white">{item.technique}</span></td>
                    <td className="p-3 text-xs text-[hsl(var(--muted-foreground))]">{item.tactic}</td>
                    <td className="p-3 text-xs text-[hsl(var(--muted-foreground))]">{item.platforms.join(', ')}</td>
                    <td className="p-3 text-xs">{item.rules.length > 0 ? item.rules.map((rule) => <div key={`${rule.engine}-${rule.id}`} className="truncate" title={rule.title}>{rule.id} · {rule.title}</div>) : '—'}</td>
                    <td className="p-3">
                      <span className={cn('inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase', item.covered ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' : 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400')}>
                        {item.covered ? <ShieldCheck size={10} /> : <ShieldQuestion size={10} />}
                        {item.covered ? 'covered' : 'gap'}
                      </span>
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
