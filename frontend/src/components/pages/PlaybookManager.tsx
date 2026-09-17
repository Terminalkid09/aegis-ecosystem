import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Play, Trash2, Plus, Activity, BookOpen, AlertCircle, CheckCircle2, XCircle } from 'lucide-react'
import { playbookAPI } from '@/services/api'
import { PermissionGate } from '@/components/common/PermissionGate'
import { cn } from '@/lib/utils'

const ACTION_TYPES = ['webhook', 'block_ip', 'kill_process', 'isolate_host', 'script']

export default function PlaybookManager() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    name: '', description: '', trigger_severity: '', trigger_event_type: '',
    trigger_process_name: '', is_active: true,
    actions: [{ action_type: 'webhook', target: '', params: '{}', order: 0 }],
  })

  const { data: playbooks = [], isLoading: loadingPlaybooks } = useQuery({
    queryKey: ['playbooks'],
    queryFn: () => playbookAPI.getPlaybooks().then(r => r.data || []),
  })

  const { data: executions = [], isLoading: loadingExecutions } = useQuery({
    queryKey: ['playbook-executions'],
    queryFn: () => playbookAPI.getExecutions({ limit: 20 }).then(r => r.data || []),
    refetchInterval: 10000,
  })

  const createMut = useMutation({
    mutationFn: (payload: any) => playbookAPI.createPlaybook(payload),
    onSuccess: () => {
      setShowForm(false)
      setForm({ name: '', description: '', trigger_severity: '', trigger_event_type: '', trigger_process_name: '', is_active: true, actions: [{ action_type: 'webhook', target: '', params: '{}', order: 0 }] })
      qc.invalidateQueries({ queryKey: ['playbooks'] })
    }
  })

  const deleteMut = useMutation({
    mutationFn: (id: number) => playbookAPI.deletePlaybook(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['playbooks'] })
  })

  const handleCreate = () => {
    try {
      const payload = {
        ...form,
        actions: form.actions.map((a) => ({ ...a, params: JSON.parse(a.params || '{}') })),
      }
      createMut.mutate(payload)
    } catch (err) {
      alert("Invalid JSON in params field")
    }
  }

  const handleDelete = (id: number) => {
    if (confirm('Delete this playbook?')) deleteMut.mutate(id)
  }

  return (
    <div className="space-y-6 animate-slide-in">
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <BookOpen className="text-purple-400" /> SOAR Playbooks
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">Automated incident response and remediation.</p>
        </div>
        <PermissionGate perms={['rules']}>
          <button 
            onClick={() => setShowForm(!showForm)} 
            className={cn("btn btn-primary px-4 py-2", showForm ? "bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--secondary)/0.8)] border-[hsl(var(--border))]" : "bg-purple-600 hover:bg-purple-500 border-purple-500 shadow-purple-500/20 text-white")}
          >
            {showForm ? 'Cancel' : <><Plus size={16} /> New Playbook</>}
          </button>
        </PermissionGate>
      </div>

      {showForm && (
        <div className="card p-6 animate-fade-in shadow-xl">
          <h3 className="text-sm font-black uppercase tracking-widest text-cyan-400 mb-5">Create Playbook</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Name</label>
              <input className="input" placeholder="Block Malicious IP" value={form.name} onChange={(e) => setForm({...form, name: e.target.value})} />
            </div>
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Severity Trigger</label>
              <input className="input" placeholder="HIGH, CRITICAL" value={form.trigger_severity} onChange={(e) => setForm({...form, trigger_severity: e.target.value})} />
            </div>
            <div className="space-y-1 md:col-span-2">
              <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Description</label>
              <input className="input" placeholder="Blocks IP addresses on firewall..." value={form.description} onChange={(e) => setForm({...form, description: e.target.value})} />
            </div>
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Event Type Trigger</label>
              <input className="input" placeholder="custom_rule, network_conn" value={form.trigger_event_type} onChange={(e) => setForm({...form, trigger_event_type: e.target.value})} />
            </div>
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Process Trigger</label>
              <input className="input" placeholder="cmd.exe, powershell.exe" value={form.trigger_process_name} onChange={(e) => setForm({...form, trigger_process_name: e.target.value})} />
            </div>
          </div>
          
          <div className="mt-6 border-t border-[hsl(var(--border))] pt-4">
            <div className="flex items-center justify-between mb-3">
              <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Actions Sequence</label>
              <button onClick={() => setForm({...form, actions: [...form.actions, { action_type: 'webhook', target: '', params: '{}', order: form.actions.length }]})} className="text-[10px] text-cyan-400 uppercase font-bold hover:text-cyan-300 transition-colors">+ Add Action</button>
            </div>
            
            <div className="space-y-3">
              {form.actions.map((a, i) => (
                <div key={i} className="flex flex-wrap md:flex-nowrap gap-2 items-start bg-[hsl(var(--secondary))] p-3 rounded-lg border border-[hsl(var(--border))]">
                  <span className="flex items-center justify-center w-6 h-6 rounded-full bg-[hsl(var(--background))] border border-[hsl(var(--border))] text-xs font-mono text-[hsl(var(--muted-foreground))] shrink-0 mt-1">{i + 1}</span>
                  <div className="flex-1 space-y-2 min-w-[200px]">
                    <select className="input text-xs" value={a.action_type} onChange={(e) => {
                      const newActions = [...form.actions]; newActions[i].action_type = e.target.value; setForm({...form, actions: newActions})
                    }}>
                      {ACTION_TYPES.map((t) => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
                    </select>
                    <input className="input text-xs" placeholder="Target (URL, IP, etc)" value={a.target} onChange={(e) => {
                      const newActions = [...form.actions]; newActions[i].target = e.target.value; setForm({...form, actions: newActions})
                    }} />
                  </div>
                  <div className="flex-1 min-w-[200px]">
                    <textarea className="input text-xs h-[88px] font-mono resize-none" placeholder='{"key": "value"}' value={a.params} onChange={(e) => {
                      const newActions = [...form.actions]; newActions[i].params = e.target.value; setForm({...form, actions: newActions})
                    }} />
                  </div>
                  {form.actions.length > 1 && (
                    <button onClick={() => {
                      const newActions = form.actions.filter((_, idx) => idx !== i)
                      setForm({...form, actions: newActions.map((act, idx) => ({...act, order: idx}))})
                    }} className="p-2 text-[hsl(var(--muted-foreground))] hover:text-red-400 transition-colors mt-1">
                      <Trash2 size={16} />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
          
          <button onClick={handleCreate} disabled={createMut.isPending} className="btn btn-primary bg-cyan-600 hover:bg-cyan-500 w-full mt-6 py-2.5 shadow-cyan-500/20">
            {createMut.isPending ? 'Creating...' : 'Deploy Playbook'}
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 card p-5 h-fit">
          <h3 className="text-xs font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))] mb-4 flex items-center gap-2">
            <Play size={14} className="text-cyan-400" /> Active Playbooks ({playbooks.length})
          </h3>
          
          {loadingPlaybooks ? (
            <div className="py-10 text-center text-[hsl(var(--muted-foreground))] italic">Loading playbooks...</div>
          ) : playbooks.length === 0 ? (
            <div className="py-10 text-center text-[hsl(var(--muted-foreground))] italic border border-dashed border-[hsl(var(--border))] rounded-lg">No playbooks configured.</div>
          ) : (
            <div className="space-y-4">
              {playbooks.map((p: any) => (
                <div key={p.id} className="bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] rounded-xl p-5 hover:border-[hsl(var(--primary)/0.3)] transition-colors group">
                  <div className="flex justify-between items-start mb-3">
                    <div>
                      <div className="flex items-center gap-3 mb-1">
                        <span className="font-bold text-white text-base">{p.name}</span>
                        <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest', p.is_active ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-slate-500/10 text-slate-400 border border-slate-500/20')}>{p.is_active ? 'Active' : 'Inactive'}</span>
                      </div>
                      {p.description && <p className="text-sm text-[hsl(var(--muted-foreground))]">{p.description}</p>}
                    </div>
                    <PermissionGate perms={['rules']}>
                      <button onClick={() => handleDelete(p.id)} className="text-[hsl(var(--muted-foreground))] hover:text-red-400 opacity-0 group-hover:opacity-100 transition-opacity p-2 rounded hover:bg-red-500/10"><Trash2 size={16} /></button>
                    </PermissionGate>
                  </div>
                  
                  <div className="flex flex-wrap gap-2 mt-4">
                    {p.trigger_severity && <span className="text-[10px] bg-[hsl(var(--background))] border border-[hsl(var(--border))] px-2 py-1 rounded-md text-[hsl(var(--muted-foreground))]">Severity: <span className="font-bold text-white">{p.trigger_severity}</span></span>}
                    {p.trigger_event_type && <span className="text-[10px] bg-[hsl(var(--background))] border border-[hsl(var(--border))] px-2 py-1 rounded-md text-[hsl(var(--muted-foreground))]">Event: <span className="font-bold text-white">{p.trigger_event_type}</span></span>}
                    {p.trigger_process_name && <span className="text-[10px] bg-[hsl(var(--background))] border border-[hsl(var(--border))] px-2 py-1 rounded-md text-[hsl(var(--muted-foreground))]">Process: <span className="font-bold text-white">{p.trigger_process_name}</span></span>}
                  </div>
                  
                  {p.actions && p.actions.length > 0 && (
                    <div className="mt-4 pt-4 border-t border-[hsl(var(--border))]">
                      <div className="text-[10px] uppercase font-bold text-[hsl(var(--muted-foreground))] mb-2">Execution Flow</div>
                      <div className="flex flex-wrap gap-2 items-center text-xs">
                        {p.actions.map((a: any, i: number) => (
                          <div key={a.id || i} className="flex items-center">
                            <div className="bg-[hsl(var(--background))] border border-cyan-500/20 px-2.5 py-1.5 rounded-md flex items-center gap-2 text-cyan-400">
                              <span className="font-bold">{a.action_type}</span>
                              <span className="text-[hsl(var(--muted-foreground))] truncate max-w-[150px]">{a.target}</span>
                            </div>
                            {i < p.actions.length - 1 && <span className="mx-2 text-[hsl(var(--muted-foreground))]">→</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card p-5 h-fit">
          <h3 className="text-xs font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))] mb-4 flex items-center gap-2">
            <Activity size={14} className="text-purple-400" /> Recent Executions
          </h3>
          
          {loadingExecutions ? (
            <div className="py-10 text-center text-[hsl(var(--muted-foreground))] italic">Loading executions...</div>
          ) : executions.length === 0 ? (
            <div className="py-10 text-center text-[hsl(var(--muted-foreground))] italic border border-dashed border-[hsl(var(--border))] rounded-lg">No executions yet.</div>
          ) : (
            <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2">
              {executions.map((e: any) => (
                <div key={e.id} className="flex flex-col gap-2 bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] rounded-lg p-3">
                  <div className="flex justify-between items-start">
                    <div className="font-mono text-xs text-white">Playbook #{e.playbook_id}</div>
                    <div className="flex items-center gap-1.5">
                      {e.status === 'completed' ? <CheckCircle2 size={12} className="text-emerald-400" /> : e.status === 'failed' ? <XCircle size={12} className="text-red-400" /> : <AlertCircle size={12} className="text-yellow-400" />}
                      <span className={cn('uppercase text-[9px] font-bold tracking-widest', 
                        e.status === 'completed' ? 'text-emerald-400' :
                        e.status === 'failed' ? 'text-red-400' : 'text-yellow-400'
                      )}>{e.status}</span>
                    </div>
                  </div>
                  {e.alert_id && <div className="text-[10px] text-[hsl(var(--muted-foreground))]">Triggered by Alert <span className="font-mono text-white">#{e.alert_id}</span></div>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
