import React, { useState, useEffect } from 'react';
import { playbookAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';
import { Play, Trash2, Plus, Activity } from 'lucide-react';

export default function PlaybookManager() {
  const { settings } = useDashboard();
  const [playbooks, setPlaybooks] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({
    name: '', description: '', trigger_severity: '', trigger_event_type: '',
    trigger_process_name: '', is_active: true,
    actions: [{ action_type: 'webhook', target: '', params: '{}', order: 0 }],
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [pRes, eRes] = await Promise.all([
        playbookAPI.getPlaybooks(),
        playbookAPI.getExecutions({ limit: 20 }),
      ]);
      setPlaybooks(pRes.data || []);
      setExecutions(eRes.data || []);
    } catch (err) {
      console.error('Failed to fetch playbooks:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    try {
      const payload = {
        ...form,
        actions: form.actions.map((a) => ({ ...a, params: JSON.parse(a.params || '{}') })),
      };
      await playbookAPI.createPlaybook(payload);
      setShowForm(false);
      setForm({ name: '', description: '', trigger_severity: '', trigger_event_type: '', trigger_process_name: '', is_active: true, actions: [{ action_type: 'webhook', target: '', params: '{}', order: 0 }] });
      fetchData();
    } catch (err) {
      console.error('Create playbook failed:', err);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this playbook?')) return;
    try {
      await playbookAPI.deletePlaybook(id);
      fetchData();
    } catch (err) {
      console.error('Delete failed:', err);
    }
  };

  const ACTION_TYPES = ['webhook', 'block_ip', 'kill_process', 'isolate_host', 'script'];

  if (loading) return <div className="text-slate-500 italic">Loading playbooks...</div>;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">SOAR Playbooks</h2>
        <button onClick={() => setShowForm(!showForm)} className="text-xs bg-cyan-700 hover:bg-cyan-600 px-3 py-1.5 rounded font-bold flex items-center gap-1">
          <Plus size={14} /> {showForm ? 'Cancel' : 'New Playbook'}
        </button>
      </div>

      {showForm && (
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 space-y-4">
          <h3 className="text-lg font-bold text-cyan-400">Create Playbook</h3>
          <div className="grid grid-cols-2 gap-4">
            <input className="input-base" placeholder="Playbook name" value={form.name} onChange={(e) => setForm({...form, name: e.target.value})} />
            <input className="input-base" placeholder="Trigger severity (HIGH, MEDIUM, etc)" value={form.trigger_severity} onChange={(e) => setForm({...form, trigger_severity: e.target.value})} />
            <input className="input-base col-span-2" placeholder="Description" value={form.description} onChange={(e) => setForm({...form, description: e.target.value})} />
            <input className="input-base" placeholder="Trigger event type (custom_rule, PROCESS_CREATED)" value={form.trigger_event_type} onChange={(e) => setForm({...form, trigger_event_type: e.target.value})} />
            <input className="input-base" placeholder="Trigger process name (optional)" value={form.trigger_process_name} onChange={(e) => setForm({...form, trigger_process_name: e.target.value})} />
          </div>
          <div>
            <label className="text-xs text-slate-400">Actions:</label>
            {form.actions.map((a, i) => (
              <div key={i} className="flex gap-2 mt-2">
                <select className="input-base w-40" value={a.action_type} onChange={(e) => {
                  const newActions = [...form.actions];
                  newActions[i].action_type = e.target.value;
                  setForm({...form, actions: newActions});
                }}>
                  {ACTION_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
                <input className="input-base flex-1" placeholder="Target (URL for webhook, IP for block_ip)" value={a.target} onChange={(e) => {
                  const newActions = [...form.actions];
                  newActions[i].target = e.target.value;
                  setForm({...form, actions: newActions});
                }} />
                <input className="input-base w-40" placeholder='JSON params' value={a.params} onChange={(e) => {
                  const newActions = [...form.actions];
                  newActions[i].params = e.target.value;
                  setForm({...form, actions: newActions});
                }} />
              </div>
            ))}
            <button onClick={() => setForm({...form, actions: [...form.actions, { action_type: 'webhook', target: '', params: '{}', order: form.actions.length }]})} className="text-xs text-cyan-400 mt-2">+ Add Action</button>
          </div>
          <button onClick={handleCreate} className="bg-cyan-700 hover:bg-cyan-600 px-4 py-2 rounded text-sm font-bold">Create Playbook</button>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
        <h3 className="text-lg font-bold mb-4 flex items-center gap-2"><Play size={18} className="text-green-400" /> Playbooks ({playbooks.length})</h3>
        {playbooks.length === 0 ? (
          <div className="text-sm text-slate-500 italic">No playbooks configured.</div>
        ) : (
          <div className="space-y-3">
            {playbooks.map((p) => (
              <div key={p.id} className="bg-slate-800 border border-slate-700 rounded-lg p-4">
                <div className="flex justify-between items-start">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white">{p.name}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${p.is_active ? 'bg-green-900 text-green-300' : 'bg-slate-700 text-slate-400'}`}>{p.is_active ? 'Active' : 'Inactive'}</span>
                    </div>
                    {p.description && <p className="text-xs text-slate-400 mt-1">{p.description}</p>}
                  </div>
                  <button onClick={() => handleDelete(p.id)} className="text-red-500 hover:text-red-400"><Trash2 size={16} /></button>
                </div>
                <div className="mt-3 text-xs text-slate-500 space-y-1">
                  {p.trigger_severity && <span>Trigger Severity: <span className="text-slate-300">{p.trigger_severity}</span> | </span>}
                  {p.trigger_event_type && <span>Event Type: <span className="text-slate-300">{p.trigger_event_type}</span> | </span>}
                  {p.trigger_process_name && <span>Process: <span className="text-slate-300">{p.trigger_process_name}</span></span>}
                </div>
                {p.actions && p.actions.length > 0 && (
                  <div className="mt-2 text-xs">
                    <span className="text-slate-500">Actions:</span>
                    {p.actions.map((a, i) => (
                      <span key={a.id || i} className="ml-2 text-cyan-400">{a.action_type}→{a.target}{i < p.actions.length - 1 ? ', ' : ''}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
        <h3 className="text-lg font-bold mb-4 flex items-center gap-2"><Activity size={18} className="text-purple-400" /> Recent Executions</h3>
        {executions.length === 0 ? (
          <div className="text-sm text-slate-500 italic">No executions yet.</div>
        ) : (
          <div className="space-y-2">
            {executions.map((e) => (
              <div key={e.id} className="flex justify-between items-center bg-slate-800 rounded p-3 text-sm">
                <div>
                  <span className="text-slate-300">Playbook #{e.playbook_id}</span>
                  {e.alert_id && <span className="text-slate-500 ml-2">Alert #{e.alert_id}</span>}
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                    e.status === 'completed' ? 'bg-green-900 text-green-300' :
                    e.status === 'failed' ? 'bg-red-900 text-red-300' : 'bg-yellow-900 text-yellow-300'
                  }`}>{e.status}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
