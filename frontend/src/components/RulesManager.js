import React, { useState, useEffect } from 'react';
import { ShieldAlert, Plus, Trash2, CheckCircle, XCircle, Beaker, Swords, Filter, Eye, EyeOff, Activity } from 'lucide-react';
import { useDashboard } from '../context/DashboardContext';
import { apiClient } from '../services/api';

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-900/50 text-red-400 border-red-800',
  HIGH: 'bg-orange-900/50 text-orange-400 border-orange-800',
  MEDIUM: 'bg-yellow-900/50 text-yellow-400 border-yellow-800',
  LOW: 'bg-green-900/50 text-green-400 border-green-800',
};

const MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact'
];

const TARGET_FIELDS = [
  { value: 'process_name', label: 'Process Name' },
  { value: 'process_path', label: 'Process Path' },
  { value: 'file_hash', label: 'File Hash / Raw Message' },
  { value: 'ip_address', label: 'IP Address' },
  { value: 'hostname', label: 'Hostname' },
  { value: 'user', label: 'User' },
];

export default function RulesManager() {
  const { settings } = useDashboard();
  const [tab, setTab] = useState('custom');
  const [rules, setRules] = useState([]);
  const [staticRules, setStaticRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [showForm, setShowForm] = useState(false);
  const [newRule, setNewRule] = useState({
    name: '', description: '', target_field: 'process_name', pattern: '', severity: 'MEDIUM',
    mitre_tactic: '', mitre_technique: '', mitre_technique_id: '',
    conditions: null, whitelist: null, auto_remediation: '',
  });

  const [testEvent, setTestEvent] = useState(JSON.stringify({ process_name: 'powershell.exe', process_path: 'C:\\Users\\test\\AppData\\Local\\Temp\\payload.exe', event_type: 'PROCESS_CREATED', agent_id: 'test', timestamp: new Date().toISOString() }, null, 2));
  const [testResults, setTestResults] = useState(null);
  const [testing, setTesting] = useState(false);

  const bg = settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200';
  const inputCls = `w-full p-2 rounded border focus:border-cyan-500 focus:outline-none ${settings.darkMode ? 'bg-slate-800 border-slate-700 text-white' : 'bg-slate-50 text-slate-900 border-slate-300'}`;

  useEffect(() => { fetchRules(); fetchStaticRules(); }, []);

  const fetchRules = async () => {
    try { setLoading(true); const res = await apiClient.get('/rules/'); setRules(res.data); setError(null); }
    catch (err) { console.error("Failed to fetch rules:", err); setError("Failed to load rules."); }
    finally { setLoading(false); }
  };

  const fetchStaticRules = async () => {
    try { const res = await apiClient.get('/rules/static'); setStaticRules(res.data); }
    catch (err) { console.error("Failed to fetch static rules:", err); }
  };

  const handleCreateRule = async (e) => {
    e.preventDefault();
    try {
      const payload = { ...newRule };
      if (!payload.mitre_tactic) delete payload.mitre_tactic;
      if (!payload.mitre_technique) delete payload.mitre_technique;
      if (!payload.mitre_technique_id) delete payload.mitre_technique_id;
      if (!payload.auto_remediation) delete payload.auto_remediation;
      await apiClient.post('/rules/', payload);
      setShowForm(false);
      setNewRule({ name: '', description: '', target_field: 'process_name', pattern: '', severity: 'MEDIUM', mitre_tactic: '', mitre_technique: '', mitre_technique_id: '', conditions: null, whitelist: null, auto_remediation: '' });
      fetchRules();
    } catch (err) { console.error("Failed to create rule:", err); alert("Error creating rule."); }
  };

  const handleDeleteRule = async (id) => {
    if (!window.confirm("Delete this rule?")) return;
    try { await apiClient.delete(`/rules/${id}`); fetchRules(); }
    catch (err) { console.error("Failed to delete rule:", err); }
  };

  const handleToggleRule = async (rule) => {
    try { await apiClient.patch(`/rules/${rule.id}`, { is_active: !rule.is_active }); fetchRules(); }
    catch (err) { console.error("Failed to toggle rule:", err); }
  };

  const handleTestRules = async () => {
    try {
      setTesting(true);
      setTestResults(null);
      const event = JSON.parse(testEvent);
      const res = await apiClient.post('/rules/test', { event });
      setTestResults(res.data);
    } catch (err) {
      console.error("Test failed:", err);
      alert("Invalid JSON or API error. Check console.");
    } finally { setTesting(false); }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-3xl font-bold flex items-center gap-3">
            <ShieldAlert className="text-red-500" /> Detection Rules Engine
          </h2>
          <p className="text-slate-400 mt-1">MITRE ATT&CK-powered threat detection with custom rules</p>
        </div>
        {tab === 'custom' && (
          <button onClick={() => setShowForm(!showForm)} className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg flex items-center gap-2 transition-colors font-bold shadow-lg shadow-cyan-500/20">
            {showForm ? <XCircle size={18}/> : <Plus size={18}/>}
            {showForm ? 'Cancel' : 'New Rule'}
          </button>
        )}
      </div>

      <div className="flex gap-2 border-b border-slate-700 pb-2">
        {['custom', 'static', 'test'].map(t => (
          <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 rounded-t font-bold text-sm flex items-center gap-2 transition-colors ${tab === t ? (settings.darkMode ? 'bg-slate-800 text-cyan-400 border-t border-l border-r border-slate-700' : 'bg-white text-cyan-600 border-t border-l border-r border-slate-200') : 'text-slate-500 hover:text-slate-300'}`}>
            {t === 'custom' && <Filter size={14}/>}
            {t === 'static' && <Swords size={14}/>}
            {t === 'test' && <Beaker size={14}/>}
            {t === 'custom' ? 'Custom Rules' : t === 'static' ? 'MITRE ATT&CK Rules' : 'Rule Tester'}
          </button>
        ))}
      </div>

      {tab === 'custom' && (
        <>
          {showForm && (
            <div className={`p-6 rounded-lg border shadow-lg ${bg}`}>
              <h3 className="text-lg font-bold mb-4 border-b pb-2 border-slate-700">Create New Detection Rule</h3>
              <form onSubmit={handleCreateRule} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-semibold mb-1">Rule Name</label>
                    <input required type="text" value={newRule.name} onChange={e => setNewRule({...newRule, name: e.target.value})} placeholder="e.g. Block Suspicious IP" className={inputCls} />
                  </div>
                  <div>
                    <label className="block text-sm font-semibold mb-1">Severity</label>
                    <select value={newRule.severity} onChange={e => setNewRule({...newRule, severity: e.target.value})} className={inputCls}>
                      <option value="LOW">LOW</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="HIGH">HIGH</option>
                      <option value="CRITICAL">CRITICAL</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-semibold mb-1">Target Field</label>
                    <select value={newRule.target_field} onChange={e => setNewRule({...newRule, target_field: e.target.value})} className={inputCls}>
                      {TARGET_FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-semibold mb-1">Regex Pattern</label>
                    <input required type="text" value={newRule.pattern} onChange={e => setNewRule({...newRule, pattern: e.target.value})} placeholder="e.g. .*malware.*" className={`${inputCls} font-mono`} />
                  </div>
                </div>

                <details className="border border-slate-700 rounded p-3">
                  <summary className="text-sm font-semibold cursor-pointer text-cyan-400">MITRE ATT&CK Mapping (optional)</summary>
                  <div className="grid grid-cols-3 gap-4 mt-3">
                    <div>
                      <label className="block text-xs font-semibold mb-1">Tactic</label>
                      <select value={newRule.mitre_tactic} onChange={e => setNewRule({...newRule, mitre_tactic: e.target.value})} className={inputCls}>
                        <option value="">-- None --</option>
                        {MITRE_TACTICS.map(t => <option key={t} value={t}>{t}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold mb-1">Technique Name</label>
                      <input type="text" value={newRule.mitre_technique} onChange={e => setNewRule({...newRule, mitre_technique: e.target.value})} placeholder="e.g. PowerShell" className={inputCls} />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold mb-1">Technique ID</label>
                      <input type="text" value={newRule.mitre_technique_id} onChange={e => setNewRule({...newRule, mitre_technique_id: e.target.value})} placeholder="e.g. T1059.001" className={`${inputCls} font-mono`} />
                    </div>
                  </div>
                </details>

                <details className="border border-slate-700 rounded p-3">
                  <summary className="text-sm font-semibold cursor-pointer text-cyan-400">Auto-Remediation (optional)</summary>
                  <div className="mt-3">
                    <select value={newRule.auto_remediation} onChange={e => setNewRule({...newRule, auto_remediation: e.target.value})} className={inputCls}>
                      <option value="">-- None (alert only) --</option>
                      <option value="kill_process">⚡ Kill Process</option>
                      <option value="block_ip">🔒 Block IP</option>
                      <option value="isolate_agent">🛡️ Isolate Agent</option>
                    </select>
                  </div>
                </details>

                <details className="border border-slate-700 rounded p-3">
                  <summary className="text-sm font-semibold cursor-pointer text-cyan-400">Whitelist (optional)</summary>
                  <div className="mt-3 space-y-3">
                    <div>
                      <label className="block text-xs font-semibold mb-1">Excluded Hostnames (comma-separated)</label>
                      <input type="text" value={(newRule.whitelist?.hostnames || []).join(', ')} onChange={e => setNewRule({...newRule, whitelist: { ...newRule.whitelist, hostnames: e.target.value.split(',').map(s => s.trim()).filter(Boolean) }})} placeholder="e.g. admin-pc, test-vm-1" className={inputCls} />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold mb-1">Excluded IPs (comma-separated)</label>
                      <input type="text" value={(newRule.whitelist?.ips || []).join(', ')} onChange={e => setNewRule({...newRule, whitelist: { ...newRule.whitelist, ips: e.target.value.split(',').map(s => s.trim()).filter(Boolean) }})} placeholder="e.g. 127.0.0.1, 192.168.1.1" className={inputCls} />
                    </div>
                  </div>
                </details>

                <div>
                  <label className="block text-sm font-semibold mb-1">Description</label>
                  <input type="text" value={newRule.description} onChange={e => setNewRule({...newRule, description: e.target.value})} placeholder="What does this rule detect?" className={inputCls} />
                </div>

                <div className="pt-4 flex justify-end">
                  <button type="submit" className="px-6 py-2 bg-green-600 hover:bg-green-500 text-white rounded font-bold shadow-lg flex items-center gap-2">
                    <CheckCircle size={18} /> Save Rule
                  </button>
                </div>
              </form>
            </div>
          )}

          {loading ? (
            <div className="text-center py-8 text-slate-500 animate-pulse">Loading Rules...</div>
          ) : error ? (
            <div className="text-center py-8 text-red-500">{error}</div>
          ) : rules.length === 0 ? (
            <div className="text-center py-16 border-2 border-dashed border-slate-700 rounded-lg text-slate-500">
              <ShieldAlert size={48} className="mx-auto mb-4 opacity-50" />
              <p className="text-lg">No custom rules configured.</p>
              <p className="text-sm">Click 'New Rule' to define custom threats.</p>
            </div>
          ) : (
            <div className={`rounded-lg border overflow-hidden ${bg}`}>
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className={`uppercase text-xs ${settings.darkMode ? 'bg-slate-800 text-slate-400' : 'bg-slate-100 text-slate-500'}`}>
                    <th className="p-3">Rule</th>
                    <th className="p-3">MITRE</th>
                    <th className="p-3">Target</th>
                    <th className="p-3">Severity</th>
                    <th className="p-3 text-center">Triggers</th>
                    <th className="p-3 text-center">Active</th>
                    <th className="p-3 text-center">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((rule) => (
                    <tr key={rule.id} className={`border-t ${settings.darkMode ? 'border-slate-800' : 'border-slate-200'}`}>
                      <td className="p-3">
                        <div className="font-bold text-cyan-500">{rule.name}</div>
                        {rule.description && <div className="text-xs text-slate-500 mt-0.5">{rule.description}</div>}
                        <div className="flex gap-1 mt-1">
                          {rule.auto_remediation && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-900/30 text-amber-400 border border-amber-800/50">
                              {rule.auto_remediation === 'kill_process' ? '⚡Kill' : rule.auto_remediation === 'block_ip' ? '🔒Block' : rule.auto_remediation === 'isolate_agent' ? '🛡️Isolate' : rule.auto_remediation}
                            </span>
                          )}
                          {(rule.whitelist?.hostnames?.length || rule.whitelist?.ips?.length) ? (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-900/30 text-green-400 border border-green-800/50">✓ Whitelist</span>
                          ) : null}
                        </div>
                      </td>
                      <td className="p-3">
                        {rule.mitre_technique_id ? (
                          <div className="flex flex-col gap-0.5">
                            <span className="text-[10px] text-slate-500">{rule.mitre_tactic ? `${rule.mitre_tactic} →` : ''}</span>
                            <span className="px-2 py-1 rounded bg-purple-900/30 text-purple-300 text-xs font-mono border border-purple-800/50">
                              {rule.mitre_technique_id} {rule.mitre_technique || ''}
                            </span>
                          </div>
                        ) : <span className="text-slate-600 text-xs">—</span>}
                      </td>
                      <td className="p-3"><span className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono">{rule.target_field}</span></td>
                      <td className="p-3">
                        <span className={`px-2 py-1 rounded text-xs font-bold ${SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.MEDIUM}`}>
                          {rule.severity}
                        </span>
                      </td>
                      <td className="p-3 text-center text-xs text-slate-400">
                        <div className="flex items-center justify-center gap-1">
                          <Activity size={12} />
                          {rule.trigger_count || 0}
                        </div>
                        {rule.last_triggered && <div className="text-[10px] text-slate-600">{new Date(rule.last_triggered).toLocaleTimeString()}</div>}
                      </td>
                      <td className="p-3 text-center">
                        <button onClick={() => handleToggleRule(rule)} className={`p-1.5 rounded transition-colors ${rule.is_active ? 'text-green-500 hover:bg-green-900/20' : 'text-slate-600 hover:bg-slate-700/20'}`}>
                          {rule.is_active ? <Eye size={16} /> : <EyeOff size={16} />}
                        </button>
                      </td>
                      <td className="p-3 text-center">
                        <button onClick={() => handleDeleteRule(rule.id)} className="p-1.5 text-slate-400 hover:text-red-500 hover:bg-red-900/20 rounded transition-colors" title="Delete Rule">
                          <Trash2 size={15} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {tab === 'static' && (
        <div className={`rounded-lg border overflow-hidden ${bg}`}>
          <table className="w-full text-left text-sm">
            <thead>
              <tr className={`uppercase text-xs ${settings.darkMode ? 'bg-slate-800 text-slate-400' : 'bg-slate-100 text-slate-500'}`}>
                <th className="p-3">Rule Name</th>
                <th className="p-3">MITRE ATT&CK</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Description</th>
              </tr>
            </thead>
            <tbody>
              {staticRules.map((rule, i) => (
                <tr key={i} className={`border-t ${settings.darkMode ? 'border-slate-800' : 'border-slate-200'}`}>
                  <td className="p-3 font-bold text-cyan-500">{rule.name}</td>
                  <td className="p-3">
                    <div className="flex flex-col gap-1">
                      <span className="text-xs text-slate-400">{rule.mitre_tactic} →</span>
                      <span className="px-2 py-0.5 rounded bg-purple-900/30 text-purple-300 text-xs font-mono border border-purple-800/50 inline-block w-fit">
                        {rule.mitre_technique_id} {rule.mitre_technique}
                      </span>
                    </div>
                  </td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs font-bold ${SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.MEDIUM}`}>
                      {rule.severity}
                    </span>
                  </td>
                  <td className="p-3 text-xs text-slate-400">{rule.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'test' && (
        <div className="grid grid-cols-2 gap-6">
          <div className={`p-4 rounded-lg border ${bg}`}>
            <h3 className="font-bold mb-2 flex items-center gap-2"><Beaker size={16} /> Test Event (JSON)</h3>
            <textarea value={testEvent} onChange={e => setTestEvent(e.target.value)} rows={14}
              className={`w-full p-3 rounded border font-mono text-xs focus:border-cyan-500 focus:outline-none ${settings.darkMode ? 'bg-slate-800 border-slate-700 text-green-300' : 'bg-slate-50 border-slate-300 text-slate-800'}`} />
            <button onClick={handleTestRules} disabled={testing}
              className="mt-3 px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white rounded font-bold flex items-center gap-2">
              {testing ? 'Testing...' : 'Run Against All Rules'}
            </button>
          </div>
          <div className={`p-4 rounded-lg border ${bg}`}>
            <h3 className="font-bold mb-2 flex items-center gap-2"><ShieldAlert size={16} /> Results</h3>
            {testResults === null ? (
              <div className="text-center py-12 text-slate-500 text-sm">Click "Run Against All Rules" to test.</div>
            ) : testResults.length === 0 ? (
              <div className="text-center py-12 text-green-500">
                <CheckCircle size={32} className="mx-auto mb-2" />
                <p className="font-bold">No rules matched</p>
                <p className="text-xs text-slate-500 mt-1">The test event is clean.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {testResults.map((r, i) => (
                  <div key={i} className={`p-3 rounded border text-sm ${r.severity === 'CRITICAL' ? 'bg-red-900/20 border-red-800' : r.severity === 'HIGH' ? 'bg-orange-900/20 border-orange-800' : 'bg-yellow-900/20 border-yellow-800'}`}>
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-xs font-mono">{r.rule_name}</span>
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${SEVERITY_COLORS[r.severity]}`}>{r.severity}</span>
                    </div>
                    <p className="text-xs mt-1 text-slate-300">{r.description}</p>
                    {r.mitre_technique_id && <span className="text-xs text-purple-400 font-mono mt-1 inline-block">{r.mitre_technique_id}</span>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
