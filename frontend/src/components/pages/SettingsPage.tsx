import { useEffect, useState } from 'react'
import { Bell, Lock, Zap, Shield, HelpCircle, Network, KeyRound, ExternalLink, RefreshCw } from 'lucide-react'
import { useAppStore } from '@/store/appStore'
import { integrationsAPI } from '@/services/api'
import { cn } from '@/lib/utils'

interface ProviderSetting {
  key: string
  label: string
  env_var: string
  help_text: string
  docs_url: string
  source: 'env' | 'database' | 'not set'
  active: boolean
  masked: string
  overridable: boolean
}

/** Sezione API keys: i campi sono generati dalla risposta del backend
 *  (catalogo dinamico) — aggiungere un provider nel brain lo fa comparire
 *  qui senza toccare il frontend. Le chiavi non si rileggono mai: si vede
 *  solo il mascheramento; salvare una stringa vuota rimuove l'override. */
function ApiKeysSection() {
  const [providers, setProviders] = useState<ProviderSetting[]>([])
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  const load = async () => {
    try {
      const res = await integrationsAPI.status()
      setProviders(res.data?.providers || [])
    } catch {
      setProviders([])
    }
  }

  useEffect(() => { load() }, [])

  const save = async (p: ProviderSetting) => {
    setBusy(true); setMsg('')
    try {
      await integrationsAPI.setKey(p.key, drafts[p.key] ?? '')
      setDrafts(d => ({ ...d, [p.key]: '' }))
      await load()
      setMsg(`${p.label} aggiornato.`)
    } catch (e: any) {
      setMsg(e?.response?.status === 403
        ? 'Serve il ruolo admin per modificare le chiavi.'
        : 'Salvataggio fallito.')
    } finally { setBusy(false) }
  }

  if (!providers.length) {
    return (
      <div className="card p-6 bg-[hsl(var(--secondary)/0.3)]">
        <div className="flex items-center gap-3">
          <KeyRound size={20} className="text-cyan-400" />
          <h3 className="text-lg font-bold text-white">Integrations & API Keys</h3>
        </div>
        <p className="text-sm text-[hsl(var(--muted-foreground))] mt-3">
          Nessun provider configurato oppure backend non raggiungibile.
        </p>
      </div>
    )
  }

  return (
    <div className="card p-6 space-y-5 bg-[hsl(var(--secondary)/0.3)]">
      <div className="flex items-center justify-between border-b border-[hsl(var(--border))] pb-4">
        <div className="flex items-center gap-3">
          <KeyRound size={20} className="text-cyan-400" />
          <h3 className="text-lg font-bold text-white">Integrations & API Keys</h3>
        </div>
        <button onClick={load} className="btn btn-ghost btn-sm flex items-center gap-1.5">
          <RefreshCw size={13} /> Reload
        </button>
      </div>

      {msg && <p className="text-xs text-cyan-300">{msg}</p>}

      {providers.map(p => (
        <div key={p.key} className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">
              {p.label}
              {p.active && <span className={cn('ml-2 px-1.5 py-0.5 rounded text-[9px] normal-case',
                p.source === 'env' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20')}>
                {p.source === 'env' ? `da env (${p.masked})` : `da dashboard (${p.masked})`}
              </span>}
              {!p.active && <span className="ml-2 text-[9px] text-[hsl(var(--muted-foreground))] normal-case">non configurata</span>}
            </label>
            <a href={p.docs_url} target="_blank" rel="noreferrer"
               className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
              ottieni chiave <ExternalLink size={10} />
            </a>
          </div>
          <div className="flex gap-2">
            <input
              type="password"
              autoComplete="off"
              disabled={!p.overridable && p.source === 'env'}
              placeholder={p.source === 'env' ? 'Gestita da .env (override non possibile)' : 'Inserisci API key...'}
              value={drafts[p.key] ?? ''}
              onChange={e => setDrafts(d => ({ ...d, [p.key]: e.target.value }))}
              className="input w-full bg-[hsl(var(--background))] font-mono text-sm"
            />
            <button onClick={() => save(p)} disabled={busy}
              className="btn btn-primary bg-cyan-600 hover:bg-cyan-500 border-cyan-500 px-4 text-xs">
              Salva
            </button>
          </div>
          <p className="text-[10px] text-[hsl(var(--muted-foreground))]">
            {p.help_text}
            {p.source === 'database' && ' · Salvata cifrata nel database (override attivo).'}
          </p>
        </div>
      ))}
    </div>
  )
}

function SettingCard({ icon: Icon, title, description, enabled, onChange, highlight = false }: any) {
  return (
    <div className={cn("card p-6 flex items-center justify-between transition-all group", highlight ? "border-[hsl(var(--primary)/0.5)] shadow-[0_0_15px_rgba(6,182,212,0.1)]" : "hover:border-[hsl(var(--primary)/0.3)]")}>
      <div className="flex items-center gap-4">
        <div className={cn("p-3 rounded-xl transition-colors", enabled ? "bg-cyan-500/20 text-cyan-400" : "bg-[hsl(var(--background))] text-[hsl(var(--muted-foreground))] border border-[hsl(var(--border))] group-hover:text-cyan-400")}>
          <Icon size={24} />
        </div>
        <div>
          <h3 className="font-bold text-white text-base">{title}</h3>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">{description}</p>
        </div>
      </div>
      <button
        onClick={onChange}
        className={cn("relative inline-flex h-7 w-12 items-center rounded-full transition-colors shrink-0", enabled ? "bg-cyan-500 shadow-lg shadow-cyan-500/20" : "bg-[hsl(var(--secondary))] border border-[hsl(var(--border))]")}
      >
        <span className={cn("inline-block h-5 w-5 transform rounded-full bg-white transition-transform", enabled ? "translate-x-6" : "translate-x-1")} />
      </button>
    </div>
  )
}

export default function SettingsPage() {
  const { settings, setSettings, resetSettings } = useAppStore()

  const toggleSetting = (key: keyof typeof settings) => {
    setSettings({ [key]: !settings[key] })
  }

  const handleSave = () => {
    // Note: Zustand persist automatically saves to localStorage
    alert('Settings saved successfully!')
  }

  return (
    <div className="space-y-8 animate-slide-in max-w-5xl mx-auto">
      <div>
        <h1 className="text-3xl font-bold text-white tracking-tight">Platform Settings</h1>
        <p className="text-[hsl(var(--muted-foreground))] mt-1">Configure Aegis EDR preferences and system behaviors.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-6">
          <div className="space-y-4">
            <h3 className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest px-1">Alerts & Notifications</h3>
            <SettingCard
              icon={Bell}
              title="Desktop Notifications"
              description="Native OS alerts for critical detections."
              enabled={settings.notifications}
              onChange={() => toggleSetting('notifications')}
              highlight={settings.notifications}
            />
            <SettingCard
              icon={Zap}
              title="Audio Alarms"
              description="Play alert sounds when threats are detected."
              enabled={settings.soundAlerts}
              onChange={() => toggleSetting('soundAlerts')}
            />
          </div>

          <div className="space-y-4">
            <h3 className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest px-1">Performance</h3>
            <SettingCard
              icon={Zap}
              title="Real-time Telemetry"
              description="Live websocket streaming for dashboard widgets."
              enabled={settings.autoRefresh}
              onChange={() => toggleSetting('autoRefresh')}
              highlight={settings.autoRefresh}
            />
            <SettingCard
              icon={Zap}
              title="Sound Alarms"
              description="Play alert sounds when threats are detected."
              enabled={settings.soundAlerts}
              onChange={() => toggleSetting('soundAlerts')}
            />
          </div>
        </div>

        <div className="space-y-6">
          <ApiKeysSection />

          <div className="card p-6 space-y-6 bg-[hsl(var(--secondary)/0.3)]">
            <div className="flex items-center gap-3 border-b border-[hsl(var(--border))] pb-4">
              <Lock size={20} className="text-cyan-400" />
              <h3 className="text-lg font-bold text-white">API Configuration</h3>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest mb-1.5 block">Endpoint Base URL</label>
                <div className="flex relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))]"><Network size={14}/></span>
                  <input
                    type="text"
                    defaultValue={import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1"}
                    className="input pl-9 w-full bg-[hsl(var(--background))] font-mono text-sm"
                  />
                </div>
                <p className="text-[10px] text-[hsl(var(--muted-foreground))] mt-2">Core API for Aegis backend services.</p>
              </div>
              
              <div>
                <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest mb-1.5 block">Local Storage Mode</label>
                <select className="input bg-[hsl(var(--background))] w-full">
                  <option>Persistent (IndexedDB)</option>
                  <option>Session Only (RAM)</option>
                </select>
                <p className="text-[10px] text-[hsl(var(--muted-foreground))] mt-2">Controls how offline data is cached locally.</p>
              </div>
            </div>
          </div>

          <div className="card p-6 bg-[hsl(var(--secondary)/0.3)] border-dashed">
            <div className="flex items-center gap-3 mb-4">
              <Shield size={20} className="text-emerald-400" />
              <h3 className="text-lg font-bold text-white">System Info</h3>
            </div>
            
            <div className="space-y-3">
              <div className="flex justify-between items-center py-2 border-b border-[hsl(var(--border))]">
                <span className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Platform Version</span>
                <span className="font-mono text-sm font-bold text-white">v2.0.0-beta</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-[hsl(var(--border))]">
                <span className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Build Hash</span>
                <span className="font-mono text-sm text-[hsl(var(--muted-foreground))]">f4a9b2c</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-[hsl(var(--border))]">
                <span className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">UI Framework</span>
                <span className="text-sm font-semibold text-white">React 19 + Vite</span>
              </div>
              <div className="flex justify-between items-center py-2">
                <span className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">State Management</span>
                <span className="text-sm font-semibold text-white">Zustand + TanStack Query</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-4 pt-6 border-t border-[hsl(var(--border))]">
        <div className="flex items-center gap-2 text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">
          <HelpCircle size={14} /> Need help? Contact support
        </div>
        <div className="flex gap-3">
          <button onClick={resetSettings} className="btn btn-ghost border border-[hsl(var(--border))] hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/20">
            Reset Defaults
          </button>
          <button onClick={handleSave} className="btn btn-primary bg-cyan-600 hover:bg-cyan-500 border-cyan-500 shadow-cyan-500/20 px-8">
            Apply Changes
          </button>
        </div>
      </div>
    </div>
  )
}
