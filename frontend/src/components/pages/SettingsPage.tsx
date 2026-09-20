import { useEffect, useState } from 'react'
import { Bell, Lock, Zap, Shield, HelpCircle, Network, KeyRound, ExternalLink, RefreshCw, Sparkles, MonitorSmartphone, Send } from 'lucide-react'
import { useAppStore } from '@/store/appStore'
import { apiClient, aiAPI, devicesAPI, healthAPI, integrationsAPI } from '@/services/api'
import { PermissionGate } from '@/components/common/PermissionGate'
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
      setMsg(`${p.label} updated.`)
    } catch (e: any) {
      setMsg(e?.response?.status === 403
        ? 'Admin role required to change API keys.'
        : 'Save failed.')
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
          No provider configured, or the backend is unreachable.
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
                {p.source === 'env' ? `from env (${p.masked})` : `from dashboard (${p.masked})`}
              </span>}
              {!p.active && <span className="ml-2 text-[9px] text-[hsl(var(--muted-foreground))] normal-case">not set</span>}
            </label>
            <a href={p.docs_url} target="_blank" rel="noreferrer"
               className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
              get key <ExternalLink size={10} />
            </a>
          </div>
          <div className="flex gap-2">
            <input
              type="password"
              autoComplete="off"
              disabled={!p.overridable && p.source === 'env'}
              placeholder={p.source === 'env' ? 'Managed by .env (override not possible)' : 'Enter API key...'}
              value={drafts[p.key] ?? ''}
              onChange={e => setDrafts(d => ({ ...d, [p.key]: e.target.value }))}
              className="input w-full bg-[hsl(var(--background))] font-mono text-sm"
            />
            <PermissionGate perms={['manage']}>
              <button onClick={() => save(p)} disabled={busy}
                className="btn btn-primary bg-cyan-600 hover:bg-cyan-500 border-cyan-500 px-4 text-xs">
                Save
              </button>
            </PermissionGate>
          </div>
          <p className="text-[10px] text-[hsl(var(--muted-foreground))]">
            {p.help_text}
            {p.source === 'database' && ' · Stored encrypted in the database (override active).'}
          </p>
        </div>
      ))}
    </div>
  )
}

interface AISettings {
  current: {
    provider: string
    provider_source: 'env' | 'database' | 'default'
    model: string
    model_source: 'env' | 'database' | 'default'
    automatic_enrich: boolean
    automatic_source: 'env' | 'database'
    cloud: boolean
    local: boolean
  }
  providers: { value: string; label: string }[]
  default_models: Record<string, string>
  status: {
    provider: string
    model: string
    local: boolean
    reason: string
    automatic_enrichment: boolean
    reachable?: boolean | null
  }
}

const sourceBadge = (source: 'env' | 'database' | 'default') => {
  if (source === 'env') return { text: 'from .env', cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' }
  if (source === 'database') return { text: 'from dashboard', cls: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' }
  return { text: 'default', cls: 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]' }
}

/** AI section: provider, model and consent for data leaving the network.
 *  Il valore di ogni campo dichiara la sua origine (.env o dashboard) perché
 *  un campo che non ha effetto senza dirlo è peggio di un campo assente. */
function AISection() {
  const [data, setData] = useState<AISettings | null>(null)
  const [provider, setProvider] = useState('')
  const [model, setModel] = useState('')
  const [autoCloud, setAutoCloud] = useState(false)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  const load = async () => {
    try {
      const res = await aiAPI.getSettings()
      const d: AISettings = res.data
      setData(d)
      setProvider(d.current.provider)
      setModel(d.current.model_source === 'default' ? '' : d.current.model)
      setAutoCloud(d.current.automatic_enrich)
    } catch {
      setData(null)
    }
  }

  useEffect(() => { load() }, [])

  const save = async () => {
    setBusy(true); setMsg('')
    try {
      const res = await aiAPI.setSettings({
        provider,
        model,
        automatic_enrich: autoCloud,
      })
      setData(res.data)
      setMsg('AI settings saved. They apply immediately: no restart needed.')
    } catch (e: any) {
      setMsg(e?.response?.status === 403
        ? 'Admin role required to change the AI provider.'
        : e?.response?.data?.detail || 'Save failed.')
    } finally { setBusy(false) }
  }

  if (!data) {
    return (
      <div className="card p-6 bg-[hsl(var(--secondary)/0.3)]">
        <div className="flex items-center gap-3">
          <Sparkles size={20} className="text-cyan-400" />
          <h3 className="text-lg font-bold text-white">AI Provider</h3>
        </div>
        <p className="text-sm text-[hsl(var(--muted-foreground))] mt-3">
          Backend unreachable: AI status unavailable.
        </p>
      </div>
    )
  }

  const pb = sourceBadge(data.current.provider_source)
  const mb = sourceBadge(data.current.model_source)
  const placeholder = data.default_models[provider] || 'provider default'

  return (
    <div className="card p-6 space-y-5 bg-[hsl(var(--secondary)/0.3)]">
      <div className="flex items-center justify-between border-b border-[hsl(var(--border))] pb-4">
        <div className="flex items-center gap-3">
          <Sparkles size={20} className="text-cyan-400" />
          <h3 className="text-lg font-bold text-white">AI Provider</h3>
        </div>
        <button onClick={load} className="btn btn-ghost btn-sm flex items-center gap-1.5">
          <RefreshCw size={13} /> Reload
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-[10px]">
        <span className={cn('px-2 py-1 rounded border font-mono',
          data.status.provider === 'disabled' || data.status.reachable === false
            ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
            : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20')}>
          status: {data.status.provider}{data.status.model ? ` · ${data.status.model}` : ''}
        </span>
        <span className="px-2 py-1 rounded border bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]">
          {data.status.local ? 'no data leaves the network' : 'cloud provider: anonymized data leaves only when authorized'}
        </span>
        {data.status.reason && <span className="text-[hsl(var(--muted-foreground))]">{data.status.reason}</span>}
      </div>

      {msg && <p className="text-xs text-cyan-300">{msg}</p>}

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">
            Provider{' '}
            <span className={cn('ml-1 px-1.5 py-0.5 rounded border text-[9px] normal-case', pb.cls)}>{pb.text}</span>
          </label>
        </div>
        <select value={provider} onChange={e => setProvider(e.target.value)}
          disabled={data.current.provider_source === 'env'}
          className="input w-full bg-[hsl(var(--background))] text-sm">
          {data.providers.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
        </select>
        {data.current.provider_source === 'env' && (
          <p className="text-[10px] text-[hsl(var(--muted-foreground))]">
            Set in the <span className="font-mono">.env</span> (AI_PROVIDER): to choose it from the dashboard, remove it from the env.
          </p>
        )}
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">
            Model{' '}
            <span className={cn('ml-1 px-1.5 py-0.5 rounded border text-[9px] normal-case', mb.cls)}>{mb.text}</span>
          </label>
        </div>
        <input value={model} onChange={e => setModel(e.target.value)}
          disabled={data.current.model_source === 'env'}
          placeholder={`empty = ${placeholder}`}
          className="input w-full bg-[hsl(var(--background))] font-mono text-sm" />
        <p className="text-[10px] text-[hsl(var(--muted-foreground))]">
          With Ollama you can use a model served elsewhere (e.g. <span className="font-mono">qwen2.5:14b</span>) or point to a powerful machine on your network.
        </p>
      </div>

      <label className="flex items-start gap-3 cursor-pointer">
        <input type="checkbox" checked={autoCloud} onChange={e => setAutoCloud(e.target.checked)}
          disabled={data.current.automatic_source === 'env'}
          className="mt-0.5 h-4 w-4 accent-cyan-500" />
        <span className="text-xs text-[hsl(var(--muted-foreground))]">
          <span className="font-semibold text-white">Automatic enrichment with a cloud provider</span>
          <br />
          When on, new alerts are summarized automatically by the selected provider — with Gemini/OpenAI the
          context (IPs, emails and tokens already anonymized before sending) leaves the network. With a local
          provider it stays always on and needs no consent. Off, the AI only answers questions.
        </span>
      </label>

      <PermissionGate perms={['manage']}>
        <button onClick={save} disabled={busy}
          className="btn btn-primary bg-cyan-600 hover:bg-cyan-500 border-cyan-500 px-4 text-xs w-full">
          {busy ? 'Saving…' : 'Save AI settings'}
        </button>
      </PermissionGate>
    </div>
  )
}

/** Notifiche Telegram: config live (chat_id, severita', heartbeat) + token
 *  nella sezione Integrations. Il bottone Test verifica token+chat davvero,
 *  senza aspettare il primo alert. */
function TelegramSection() {
  const [cfg, setCfg] = useState<any>(null)
  const [draft, setDraft] = useState<any>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [chats, setChats] = useState<any[]>([])

  const load = async () => {
    try {
      const res = await apiClient.get('/telegram/settings')
      setCfg(res.data)
      setDraft({
        enabled: res.data.enabled,
        chat_id: res.data.chat_id || '',
        min_severity: res.data.min_severity,
        heartbeat_minutes: res.data.heartbeat_minutes,
      })
    } catch { setCfg(null) }
  }

  useEffect(() => { load() }, [])

  const save = async () => {
    setBusy(true); setMsg('')
    try {
      await apiClient.put('/telegram/settings', draft)
      setMsg('Saved.')
      await load()
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || 'Save failed.')
    } finally { setBusy(false) }
  }

  const sendTest = async () => {
    setBusy(true); setMsg('')
    try {
      await apiClient.post('/telegram/test')
      setMsg('Test message sent — check your Telegram chat.')
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || 'Test failed.')
    } finally { setBusy(false) }
  }

  // Scopre i chat_id che hanno scritto al bot: niente indovinelli — il chat_id
  // personale NON e' il @username del bot e il bot lo vede solo se gli scrivi.
  const detectChats = async () => {
    setBusy(true); setMsg('')
    try {
      const res = await apiClient.post('/telegram/detect')
      setChats(res.data?.chats || [])
      setMsg(res.data?.hint || (res.data?.chats?.length ? 'Click a chat below to use it.' : ''))
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || 'Detect failed.')
    } finally { setBusy(false) }
  }

  if (!cfg) {
    return (
      <div className="card p-6 bg-[hsl(var(--secondary)/0.3)]">
        <div className="flex items-center gap-3">
          <Send size={20} className="text-cyan-400" />
          <h3 className="text-lg font-bold text-white">Telegram Notifications</h3>
        </div>
        <p className="text-sm text-[hsl(var(--muted-foreground))] mt-3">Backend unreachable.</p>
      </div>
    )
  }

  return (
    <div className="card p-6 space-y-4 bg-[hsl(var(--secondary)/0.3)]">
      <div className="flex items-center gap-3 border-b border-[hsl(var(--border))] pb-4">
        <Send size={20} className="text-cyan-400" />
        <h3 className="text-lg font-bold text-white">Telegram Notifications</h3>
      </div>
      <p className="text-xs text-[hsl(var(--muted-foreground))]">
        Alerts at or above your chosen minimum severity, plus a periodic heartbeat,
        delivered to your Telegram even when the dashboard is closed. Put the bot
        token in <span className="text-cyan-400"> Integrations &amp; API Keys</span>
        (from @BotFather, full format <span className="font-mono">123456789:ABC...</span>),
        then detect your chat id here: send your bot any message and press Detect.
      </p>
      {msg && <p className="text-xs text-cyan-400">{msg}</p>}
      {draft && (
        <div className="space-y-3">
          <label className="flex items-center gap-2 text-sm text-white cursor-pointer select-none">
            <input type="checkbox" className="accent-[hsl(var(--primary))] w-4 h-4"
              checked={draft.enabled}
              onChange={e => setDraft({ ...draft, enabled: e.target.checked })} />
            Enable Telegram notifications
          </label>
          <div>
            <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest mb-1 block">Chat ID</label>
            <input className="input font-mono text-sm" placeholder="123456789 or @channelname"
              value={draft.chat_id}
              onChange={e => setDraft({ ...draft, chat_id: e.target.value })} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest mb-1 block">Minimum severity</label>
              <select className="input bg-[hsl(var(--background))] w-full text-sm"
                value={draft.min_severity}
                onChange={e => setDraft({ ...draft, min_severity: e.target.value })}>
                <option value="INFO">INFO — everything</option>
                <option value="LOW">LOW and above</option>
                <option value="MEDIUM">MEDIUM and above</option>
                <option value="HIGH">HIGH and above (default)</option>
                <option value="CRITICAL">CRITICAL only</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest mb-1 block">Heartbeat (minutes)</label>
              <input type="number" min={15} max={1440} className="input font-mono text-sm"
                value={draft.heartbeat_minutes}
                onChange={e => setDraft({ ...draft, heartbeat_minutes: parseInt(e.target.value || '60', 10) })} />
            </div>
          </div>
          <div className="flex items-center gap-3 pt-1">
            <button onClick={save} disabled={busy} className="btn btn-primary btn-sm">Save</button>
            <button onClick={sendTest} disabled={busy} className="btn btn-ghost btn-sm border border-[hsl(var(--border))]">Send test message</button>
            <button onClick={detectChats} disabled={busy} className="btn btn-ghost btn-sm border border-[hsl(var(--border))]">Detect chat ID</button>
            <span className="text-[10px] text-[hsl(var(--muted-foreground))]">
              Bot token: {cfg.bot_token_configured ? 'configured' : 'NOT configured'}
            </span>
          </div>
          {/* Comandi del bot: il telefono serve a sapere "sta girando?"
              senza aprire la dashboard. Documentati qui perche' l'unico modo
              di scoprirli e' /help dal telefono: se non lo sai, non esiste. */}
          <p className="text-[11px] text-[hsl(var(--muted-foreground))] leading-relaxed">
            Remote commands (answered only to the chat ID above):{' '}
            <code className="font-mono text-cyan-400">/status</code> agents, devices and last contact ·{' '}
            <code className="font-mono text-cyan-400">/alerts</code> open alerts above your threshold ·{' '}
            <code className="font-mono text-cyan-400">/help</code> this list.
            Resolution notices use the same threshold as the alerts.
          </p>
          {chats.length > 0 && (
            <div className="space-y-1 border border-[hsl(var(--border))] rounded p-3 bg-[hsl(var(--background))]">
              <p className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Found chats — click to use</p>
              {chats.map(c => (
                <button key={c.id}
                  onClick={() => setDraft((d: any) => ({ ...d, chat_id: String(c.id) }))}
                  className="block w-full text-left text-xs font-mono text-cyan-400 hover:text-cyan-300 py-0.5">
                  {c.id} — {c.title || c.username || c.type}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/** Dispositivi fidati ("Mantieni l'accesso"): elenco e revoca individuale.
 *  Il logout da un PC condiviso senza revocare da qui lascerebbe il trust
 *  attivo: la revoca qui è il modo ufficiale per chiudere una sessione
 *  persistente da un'altra macchina. */
function TrustedDevicesSection() {
  const [devices, setDevices] = useState<any[]>([])
  const [msg, setMsg] = useState('')

  const load = async () => {
    try {
      const res = await devicesAPI.list()
      setDevices(res.data || [])
    } catch { setDevices([]) }
  }

  useEffect(() => { load() }, [])

  const revoke = async (id: number) => {
    try {
      await devicesAPI.revoke(id)
      setMsg('Device revoked.')
      await load()
    } catch { setMsg('Revoke failed.') }
  }

  const fmt = (d?: string | null) => d
    ? new Date(d).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
    : '—'

  return (
    <div className="card p-6 space-y-4 bg-[hsl(var(--secondary)/0.3)]">
      <div className="flex items-center justify-between border-b border-[hsl(var(--border))] pb-4">
        <div className="flex items-center gap-3">
          <MonitorSmartphone size={20} className="text-cyan-400" />
          <h3 className="text-lg font-bold text-white">Trusted Devices</h3>
        </div>
        <button onClick={load} className="btn btn-ghost btn-sm flex items-center gap-1.5">
          <RefreshCw size={13} /> Reload
        </button>
      </div>
      <p className="text-xs text-[hsl(var(--muted-foreground))]">
        Browsers where "Stay signed in" is active. Logging out on a shared
        machine ends its session, but revoke here to remove the 30-day trust.
      </p>
      {msg && <p className="text-xs text-cyan-400">{msg}</p>}
      {!devices.length ? (
        <p className="text-sm text-[hsl(var(--muted-foreground))]">No trusted devices.</p>
      ) : (
        <div className="space-y-2">
          {devices.map(d => (
            <div key={d.id} className="flex items-center justify-between gap-3 p-3 rounded-lg bg-[hsl(var(--background))] border border-[hsl(var(--border))]">
              <div className="min-w-0">
                <p className="text-sm font-semibold text-white truncate">
                  {d.device_label || 'Unknown device'}
                  {d.revoked && <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">revoked</span>}
                </p>
                <p className="text-[10px] text-[hsl(var(--muted-foreground))] truncate">
                  Added {fmt(d.created_at)} · Last used {fmt(d.last_used_at)} · Expires {fmt(d.expires_at)}
                </p>
              </div>
              {!d.revoked && (
                <button
                  onClick={() => revoke(d.id)}
                  className="btn btn-ghost btn-sm shrink-0 hover:bg-red-500/10 hover:text-red-400"
                >
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      )}
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

const fmtUptime = (s?: number) => {
  if (s == null) return '—'
  if (s >= 3600) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
  if (s >= 60) return `${Math.floor(s / 60)}m`
  return `${Math.floor(s)}s`
}

export default function SettingsPage() {
  const { settings, setSettings, resetSettings } = useAppStore()
  // Versione e uptime arrivano dal backend: la pagina non li inventa (prima
  // erano stringhe hardcoded, con una versione diversa da quella reale).
  const [backend, setBackend] = useState<{ version?: string; uptime_s?: number } | null>(null)

  useEffect(() => {
    healthAPI.live()
      .then(r => setBackend(r.data))
      .catch(() => setBackend(null))
  }, [])

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
          </div>
        </div>

        <div className="space-y-6">
          <AISection />

          <ApiKeysSection />

          <TrustedDevicesSection />

          <TelegramSection />

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
                <span className="font-mono text-sm font-bold text-white">
                  {backend?.version ? `v${backend.version}` : 'backend unreachable'}
                </span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-[hsl(var(--border))]">
                <span className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Backend Uptime</span>
                <span className="font-mono text-sm text-[hsl(var(--muted-foreground))]">{fmtUptime(backend?.uptime_s)}</span>
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
