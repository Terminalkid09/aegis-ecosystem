import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import {
  AlertTriangle, Check, Copy, KeyRound, RefreshCw, Search,
  ShieldCheck, UserPlus, Users as UsersIcon, X,
} from 'lucide-react'
import { usersAPI, type ManagedUser } from '@/services/api'
import { useAppStore } from '@/store/appStore'
import { cn } from '@/lib/utils'

const ROLES = [
  { value: 'viewer', label: 'Viewer', help: 'Read-only. No audit or response actions.' },
  { value: 'user', label: 'User', help: 'Legacy read-only role, same permissions as viewer.' },
  { value: 'auditor', label: 'Auditor', help: 'Read + audit log and evidence.' },
  { value: 'responder', label: 'Responder', help: 'Read + containment and response actions.' },
  { value: 'analyst', label: 'Analyst', help: 'Triage, detection rules, deploy and response.' },
  { value: 'admin', label: 'Admin', help: 'Full control, including user and platform settings.' },
]

function newPassword() {
  const bytes = new Uint8Array(18)
  crypto.getRandomValues(bytes)
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%'
  return Array.from(bytes, b => alphabet[b % alphabet.length]).join('') + 'aA1!'
}

function Modal({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="card w-full max-w-lg p-6 space-y-5 bg-[hsl(var(--card))] shadow-2xl">
        <div className="flex items-center justify-between border-b border-[hsl(var(--border))] pb-4">
          <h2 className="text-lg font-bold text-white">{title}</h2>
          <button onClick={onClose} className="text-[hsl(var(--muted-foreground))] hover:text-white">
            <X size={18} />
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}

export default function UsersPage() {
  const currentUser = useAppStore(s => s.user)
  const [users, setUsers] = useState<ManagedUser[]>([])
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [credentials, setCredentials] = useState<{ email: string; password: string } | null>(null)
  const [form, setForm] = useState({ username: '', email: '', role: 'user', password: newPassword() })

  async function load() {
    setLoading(true)
    setError('')
    try {
      const res = await usersAPI.list()
      setUsers(res.data.users ?? [])
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Unable to load users.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return users
    return users.filter(u => `${u.username} ${u.email} ${u.role}`.toLowerCase().includes(q))
  }, [users, query])

  async function update(id: number, patch: { role?: string; active?: boolean }) {
    setBusy(true); setError(''); setNotice('')
    try {
      await usersAPI.update(id, patch)
      setNotice('Account updated.')
      await load()
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Update failed.')
    } finally { setBusy(false) }
  }

  async function create(e: FormEvent) {
    e.preventDefault()
    setBusy(true); setError(''); setNotice('')
    try {
      await usersAPI.create(form)
      setCredentials({ email: form.email, password: form.password })
      setShowCreate(false)
      setForm({ username: '', email: '', role: 'user', password: newPassword() })
      setNotice('Account created. Give the temporary password to the user through a secure channel.')
      await load()
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Creation failed.')
    } finally { setBusy(false) }
  }

  async function resetPassword(user: ManagedUser) {
    if (!window.confirm(`Reset the password for ${user.email}? The current password will stop working immediately.`)) return
    const password = newPassword()
    setBusy(true); setError(''); setNotice('')
    try {
      await usersAPI.resetPassword(user.id, password)
      setCredentials({ email: user.email, password })
      setNotice('Password reset. It is shown only in this panel.')
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Password reset failed.')
    } finally { setBusy(false) }
  }

  async function copyCredentials() {
    if (!credentials) return
    try {
      await navigator.clipboard.writeText(`Email: ${credentials.email}\nTemporary password: ${credentials.password}`)
      setNotice('Credentials copied to clipboard.')
    } catch {
      setNotice('Copy failed: select the password manually.')
    }
  }

  return (
    <div className="space-y-6 animate-slide-in max-w-6xl mx-auto">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <UsersIcon size={22} className="text-cyan-400" />
            <h1 className="text-3xl font-bold text-white tracking-tight">Users &amp; Roles</h1>
          </div>
          <p className="text-[hsl(var(--muted-foreground))] mt-1">
            Admin-only account management. Roles are enforced by the backend on every request.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} disabled={loading || busy} className="btn btn-ghost btn-sm border border-[hsl(var(--border))]">
            <RefreshCw size={13} className={cn(loading && 'animate-spin')} /> Reload
          </button>
          <button data-testid="user-create" onClick={() => setShowCreate(true)} disabled={busy} className="btn btn-primary btn-sm">
            <UserPlus size={14} /> New account
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          <AlertTriangle size={16} className="shrink-0 mt-0.5" /> <span>{error}</span>
        </div>
      )}
      {notice && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-sm">
          <Check size={16} className="shrink-0 mt-0.5" /> <span>{notice}</span>
        </div>
      )}

      {credentials && (
        <div data-testid="temporary-credentials" className="card p-5 border-cyan-500/30 bg-cyan-500/5 space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <KeyRound size={16} className="text-cyan-400" />
              <h2 className="text-sm font-bold text-white">Temporary credentials — shown once</h2>
            </div>
            <div className="flex gap-2">
              <button onClick={copyCredentials} className="btn btn-ghost btn-sm border border-[hsl(var(--border))]">
                <Copy size={13} /> Copy
              </button>
              <button onClick={() => setCredentials(null)} className="btn btn-ghost btn-sm">
                <X size={13} />
              </button>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
            <div>
              <p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Email</p>
              <p className="font-mono text-white break-all">{credentials.email}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Password</p>
              <p className="font-mono text-cyan-300 break-all">{credentials.password}</p>
            </div>
          </div>
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
            Change it after the first login. Aegis does not store the plaintext value.
          </p>
        </div>
      )}

      <div className="card p-4 flex items-center gap-3 bg-[hsl(var(--secondary)/0.3)]">
        <Search size={15} className="text-[hsl(var(--muted-foreground))]" />
        <input
          data-testid="user-search"
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Search by username, email or role…"
          className="input w-full bg-[hsl(var(--background))]"
        />
        <span className="text-xs text-[hsl(var(--muted-foreground))] whitespace-nowrap">
          {filtered.length} / {users.length}
        </span>
      </div>

      <div className="card overflow-hidden bg-[hsl(var(--secondary)/0.3)]">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-widest text-[hsl(var(--muted-foreground))] border-b border-[hsl(var(--border))]">
                <th className="px-4 py-3">Account</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(u => {
                const isSelf = currentUser?.id === u.id
                return (
                  <tr key={u.id} data-testid={`user-row-${u.id}`} className="border-b border-[hsl(var(--border))]/60 last:border-0">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-white">{u.username}</span>
                        {u.oidc && <span className="px-1.5 py-0.5 rounded text-[9px] border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">SSO</span>}
                        {isSelf && <span className="text-[10px] text-[hsl(var(--muted-foreground))]">(you)</span>}
                      </div>
                      <p className="text-xs text-[hsl(var(--muted-foreground))] break-all">{u.email}</p>
                    </td>
                    <td className="px-4 py-3">
                      <select
                        value={u.role}
                        disabled={busy}
                        onChange={e => update(u.id, { role: e.target.value })}
                        className="input bg-[hsl(var(--background))] text-xs py-1.5 min-w-[130px]"
                        title={ROLES.find(r => r.value === u.role)?.help}
                      >
                        {ROLES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
                      </select>
                    </td>
                    <td className="px-4 py-3">
                      <span className={cn(
                        'inline-flex items-center gap-1 px-2 py-1 rounded-full text-[10px] font-semibold border',
                        u.active
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          : 'bg-red-500/10 text-red-400 border-red-500/20',
                      )}>
                        <span className={cn('w-1.5 h-1.5 rounded-full', u.active ? 'bg-emerald-400' : 'bg-red-400')} />
                        {u.active ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          data-testid={`user-reset-${u.id}`}
                          onClick={() => resetPassword(u)}
                          disabled={busy}
                          className="btn btn-ghost btn-sm border border-[hsl(var(--border))]"
                          title="Generate a new temporary password"
                        >
                          <KeyRound size={13} /> Reset
                        </button>
                        <button
                          data-testid={`user-toggle-${u.id}`}
                          onClick={() => update(u.id, { active: !u.active })}
                          disabled={busy}
                          className={cn('btn btn-ghost btn-sm border border-[hsl(var(--border))]',
                            u.active ? 'hover:text-red-400 hover:bg-red-500/10' : 'hover:text-emerald-400 hover:bg-emerald-500/10')}
                        >
                          {u.active ? 'Disable' : 'Enable'}
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
              {!filtered.length && (
                <tr>
                  <td colSpan={4} className="px-4 py-12 text-center text-[hsl(var(--muted-foreground))]">
                    {loading ? 'Loading accounts…' : 'No accounts match the filter.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card p-5 bg-[hsl(var(--secondary)/0.2)] border-dashed">
        <div className="flex items-center gap-2 mb-2">
          <ShieldCheck size={16} className="text-cyan-400" />
          <h3 className="text-sm font-bold text-white">Role model</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {ROLES.map(r => (
            <div key={r.value} className="text-xs">
              <span className="font-semibold text-white">{r.label}</span>
              <span className="text-[hsl(var(--muted-foreground))]"> — {r.help}</span>
            </div>
          ))}
        </div>
        <p className="text-[11px] text-[hsl(var(--muted-foreground))] mt-3">
          The last active admin cannot be disabled or demoted. Local admin accounts remain the break-glass path when SSO is unavailable.
        </p>
      </div>

      {showCreate && (
        <Modal title="Create account" onClose={() => setShowCreate(false)}>
          <form onSubmit={create} className="space-y-4">
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Username</label>
              <input data-testid="user-username" required minLength={3} maxLength={150} pattern="[A-Za-z0-9._\-]+"
                value={form.username} onChange={e => setForm({ ...form, username: e.target.value })}
                className="input w-full bg-[hsl(var(--background))] mt-1" placeholder="jdoe" />
            </div>
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Email</label>
              <input data-testid="user-email" required type="email" value={form.email}
                onChange={e => setForm({ ...form, email: e.target.value })}
                className="input w-full bg-[hsl(var(--background))] mt-1" placeholder="jdoe@company.local" />
            </div>
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Role</label>
              <select data-testid="user-role" value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}
                className="input w-full bg-[hsl(var(--background))] mt-1">
                {ROLES.map(r => <option key={r.value} value={r.value}>{r.label} — {r.help}</option>)}
              </select>
            </div>
            <div>
              <div className="flex items-center justify-between">
                <label className="text-[10px] font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Temporary password</label>
                <button type="button" onClick={() => setForm({ ...form, password: newPassword() })}
                  className="text-[10px] text-cyan-400 hover:text-cyan-300">Generate new</button>
              </div>
              <input data-testid="user-password" required minLength={12} value={form.password}
                onChange={e => setForm({ ...form, password: e.target.value })}
                className="input w-full bg-[hsl(var(--background))] mt-1 font-mono text-sm" />
              <p className="text-[10px] text-[hsl(var(--muted-foreground))] mt-1">
                Shown only after creation. The user should change it after the first login.
              </p>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" onClick={() => setShowCreate(false)} className="btn btn-ghost border border-[hsl(var(--border))]">Cancel</button>
              <button data-testid="user-create-submit" type="submit" disabled={busy} className="btn btn-primary">
                {busy ? 'Creating…' : 'Create account'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  )
}
