import { useState } from 'react'
import { Shield, Mail, Lock, Eye, EyeOff, AlertCircle } from 'lucide-react'
import { authAPI } from '@/services/api'
import { useAppStore } from '@/store/appStore'

const LAST_EMAIL_KEY = 'aegis-last-email'

export default function LoginModal() {
  const { login } = useAppStore()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  // L'email dell'ultimo login su questo browser e' precompilata: dopo una
  // scadenza di sessione l'utente digita solo la password.
  const [email, setEmail] = useState(() => {
    try { return localStorage.getItem(LAST_EMAIL_KEY) ?? '' } catch { return '' }
  })
  const [password, setPassword] = useState('')
  const [username, setUsername] = useState('')
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      if (mode === 'login') {
        const res = await authAPI.login(email, password)
        const body = res.data
        const token = body.access_token ?? body.accessToken ?? body.token
        if (token) {
          const user = body.user ?? (await authAPI.me().then(r => r.data))
          try { localStorage.setItem(LAST_EMAIL_KEY, email) } catch {}
          login(token, user)
        }
      } else {
        await authAPI.register({ username, email, password })
        const res = await authAPI.login(email, password)
        const body = res.data
        const token = body.access_token ?? body.token
        if (token) {
          const user = body.user ?? (await authAPI.me().then(r => r.data))
          login(token, user)
        }
      }
    } catch (err: any) {
      const msg = err?.response?.data?.detail ?? err?.message ?? 'Authentication failed'
      setError(typeof msg === 'string' ? msg : JSON.stringify(msg))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[hsl(var(--background))] flex items-center justify-center p-4">
      {/* Background glow */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-[hsl(var(--primary)/0.03)] blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-[400px] h-[400px] rounded-full bg-purple-500/3 blur-3xl" />
      </div>

      <div className="relative w-full max-w-sm animate-slide-in">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-[hsl(var(--primary)/0.15)] border border-[hsl(var(--primary)/0.25)] mb-4">
            <Shield size={28} className="text-[hsl(var(--primary))]" />
          </div>
          <h1 className="text-2xl font-bold text-white">Aegis Ecosystem</h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-1">Enterprise Security Platform</p>
        </div>

        {/* Card */}
        <div className="glass p-8 space-y-5">
          {/* Mode tabs */}
          <div className="flex gap-1 p-1 rounded-lg bg-[hsl(var(--secondary))]">
            {(['login', 'register'] as const).map(m => (
              <button
                key={m}
                onClick={() => { setMode(m); setError(null) }}
                className={`flex-1 py-1.5 text-sm font-medium rounded-md transition-all ${
                  mode === m
                    ? 'bg-[hsl(var(--card))] text-white shadow'
                    : 'text-[hsl(var(--muted-foreground))] hover:text-white'
                }`}
              >
                {m === 'login' ? 'Sign In' : 'Register'}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'register' && (
              <div>
                <label className="text-xs text-[hsl(var(--muted-foreground))] font-medium mb-1.5 block uppercase tracking-wider">Username</label>
                <input
                  className="input"
                  type="text"
                  placeholder="johndoe"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  required
                  autoComplete="username"
                />
              </div>
            )}

            <div>
              <label className="text-xs text-[hsl(var(--muted-foreground))] font-medium mb-1.5 block uppercase tracking-wider">Email</label>
              <div className="relative">
                <Mail size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
                <input
                  className="input pl-9"
                  type="email"
                  data-testid="login-email"
                  placeholder="you@company.local"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  required
                  autoComplete="email"
                />
              </div>
            </div>

            <div>
              <label className="text-xs text-[hsl(var(--muted-foreground))] font-medium mb-1.5 block uppercase tracking-wider">Password</label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
                <input
                  className="input pl-9 pr-10"
                  type={showPass ? 'text' : 'password'}
                  data-testid="login-password"
                  placeholder="••••••••"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))] hover:text-white transition-colors"
                >
                  {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs">
                <AlertCircle size={14} className="shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary w-full justify-center py-2.5 text-sm font-semibold"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.4 0 0 5.4 0 12h4z" />
                  </svg>
                  Authenticating…
                </span>
              ) : mode === 'login' ? 'Sign In' : 'Create Account'}
            </button>
          </form>

          <p className="text-center text-xs text-[hsl(var(--muted-foreground))]">
            Protected by Aegis Security Platform
          </p>
        </div>
      </div>
    </div>
  )
}
