import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type Page =
  | 'dashboard'
  | 'alerts'
  | 'agents'
  | 'discovery'
  | 'deploy'
  | 'sentinel'
  | 'total'
  | 'ai'
  | 'vault'
  | 'playbooks'
  | 'rules'
  | 'incidents'
  | 'audit'
  | 'syslog'
  | 'logsources'
  | 'search'
  | 'yara'
  | 'settings'

interface User {
  id: number
  username: string
  email: string
  role: string
}

interface Settings {
  autoRefresh: boolean
  notifications: boolean
  soundAlerts: boolean
}

interface LiveStats {
  active_agents: number
  demo_agents: number
  total_alerts: number
  unresolved_alerts: number
  current_critical_alerts: number
  current_high_alerts: number
  current_medium_alerts: number
}

interface AppState {
  // Navigation
  currentPage: Page
  setCurrentPage: (page: Page) => void

  // Auth
  user: User | null
  setUser: (user: User | null) => void
  token: string | null
  login: (token: string, user: User) => void
  logout: () => void
  // Cambia a ogni login/logout. Le richieste portano l'epoca in cui sono
  // partite: cosi' un 401 che arriva da una richiesta iniziata PRIMA del login
  // (sessione vecchia) non chiude la sessione appena aperta. Partiva da qui il
  // sintomo "dopo il re-login la pagina da errore finche' non la ricarico".
  sessionEpoch: number
  // True once a login succeeded on this browser: it tells the app there is a
  // session cookie worth validating on the next load. A first-time visitor has
  // no session, so probing /auth/me would only produce a guaranteed 401.
  sessionHint: boolean

  // Live WS data
  liveStats: LiveStats | null
  setLiveStats: (stats: LiveStats) => void

  // Settings
  settings: Settings
  setSetting: <K extends keyof Settings>(key: K, value: Settings[K]) => void
  setSettings: (partial: Partial<Settings>) => void
  resetSettings: () => void
  toggleSetting: (key: keyof Settings) => void

  // Sidebar
  sidebarCollapsed: boolean
  toggleSidebar: () => void
}

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      // Navigation
      currentPage: 'dashboard',
      setCurrentPage: (page) => set({ currentPage: page }),

      // Auth
      user: null,
      token: null,
      sessionHint: false,
      sessionEpoch: 0,
      setUser: (user) => set({ user }),
      login: (token, user) => {
        // The server sets an HttpOnly cookie. The token stays in memory only
        // for backwards-compatible state shape and is never persisted.
        set((state) => ({
          token: token || 'cookie-session',
          user,
          sessionHint: true,
          sessionEpoch: state.sessionEpoch + 1,
        }))
      },
      logout: () => {
        set((state) => ({
          token: null,
          user: null,
          sessionHint: false,
          sessionEpoch: state.sessionEpoch + 1,
        }))
      },

      // Live stats
      liveStats: null,
      setLiveStats: (liveStats) => set({ liveStats }),

      // Settings
      settings: {
        autoRefresh: true,
        notifications: true,
        soundAlerts: false,
      },
      setSetting: (key, value) =>
        set((state) => ({ settings: { ...state.settings, [key]: value } })),
      setSettings: (partial) =>
        set((state) => ({ settings: { ...state.settings, ...partial } })),
      resetSettings: () =>
        set({ settings: { autoRefresh: true, notifications: true, soundAlerts: false } }),
      toggleSetting: (key) =>
        set((state) => ({ settings: { ...state.settings, [key]: !state.settings[key] } })),

      // Sidebar
      sidebarCollapsed: false,
      toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
    }),
    {
      name: 'aegis-store',
      partialize: (state) => ({
        settings: state.settings,
        sidebarCollapsed: state.sidebarCollapsed,
        user: state.user,
        sessionHint: state.sessionHint,
      }),
    }
  )
)
