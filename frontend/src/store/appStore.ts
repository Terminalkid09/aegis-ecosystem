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
      setUser: (user) => set({ user }),
      login: (token, user) => {
        // The server sets an HttpOnly cookie. The token stays in memory only
        // for backwards-compatible state shape and is never persisted.
        set({ token: token || 'cookie-session', user })
      },
      logout: () => {
        set({ token: null, user: null })
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
      }),
    }
  )
)
