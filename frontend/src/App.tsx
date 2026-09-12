import { Suspense, lazy, useEffect } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useAppStore } from '@/store/appStore'
import { useLiveStats } from '@/hooks/useLiveStats'
import { Sidebar } from '@/components/layout/Sidebar'
import LoginModal from '@/components/pages/LoginModal'
import DashboardOverview from '@/components/pages/DashboardOverview'
import AlertsTable from '@/components/pages/AlertsTable'
import { authAPI } from '@/services/api'

// Lazy-load heavy pages
const AgentsList     = lazy(() => import('@/components/pages/AgentsList'))
const DiscoveryCenter= lazy(() => import('@/components/pages/DiscoveryCenter'))
const DeployManager  = lazy(() => import('@/components/pages/DeployManager'))
const SentinelX      = lazy(() => import('@/components/pages/SentinelX'))
const AegisTotal     = lazy(() => import('@/components/pages/AegisTotal'))
const AIChat         = lazy(() => import('@/components/pages/AIChat'))
const VaultX         = lazy(() => import('@/components/pages/VaultX'))
const PlaybookManager= lazy(() => import('@/components/pages/PlaybookManager'))
const RulesManager   = lazy(() => import('@/components/pages/RulesManager'))
const Incidents      = lazy(() => import('@/components/pages/Incidents'))
const AuditLogViewer = lazy(() => import('@/components/pages/AuditLogViewer'))
const SyslogViewer   = lazy(() => import('@/components/pages/SyslogViewer'))
const SettingsPage   = lazy(() => import('@/components/pages/SettingsPage'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 10_000,
    },
  },
})

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64 text-[hsl(var(--muted-foreground))]">
      <div className="flex items-center gap-2">
        <svg className="animate-spin h-5 w-5" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.4 0 0 5.4 0 12h4z" />
        </svg>
        Loading…
      </div>
    </div>
  )
}

function AppShell() {
  const { user, setUser, currentPage } = useAppStore()

  // Hydrate user from token on app start
  useEffect(() => {
    if (!user) {
      authAPI.me().then(r => setUser(r.data)).catch(() => {})
    }
  }, [user, setUser])

  // Start live WS stats
  useLiveStats()

  if (!user) return <LoginModal />

  const PAGE_MAP: Record<string, React.ReactNode> = {
    dashboard:  <DashboardOverview />,
    alerts:     <AlertsTable />,
    agents:     <AgentsList />,
    discovery:  <DiscoveryCenter />,
    deploy:     <DeployManager />,
    sentinel:   <SentinelX />,
    total:      <AegisTotal />,
    ai:         <AIChat />,
    vault:      <VaultX />,
    playbooks:  <PlaybookManager />,
    rules:      <RulesManager />,
    incidents:  <Incidents />,
    audit:      <AuditLogViewer />,
    syslog:     <SyslogViewer />,
    settings:   <SettingsPage />,
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-7xl mx-auto px-6 py-6">
          <Suspense fallback={<PageLoader />}>
            {PAGE_MAP[currentPage] ?? <DashboardOverview />}
          </Suspense>
        </div>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppShell />
    </QueryClientProvider>
  )
}
