import {
  Shield,
  LayoutDashboard,
  AlertTriangle,
  Monitor,
  Network,
  Rocket,
  Search,
  FileSearch,
  Bot,
  Lock,
  BookOpen,
  BookMarked,
  FileText,
  ScrollText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Menu,
  LogOut,
  User,
  Zap,
  Database,
  SearchCode,
} from 'lucide-react'
import { type Page, useAppStore } from '@/store/appStore'
import { cn } from '@/lib/utils'
import { authAPI } from '@/services/api'

const NAV_ITEMS: { id: Page; label: string; icon: React.ElementType; section?: string }[] = [
  { id: 'dashboard',  label: 'Dashboard',      icon: LayoutDashboard, section: 'MONITOR' },
  { id: 'alerts',     label: 'Alerts',          icon: AlertTriangle },
  { id: 'agents',     label: 'Endpoints',       icon: Monitor },
  { id: 'incidents',  label: 'Incidents',       icon: Zap },
  { id: 'discovery',  label: 'Discovery',       icon: Network,         section: 'INVESTIGATE' },
  { id: 'sentinel',   label: 'SentinelX',       icon: Search },
  { id: 'total',      label: 'Aegis Total',     icon: FileSearch },
  { id: 'ai',         label: 'AI Chat',         icon: Bot },
  { id: 'search',     label: 'Log Search',      icon: SearchCode,      section: 'SIEM' },
  { id: 'logsources', label: 'Log Sources',     icon: Database },
  { id: 'deploy',     label: 'Deploy',          icon: Rocket,          section: 'MANAGE' },
  { id: 'playbooks',  label: 'Playbooks',       icon: BookOpen },
  { id: 'rules',      label: 'Rules',           icon: BookMarked },
  { id: 'vault',      label: 'VaultX',          icon: Lock },
  { id: 'audit',      label: 'Audit Log',       icon: FileText,        section: 'LOGS' },
  { id: 'syslog',     label: 'Syslog',          icon: ScrollText },
  { id: 'settings',   label: 'Settings',        icon: Settings,        section: 'SYSTEM' },
]

export function Sidebar() {
  const { currentPage, setCurrentPage, user, logout, liveStats, sidebarCollapsed, toggleSidebar } = useAppStore()

  const criticalCount = liveStats?.current_critical_alerts ?? 0

  async function handleLogout() {
    try { await authAPI.logout() } catch {}
    logout()
  }

  return (
    <aside
      className={cn(
        'flex flex-col h-screen border-r border-[hsl(var(--border))] bg-[hsl(var(--card))] transition-all duration-200 shrink-0',
        sidebarCollapsed ? 'w-14' : 'w-56'
      )}
    >
      {/* Logo */}
      <div className="flex items-center justify-between px-3 py-4 border-b border-[hsl(var(--border))]">
        {!sidebarCollapsed && (
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-[hsl(var(--primary)/0.15)] border border-[hsl(var(--primary)/0.25)]">
              <Shield size={16} className="text-[hsl(var(--primary))]" />
            </div>
            <span className="font-bold text-sm tracking-wider text-white">AEGIS</span>
            {criticalCount > 0 && (
              <span className="badge badge-critical animate-pulse-glow ml-1">{criticalCount}</span>
            )}
          </div>
        )}
        {sidebarCollapsed && (
          <div className="mx-auto p-1.5 rounded-lg bg-[hsl(var(--primary)/0.15)] border border-[hsl(var(--primary)/0.25)]">
            <Shield size={16} className="text-[hsl(var(--primary))]" />
          </div>
        )}
        {!sidebarCollapsed && (
          <button
            onClick={toggleSidebar}
            className="p-1 rounded text-[hsl(var(--muted-foreground))] hover:text-white hover:bg-[hsl(var(--secondary))] transition-colors"
          >
            <ChevronLeft size={14} />
          </button>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2 py-2 space-y-0.5">
        {NAV_ITEMS.map((item) => (
          <div key={item.id}>
            {item.section && !sidebarCollapsed && (
              <p className="text-[10px] font-semibold tracking-widest text-[hsl(var(--muted-foreground))] px-2 pt-4 pb-1 uppercase">
                {item.section}
              </p>
            )}
            <button
              id={`nav-${item.id}`}
              onClick={() => setCurrentPage(item.id)}
              className={cn(
                'sidebar-item w-full text-left',
                currentPage === item.id && 'active',
                sidebarCollapsed && 'justify-center px-0'
              )}
              title={sidebarCollapsed ? item.label : undefined}
            >
              <item.icon size={16} className="shrink-0" />
              {!sidebarCollapsed && <span>{item.label}</span>}
              {!sidebarCollapsed && item.id === 'alerts' && criticalCount > 0 && (
                <span className="ml-auto badge badge-critical">{criticalCount}</span>
              )}
            </button>
          </div>
        ))}
      </nav>

      {/* User + collapse */}
      <div className="border-t border-[hsl(var(--border))] p-2 space-y-1">
        {sidebarCollapsed ? (
          <button
            onClick={toggleSidebar}
            className="w-full flex justify-center p-2 rounded text-[hsl(var(--muted-foreground))] hover:text-white hover:bg-[hsl(var(--secondary))] transition-colors"
          >
            <ChevronRight size={14} />
          </button>
        ) : user ? (
          <div className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-[hsl(var(--secondary))]">
            <div className="w-7 h-7 rounded-full bg-[hsl(var(--primary)/0.2)] flex items-center justify-center text-[hsl(var(--primary))] shrink-0">
              <User size={12} />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-white truncate">{user.username}</p>
              <p className="text-[10px] text-[hsl(var(--muted-foreground))] truncate uppercase">{user.role}</p>
            </div>
            <button
              onClick={handleLogout}
              title="Logout"
              className="p-1 rounded text-[hsl(var(--muted-foreground))] hover:text-red-400 transition-colors"
            >
              <LogOut size={12} />
            </button>
          </div>
        ) : null}
      </div>
    </aside>
  )
}
