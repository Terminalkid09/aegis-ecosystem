import type { ReactNode } from 'react'
import { hasAnyPerm, minRoleLabel } from '@/lib/permissions'
import { useAppStore } from '@/store/appStore'

/**
 * Hook: `const can = useCan('respond', 'triage')` — basta uno dei permessi.
 * Specchia `require_perm` del backend (OR-semantics).
 */
export function useCan(...perms: string[]): boolean {
  const user = useAppStore((s) => s.user)
  return hasAnyPerm(user?.role, ...perms)
}

interface PermissionGateProps {
  perms: string[]
  children: ReactNode
  /** 'hide' = non renderizzare; 'disable' = visibile ma non cliccabile con tooltip (default). */
  mode?: 'hide' | 'disable'
  /** Messaggio tooltip personalizzato (default: ruolo minimo richiesto). */
  reason?: string
}

/**
 * Gate dichiarativo per azioni protette da ruolo lato backend.
 *
 * In modalità 'disable' il figlio resta visibile ma i click non arrivano
 * al bottone: doppio span con pointer-events-none sul contenuto e tooltip
 * sul wrapper, così l'utente capisce PERCHÉ è disabilitato invece di
 * scoprirlo da un 403.
 */
export function PermissionGate({ perms, children, mode = 'disable', reason }: PermissionGateProps) {
  const user = useAppStore((s) => s.user)
  const allowed = hasAnyPerm(user?.role, ...perms)

  if (allowed) return <>{children}</>
  if (mode === 'hide') return null

  const hint = reason ?? `Richiede ruolo ${minRoleLabel(...perms)} o superiore`
  return (
    <span title={hint} className="inline-block cursor-not-allowed" onClick={(e) => e.stopPropagation()}>
      <span className="pointer-events-none opacity-50 inline-block">{children}</span>
    </span>
  )
}
