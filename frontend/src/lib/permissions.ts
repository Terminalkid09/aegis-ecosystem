/**
 * Specchio esatto di `aegis-brain/app/core/deps.py` (ROLE_PERMISSIONS).
 * Se cambi lì, cambia qui: la UI deve filtrare ESATTAMENTE ciò che il
 * backend applicherebbe, altrimenti nasconde funzioni concesse o mostra
 * pulsanti destinati al 403.
 *
 * Nota di verità (verificata sugli endpoint, non assunta):
 * - la LETTURA di ogni pagina (rules, deploy, playbooks, audit, vault...)
 *   è concessa a qualunque utente autenticato: nessuna pagina è nascosta;
 * - le MUTAZIONI sono filtrate qui azione per azione;
 * - VaultX e AI sono read/write per tutti gli autenticati (com'è lato server).
 */
export const ROLE_PERMISSIONS: Record<string, readonly string[]> = {
  viewer:    ['read'],
  user:      ['read'],
  auditor:   ['read', 'audit'],
  responder: ['read', 'respond'],
  analyst:   ['read', 'audit', 'respond', 'triage', 'deploy', 'rules'],
  admin:     ['read', 'audit', 'respond', 'triage', 'deploy', 'rules', 'manage'],
}

export function permissionsOf(role: string | undefined | null): Set<string> {
  const key = (role || 'user').toLowerCase()
  return new Set(ROLE_PERMISSIONS[key] ?? ROLE_PERMISSIONS.user)
}

/** Basta UNO dei permessi elencati (come require_perm lato server). */
export function hasAnyPerm(role: string | undefined | null, ...perms: string[]): boolean {
  if (perms.length === 0) return true
  const own = permissionsOf(role)
  return perms.some((p) => own.has(p))
}

/** Ruolo minimo leggibile per i tooltip ("Richiede ruolo analyst o superiore"). */
export function minRoleLabel(...perms: string[]): string {
  if (perms.includes('manage')) return 'admin'
  if (perms.includes('triage') || perms.includes('rules') || perms.includes('deploy')) return 'analyst'
  if (perms.includes('respond')) return 'responder'
  if (perms.includes('audit')) return 'auditor'
  return 'viewer'
}
