import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { authAPI } from '@/services/api'
import { useAppStore } from '@/store/appStore'

/**
 * Rinnovo silenzioso della sessione.
 *
 * Problema risolto: il cookie di sessione scadeva (60 min fissi) anche mentre
 * l'utente lavorava; al 401 l'interceptor sloggava, e dopo il re-login la
 * dashboard restava nello stato vecchio (cache React Query + WebSocket morti)
 * finché l'utente non refreshava a mano.
 *
 * Comportamento:
 * - rinnovo a meta' della finestra di validita' (default 60 min -> refresh
 *   ogni 30 min) e comunque al ritorno sulla finestra se l'assenza e' stata
 *   lunga (tab chiusa/sospesa = il timer non gira);
 * - un refresh fallito NON slogga (flag __skipAuthWipe): slogga solo il 401
 *   su una richiesta dati reale;
 * - al re-login la cache React Query viene svuotata, cosi' la UI riparte
 *   dai dati freschi invece di mostrare lo stato freezato.
 *
 * Da montare dentro QueryClientProvider (usa useQueryClient).
 */
const RENEW_INTERVAL_MS = 25 * 60 * 1000      // 25 min con TTL 60 min: margine
const AWAY_THRESHOLD_MS = 10 * 60 * 1000      // assenza > 10 min => rinnova

export function useSessionRenewal() {
  const queryClient = useQueryClient()
  const user = useAppStore((s) => s.user)
  const lastAwayRef = useRef<number>(0)

  // Re-login => cache pulita: niente stato vecchio dalla sessione precedente.
  const prevUserIdRef = useRef<number | null>(null)
  useEffect(() => {
    const prev = prevUserIdRef.current
    prevUserIdRef.current = user?.id ?? null
    if (user && prev !== null && prev !== user.id) {
      queryClient.clear()
    }
  }, [user?.id, queryClient])

  // Remember-me: se non c'e' sessione ma il browser ha un dispositivo fidato
  // ("Mantieni l'accesso"), rientra in silenzio senza chiedere le credenziali.
  // Un solo tentativo per montaggio: 401 = nessun trust valido, caso normale.
  const rememberTriedRef = useRef(false)
  useEffect(() => {
    if (user || rememberTriedRef.current) return
    rememberTriedRef.current = true
    authAPI.rememberLogin()
      .then((res: any) => {
        const { access_token: token, user: u } = res.data
        if (u) useAppStore.getState().login(token || 'cookie-session', u)
      })
      .catch(() => { /* nessun dispositivo fidato: si passa dal login */ })
  }, [user?.id])

  useEffect(() => {
    if (!user) return

    let stopped = false
    let renewing = false

    async function renew(reason: string) {
      if (renewing || stopped) return
      renewing = true
      try {
        await authAPI.refresh()
        // Rinnovo ok: i dati li aggiornano le query in background; qui non
        // tocco nulla per non far lampeggiare la UI.
      } catch {
        // 401 qui = sessione davvero persa (rifiutata dal server): i dati
        // in volo riceveranno il 401 e l'interceptor fara' il suo corso.
        console.warn(`[Aegis] session renewal failed (${reason})`)
      } finally {
        renewing = false
      }
    }

    //visibilitychange: il timer non gira a tab chiusa/sospesa; al ritorno
    //rinnovo subito se l'assenza e' stata lunga, invece di aspettare il tick.
    const onVisible = () => {
      if (document.visibilityState !== 'visible') return
      const away = Date.now() - lastAwayRef.current
      if (lastAwayRef.current > 0 && away > AWAY_THRESHOLD_MS) {
        renew(`away ${Math.round(away / 60000)}min`)
      }
    }
    const onHide = () => {
      if (document.visibilityState === 'hidden') lastAwayRef.current = Date.now()
    }

    document.addEventListener('visibilitychange', onVisible)
    window.addEventListener('pagehide', onHide)

    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') renew('timer')
    }, RENEW_INTERVAL_MS)

    return () => {
      stopped = true
      clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisible)
      window.removeEventListener('pagehide', onHide)
    }
  }, [user?.id])
}
