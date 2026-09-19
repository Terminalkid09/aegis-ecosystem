import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAppStore } from '@/store/appStore'

/**
 * Notifiche alert realtime: ascolta il WS /ws/alerts e agisce su ogni alert nuovo.
 *
 * Finora i toggle "Desktop Notifications" e "Audio Alarms" erano decorativi:
 * nessun codice li leggeva. Ora davvero:
 * - Desktop Notifications -> Notification API del browser (dopo permission);
 * - Audio Alarms -> breve bip via WebAudio, niente file audio da scaricare.
 *
 * Il WS e' autenticato dal cookie di sessione (HttpOnly): nessun token nell'URL.
 */
const WS_ALERTS_BASE = (import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1')
  .replace(/^https/, 'wss')
  .replace(/^http/, 'ws')
  .replace(/\/api\/v1$/, '/api/v1/ws/alerts')

function beep() {
  try {
    const Ctx = window.AudioContext || (window as any).webkitAudioContext
    if (!Ctx) return
    const ctx = new Ctx()
    const osc = ctx.createOscillator()
    const gain = ctx.createGain()
    osc.connect(gain)
    gain.connect(ctx.destination)
    osc.frequency.value = 880
    gain.gain.setValueAtTime(0.08, ctx.currentTime)
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.35)
    osc.start()
    osc.stop(ctx.currentTime + 0.35)
    osc.onended = () => ctx.close()
  } catch { /* audio non disponibile: silenzioso */ }
}

export function useAlertNotifications() {
  const { user, settings } = useAppStore()
  const settingsRef = useRef(settings)
  settingsRef.current = settings
  const wsRef = useRef<WebSocket | null>(null)
  const queryClient = useQueryClient()

  useEffect(() => {
    if (!user) return

    // Permission la chiediamo solo se l'utente ha acceso il toggle: senza questo,
    // il primo accesso mostrerebbe il prompt del browser senza motivo.
    if (settingsRef.current.notifications && 'Notification' in window
        && Notification.permission === 'default') {
      Notification.requestPermission().catch(() => {})
    }

    let stopped = false

    function connect() {
      if (stopped) return
      const prev = wsRef.current
      if (prev) prev.close()
      const ws = new WebSocket(WS_ALERTS_BASE)
      wsRef.current = ws

      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          if (data.type !== 'alert') return
          const s = settingsRef.current

          if (s.notifications && 'Notification' in window && Notification.permission === 'granted') {
            const n = new Notification(`Aegis ${data.severity ?? 'ALERT'}`, {
              body: `${data.process_name ?? ''} — ${data.description ?? ''}`.slice(0, 180),
              tag: `aegis-alert-${data.id}`,
            })
            n.onclick = () => { window.focus(); n.close() }
          }
          if (s.soundAlerts) beep()

          // Gli alert list si aggiornano al giro di query: questa invalidazione
          // rende immediato quello che prima aspettava il refetch periodico.
          queryClient.invalidateQueries({ queryKey: ['alerts'] })
          queryClient.invalidateQueries({ queryKey: ['stats'] })
        } catch { /* payload non valido: ignora */ }
      }

      ws.onerror = () => console.warn('[Aegis alerts WS] error, will reconnect')
      ws.onclose = () => {
        if (wsRef.current !== ws) return
        setTimeout(connect, 5000)
      }
    }

    connect()
    return () => { stopped = true; wsRef.current?.close() }
  }, [user?.id, queryClient])
}
