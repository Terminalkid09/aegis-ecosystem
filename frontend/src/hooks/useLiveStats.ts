import { useEffect, useRef } from 'react'
import { useAppStore } from '@/store/appStore'

const WS_BASE = (import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1')
  .replace(/^https/, 'wss')
  .replace(/^http/, 'ws')
  .replace(/\/api\/v1$/, '/api/v1/ws/overview')

export function useLiveStats() {
  const { user, settings, setLiveStats } = useAppStore()
  const wsRef = useRef<WebSocket | null>(null)
  const pingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    if (!settings.autoRefresh || !user) return

    const url = WS_BASE

    function connect() {
      const prev = wsRef.current
      if (prev) prev.close()
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          if (data.type === 'overview' || data.active_agents !== undefined) {
            setLiveStats(data)
          }
        } catch {}
      }

      ws.onerror = () => console.warn('[Aegis WS] error, will reconnect')
      ws.onclose = () => {
        // Riconnette SOLO se questo socket e' ancora quello corrente: se e'
        // stato sostituito da un connect() piu' recente, il suo onclose non
        // deve a sua volta schedulare un'altra connessione (doppio loop).
        if (wsRef.current !== ws) return
        // Il browser riusa il cookie aggiornato dal rinnovo silenzioso:
        // una sessione viva si ricollega da sola senza intervento utente.
        setTimeout(connect, 5000)
      }
    }

    connect()

    // Heartbeat ping every 25s to keep the connection alive
    pingRef.current = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send('ping')
      }
    }, 25000)

    return () => {
      wsRef.current?.close()
      if (pingRef.current) clearInterval(pingRef.current)
    }
  }, [user, settings.autoRefresh, setLiveStats])
}
