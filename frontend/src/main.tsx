import './index.css'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.tsx'

// Una tab aperta mentre il frontend viene ricostruito conserva i nomi dei chunk
// lazy della build precedente. Dopo il deploy quei file non esistono più e le
// pagine falliscono finché l'utente non ricarica a mano. Vite emette
// `vite:preloadError` in quel caso: ricarichiamo una sola volta (la guardia in
// sessionStorage evita un loop se anche la nuova build è irraggiungibile).
const CHUNK_RELOAD_KEY = 'aegis-chunk-reload-at'
window.addEventListener('vite:preloadError', (event) => {
  event.preventDefault()
  try {
    const last = Number(sessionStorage.getItem(CHUNK_RELOAD_KEY) || 0)
    if (Date.now() - last < 30_000) return
    sessionStorage.setItem(CHUNK_RELOAD_KEY, String(Date.now()))
  } catch {
    // Storage non disponibile: meglio un reload che una pagina vuota.
  }
  window.location.reload()
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
