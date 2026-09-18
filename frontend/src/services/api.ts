import axios from 'axios'
import { useAppStore } from '@/store/appStore'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
})

// Expired session: a 401 must not leave the UI stuck in error on every page
// (the symptom was "sometimes other pages break too"): the auth state is
// cleared so App.tsx shows the login again. Login/me are excluded because a
// 401 there is the expected answer, not a lost session.
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status
    const url: string = error?.config?.url || ''
    if (status === 401 && !url.includes('/auth/login') && !url.includes('/auth/me')) {
      useAppStore.getState().logout()
    }
    return Promise.reject(error)
  },
)

// ─── Auth ───────────────────────────────────────────────────────────────────
export const authAPI = {
  login: (email: string, password: string) => apiClient.post('/auth/login', { email, password }),
  register: (data: { username: string; email: string; password: string }) => apiClient.post('/auth/register', data),
  me: () => apiClient.get('/auth/me'),
  logout: () => apiClient.post('/auth/logout'),
}

// ─── Telemetry / Stats ───────────────────────────────────────────────────────
export const statsAPI = {
  getStats: () => apiClient.get('/telemetry/stats'),
  getRecentTelemetry: (params = {}) => apiClient.get('/telemetry/recent', { params }),
  getActivity: (params = {}) => apiClient.get('/telemetry/activity', { params }),
  getAgents: (params = {}) => apiClient.get('/telemetry/agents', { params }),
  isolateAgent: (agentId: string, reason: string) => apiClient.post(`/telemetry/agents/${agentId}/isolate`, { reason }),
  releaseAgent: (agentId: string) => apiClient.post(`/telemetry/agents/${agentId}/release`),
}

export const agentsAPI = statsAPI

// ─── Health radice (audit: NON sotto /api/v1 — il brain espone /health/*
// al root; prima si chiamava /api/v1/health/* = 404 silenzioso con strip
// sempre "unknown"). Deriva l'origin togliendo il suffisso /api/v1.
const API_ORIGIN = API_BASE_URL.replace(/\/api\/v1\/?$/, '') || window.location.origin
export const healthAPI = {
  live: () => axios.get(`${API_ORIGIN}/health/live`, { timeout: 10000 }),
  ready: () => axios.get(`${API_ORIGIN}/health/ready`, { timeout: 10000 }),
}

// ─── Fleet M7: siti e stato ──────────────────────────────────────────────
export const fleetAPI = {
  assignSite: (agentId: string, site: string) =>
    apiClient.patch(`/telemetry/agents/${agentId}/site`, { site }),
}

// ─── Detection replay M4 ─────────────────────────────────────────────────
export const replayAPI = {
  run: (includeCanary = false) => apiClient.post('/rules/replay', { include_canary: includeCanary }),
}

// ─── Playbook dry-run M5 ─────────────────────────────────────────────────
export const dryRunAPI = {
  playbook: (id: number, alertId: number) =>
    apiClient.post(`/soar/playbooks/${id}/dry-run`, { alert_id: alertId }),
}

// ─── Integrazioni (chiavi API provider, es. OSINT) ─────────────────────
export const integrationsAPI = {
  status: () => apiClient.get('/integrations/settings'),
  setKey: (provider: string, value: string) =>
    apiClient.put('/integrations/settings', { provider, value }),
}

// ─── YARA & FIM ─────────────────────────────────────────────────────────────
export const yaraAPI = {
  list: () => apiClient.get('/yara/rules'),
  create: (data: { name: string; content: string; is_active: boolean }) => apiClient.post('/yara/rules', data),
  update: (id: number, data: { name?: string; content?: string; is_active?: boolean }) => apiClient.put(`/yara/rules/${id}`, data),
  remove: (id: number) => apiClient.delete(`/yara/rules/${id}`),
  scan: (agentId: string, targets: string[]) => apiClient.post(`/yara/agents/${agentId}/scan`, { targets }),
}

export const fimAPI = {
  get: (agentId: string) => apiClient.get(`/fim/agents/${agentId}/fim-watchlist`),
  set: (agentId: string, paths: string[], recursive: boolean) =>
    apiClient.put(`/fim/agents/${agentId}/fim-watchlist`, { paths, recursive }),
  reset: (agentId: string) => apiClient.delete(`/fim/agents/${agentId}/fim-watchlist`),
}

// ─── Device PKI M6 ───────────────────────────────────────────────────────
export const pkiAPI = {
  caCert: () => apiClient.get('/enroll/ca.crt'),
  revokeAgent: (agentId: string, reason = '') =>
    apiClient.post(`/enroll/agents/${agentId}/revoke`, { reason }),
  certStatus: (agentId: string) => apiClient.get(`/enroll/agents/${agentId}/certificate-status`),
  manifest: () => apiClient.get('/deploy/manifest'),
}

// ─── Alerts ──────────────────────────────────────────────────────────────────
export const alertsAPI = {
  getAlerts: (params = {}) => apiClient.get('/telemetry/alerts', { params }),
  getAlert: (id: number) => apiClient.get(`/telemetry/alerts/${id}`),
  resolveAlert: (id: number, resolved = true) => apiClient.patch(`/telemetry/alerts/${id}/resolve`, { resolved }),
  resolveAll: () => apiClient.post('/telemetry/alerts/resolve-all'),
  deleteAll: () => apiClient.delete('/telemetry/alerts'),
}

// ─── Deploy ───────────────────────────────────────────────────────────────────
export const deployAPI = {
  createToken: (data: object) => apiClient.post('/deploy/token', data),
  listTokens: () => apiClient.get('/deploy/token'),
  revokeToken: (id: number) => apiClient.post(`/deploy/token/${id}/revoke`),
  listArtifacts: () => apiClient.get('/deploy/artifacts'),
  createJob: (data: object) => apiClient.post('/deploy/jobs', data, { timeout: 60000 }),
  listJobs: () => apiClient.get('/deploy/jobs'),
  getJob: (id: number) => apiClient.get(`/deploy/jobs/${id}`),
  pushUpdate: (agentId: string, version: string) => apiClient.post('/deploy/update-command', { agent_id: agentId, version }),
}

// ─── Discovery ────────────────────────────────────────────────────────────────
export const discoveryAPI = {
  scan: (data: object) => apiClient.post('/discovery/scan', data, { timeout: 120000 }),
  getHosts: () => apiClient.get('/discovery/hosts'),
  addManualHost: (data: object) => apiClient.post('/discovery/hosts/manual', data),
  getReputation: (params = {}) => apiClient.get('/discovery/reputation', { params }),
  upsertReputation: (data: object) => apiClient.post('/discovery/reputation', data),
  syncAgentStatus: () => apiClient.post('/discovery/sync-agent-status'),
  scanViaAgent: (agentId: string, data: object) => apiClient.post(`/discovery/scan-via-agent/${agentId}`, data, { timeout: 120000 }),
  startDemo: () => apiClient.post('/discovery/demo/start'),
  demoHeartbeat: () => apiClient.post('/discovery/demo/heartbeat'),
  deploymentPlan: (data: object) => apiClient.post('/discovery/deployment/plan', data),
}

// ─── OSINT / SentinelX ───────────────────────────────────────────────────────
export const osintAPI = {
  ipLookup: (ip: string, force = false) => apiClient.get(`/osint/ip/${ip}`, { params: { force } }),
  domainLookup: (domain: string, force = false) => apiClient.get(`/osint/domain/${domain}`, { params: { force } }),
  getHistory: (params = {}) => apiClient.get('/osint/history', { params }),
}

// ─── Aegis Total ─────────────────────────────────────────────────────────────
export const totalAPI = {
  getDisclaimer: () => apiClient.get('/total/disclaimer'),
  // Audit 2026-09: la UI prometteva formati non supportati e rifiutava .pe /
  // archivi. Ora la lista accettata è letta dal backend (unica fonte di verità).
  getFormats: () => apiClient.get('/total/formats'),
  listReports: () => apiClient.get('/total/reports'),
  getReport: (sha256: string) => apiClient.get(`/total/reports/${sha256}`),
  deleteReport: (sha256: string) => apiClient.delete(`/total/reports/${sha256}`),
  upload: (file: File, acceptDisclaimer = true) => {
    const fd = new FormData()
    fd.append('file', file)
    fd.append('accept_disclaimer', acceptDisclaimer ? 'true' : 'false')
    return apiClient.post('/total/upload', fd, { timeout: 300000, headers: { 'Content-Type': 'multipart/form-data' } })
  },
}

export const aiAPI = {
  status: () => apiClient.get('/ai/status'),
  getSettings: () => apiClient.get('/ai/settings'),
  setSettings: (data: { provider?: string; model?: string; automatic_enrich?: boolean }) =>
    apiClient.put('/ai/settings', data),
  chat: (prompt: string, model?: string | undefined, threadId?: string | number | null) =>
    apiClient.post('/ai/chat', { prompt, model, thread_id: threadId }, { timeout: 300000 }),
  getThreads: () => apiClient.get('/ai/threads'),
  getMessages: (threadId: string | number) => apiClient.get(`/ai/threads/${threadId}/messages`),
  deleteThread: (threadId: string | number) => apiClient.delete(`/ai/threads/${threadId}`),
}

// ─── Vault ───────────────────────────────────────────────────────────────────
export const vaultAPI = {
  getNotes: () => apiClient.get('/vault/notes'),
  createNote: (data: object) => apiClient.post('/vault/notes', data),
  deleteNote: (id: string | number) => apiClient.delete(`/vault/notes/${id}`),
}

// ─── Playbooks / SOAR ────────────────────────────────────────────────────────
export const playbookAPI = {
  getPlaybooks: () => apiClient.get('/soar/playbooks'),
  createPlaybook: (data: object) => apiClient.post('/soar/playbooks', data),
  updatePlaybook: (id: number, data: object) => apiClient.put(`/soar/playbooks/${id}`, data),
  deletePlaybook: (id: number) => apiClient.delete(`/soar/playbooks/${id}`),
  getExecutions: (params = {}) => apiClient.get('/soar/playbook-executions', { params }),
}

// ─── Incidents (SOC) ─────────────────────────────────────────────────────────
export const incidentsAPI = {
  list: (params = {}) => apiClient.get('/soc/incidents', { params }),
  get: (id: number) => apiClient.get(`/soc/incidents/${id}`),
  create: (data: object) => apiClient.post('/soc/incidents', data),
  update: (id: number, data: object) => apiClient.patch(`/soc/incidents/${id}`, data),
  attach: (id: number, alertIds: number[]) => apiClient.post(`/soc/incidents/${id}/alerts`, alertIds),
  autoGroup: () => apiClient.post('/soc/incidents/auto-group'),
}

// ─── Audit ───────────────────────────────────────────────────────────────────
export const auditAPI = {
  getLogs: (params = {}) => apiClient.get('/audit/logs', { params }),
}

// ─── Syslog ──────────────────────────────────────────────────────────────────
export const syslogAPI = {
  getEvents: (params = {}) => apiClient.get('/syslog/events', { params }),
}

// ─── SIEM: sorgenti di log, ingestione, ricerca sugli eventi normalizzati ────
export const siemAPI = {
  // Sorgenti configurate + salute (ultimo evento, eventi non riconosciuti)
  getSources: () => apiClient.get('/ingest/sources'),
  createSource: (data: { name: string; parser?: string; source_type?: string; description?: string }) =>
    apiClient.post('/ingest/sources', data),
  // Catalogo dei parser: unica fonte di verità per la UI
  getCatalog: () => apiClient.get('/ingest/catalog'),
  getStats: (hours = 24) => apiClient.get('/ingest/stats', { params: { hours } }),
  getDetectionCoverage: () => apiClient.get('/ingest/detection-coverage'),
  // Prova un parser senza salvare nulla (integrazione di una sorgente nuova)
  testParser: (data: { parser: string; payload: unknown }) => apiClient.post('/ingest/test', data),
  // Ricerca: POST strutturata (filtri) e GET semplice (link condivisibili)
  search: (body: object) => apiClient.post('/search/events', body),
  searchSimple: (params = {}) => apiClient.get('/search/events', { params }),
  getFields: () => apiClient.get('/search/fields'),
  getEventStats: (hours = 24) => apiClient.get('/search/stats', { params: { hours } }),
}

// ─── Rules ───────────────────────────────────────────────────────────────────
export const rulesAPI = {
  getCoverage: () => apiClient.get('/rules/coverage'),
  getRules: () => apiClient.get('/rules'),
  createRule: (data: object) => apiClient.post('/rules', data),
  updateRule: (id: number, data: object) => apiClient.patch(`/rules/${id}`, data),
  deleteRule: (id: number) => apiClient.delete(`/rules/${id}`),
}

export default apiClient
