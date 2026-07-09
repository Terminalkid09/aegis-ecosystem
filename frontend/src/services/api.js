import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

const CACHE_TTL = 30000;
const cache = new Map();

function cachedGet(key, fetcher) {
  const now = Date.now();
  const cached = cache.get(key);
  if (cached) {
    if (now - cached.timestamp < CACHE_TTL) {
      return Promise.resolve(cached.data);
    }
    fetcher().then(res => { cache.set(key, { data: res, timestamp: Date.now() }); }).catch(() => {});
    return Promise.resolve(cached.data);
  }
  return fetcher().then(res => { cache.set(key, { data: res, timestamp: now }); return res; });
}

export function invalidateCache(prefix) {
  for (const key of cache.keys()) {
    if (key.startsWith(prefix)) cache.delete(key);
  }
}

export const setAuthToken = (token) => {
    if (token) {
        apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        try { localStorage.setItem('aegis-jwt', token); } catch {}
    } else {
        delete apiClient.defaults.headers.common['Authorization'];
        try { localStorage.removeItem('aegis-jwt'); } catch {}
    }
};

// Restore token from localStorage on module load
try {
    const saved = localStorage.getItem('aegis-jwt');
    if (saved) {
        apiClient.defaults.headers.common['Authorization'] = `Bearer ${saved}`;
    }
} catch {};

// TELEMETRY HISTORY
export const historyAPI = {
    getHistory: (agentId) => apiClient.get(`/telemetry/history/${agentId}`),
};

// ALERTS API
export const alertsAPI = {
  getAlerts: (params = {}) => {
    const cacheKey = 'alerts-' + JSON.stringify(params);
    return cachedGet(cacheKey, () => apiClient.get('/telemetry/alerts', { params }));
  },
  getAlert: (alertId) => apiClient.get(`/telemetry/alerts/${alertId}`),
  resolveAlert: (alertId, resolved = true) => {
    invalidateCache('alerts-');
    return apiClient.patch(`/telemetry/alerts/${alertId}/resolve`, { resolved });
  },
  resolveAllAlerts: () => {
    invalidateCache('alerts-');
    return apiClient.post('/telemetry/alerts/resolve-all');
  },
  deleteAllAlerts: () => {
    invalidateCache('alerts-');
    return apiClient.delete('/telemetry/alerts');
  },
};

// AGENTS API
export const agentsAPI = {
  getAgents: (params = {}) => cachedGet('agents', () => apiClient.get('/telemetry/agents', { params })),
};

// STATS API
export const statsAPI = {
  getStats: (params = {}) => cachedGet('stats', () => apiClient.get('/telemetry/stats', { params })),
  getRecentTelemetry: (params = {}) => cachedGet('recent', () => apiClient.get('/telemetry/recent', { params })),
  getActivity: (params = {}) => cachedGet('activity', () => apiClient.get('/telemetry/activity', { params })),
};

// VAULTX (Encrypted Notes)
export const vaultAPI = {
    getNotes: () => apiClient.get('/vault/notes'),
    createNote: (data) => apiClient.post('/vault/notes', data),
    deleteNote: (id) => apiClient.delete(`/vault/notes/${id}`),
};

// SENTINELX (OSINT)
export const osintAPI = {
    ipLookup: (ip, force = false) => apiClient.get(`/osint/ip/${ip}`, { params: { force } }),
    domainLookup: (domain, force = false) => apiClient.get(`/osint/domain/${domain}`, { params: { force } }),
    getHistory: (params = {}) => apiClient.get('/osint/history', { params }),
};

// DISCOVERY / ENROLLMENT
export const discoveryAPI = {
  scan: (data) => apiClient.post('/discovery/scan', data, { timeout: 120000 }),
  getHosts: () => apiClient.get('/discovery/hosts'),
  upsertReputation: (data) => apiClient.post('/discovery/reputation', data),
  getReputation: (params = {}) => apiClient.get('/discovery/reputation', { params }),
  startDemo: () => apiClient.post('/discovery/demo/start'),
  demoHeartbeat: () => apiClient.post('/discovery/demo/heartbeat'),
  deploymentPlan: (data) => apiClient.post('/discovery/deployment/plan', data),
  autoDeploy: (data) => apiClient.post('/discovery/deploy', data, { timeout: 60000 }),
  syncAgentStatus: () => apiClient.post('/discovery/sync-agent-status'),
  addManualHost: (data) => apiClient.post('/discovery/hosts/manual', data),
  scanViaAgent: (agentId, data) => apiClient.post(`/discovery/scan-via-agent/${agentId}`, data, { timeout: 10000 }),
};

// AI-SUITE
export const aiAPI = {
    chat: (prompt, model = null, threadId = null) => apiClient.post('/ai/chat', { prompt, model, thread_id: threadId }, { timeout: 300000 }),
    getThreads: () => cachedGet('ai-threads', () => apiClient.get('/ai/threads')),
    getMessages: (threadId) => cachedGet(`ai-messages-${threadId}`, () => apiClient.get(`/ai/threads/${threadId}/messages`)),
    deleteThread: (threadId) => { invalidateCache('ai-threads'); invalidateCache(`ai-messages-${threadId}`); return apiClient.delete(`/ai/threads/${threadId}`); },
};

// AUTH
export const authAPI = {
    login: (email, password) => apiClient.post('/auth/login', { email, password }),
    register: (data) => apiClient.post('/auth/register', data),
    me: () => apiClient.get('/auth/me'),
};

// SYSLOG
export const syslogAPI = {
  getEvents: (params = {}) => apiClient.get('/syslog/events', { params }),
};

// AUDIT LOG
export const auditAPI = {
  getLogs: (params = {}) => apiClient.get('/audit/logs', { params }),
};

// SOAR PLAYBOOKS
export const playbookAPI = {
  getPlaybooks: () => apiClient.get('/soar/playbooks'),
  createPlaybook: (data) => apiClient.post('/soar/playbooks', data),
  updatePlaybook: (id, data) => apiClient.put(`/soar/playbooks/${id}`, data),
  deletePlaybook: (id) => apiClient.delete(`/soar/playbooks/${id}`),
  getExecutions: (params = {}) => apiClient.get('/soar/playbook-executions', { params }),
};

export default apiClient;
