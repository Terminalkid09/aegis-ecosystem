import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const setAuthToken = (token) => {
    if (token) {
        apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        localStorage.setItem('aegis_token', token);
    } else {
        delete apiClient.defaults.headers.common['Authorization'];
        localStorage.removeItem('aegis_token');
    }
};

const savedToken = localStorage.getItem('aegis_token');
if (savedToken) setAuthToken(savedToken);

// INTERCEPTORS
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('aegis_token');
      localStorage.removeItem('aegis_user');
      window.dispatchEvent(new Event('aegis-auth-changed'));
    }
    return Promise.reject(error);
  }
);

// TELEMETRY HISTORY
export const historyAPI = {
    getHistory: (agentId) => apiClient.get(`/telemetry/history/${agentId}`),
};

// ALERTS API
export const alertsAPI = {
  getAlerts: (params = {}) => apiClient.get('/telemetry/alerts', { params }),
  getAlert: (alertId) => apiClient.get(`/telemetry/alerts/${alertId}`),
  resolveAlert: (alertId, resolved = true) =>
    apiClient.patch(`/telemetry/alerts/${alertId}/resolve`, { resolved }),
};

// AGENTS API
export const agentsAPI = {
  getAgents: (params = {}) => apiClient.get('/telemetry/agents', { params }),
};

// STATS API
export const statsAPI = {
  getStats: () => apiClient.get('/telemetry/stats'),
  getRecentTelemetry: (params = {}) => apiClient.get('/telemetry/recent', { params }),
  getActivity: (params = {}) => apiClient.get('/telemetry/activity', { params }),
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
};

// AI-SUITE
export const aiAPI = {
    chat: (prompt, model = null, threadId = null) => apiClient.post('/ai/chat', { prompt, model, thread_id: threadId }, { timeout: 300000 }),
    getThreads: () => apiClient.get('/ai/threads'),
    getMessages: (threadId) => apiClient.get(`/ai/threads/${threadId}/messages`),
};

// AUTH
export const authAPI = {
    login: (email, password) => apiClient.post('/auth/login', { email, username: email.split('@')[0], password }),
    register: (data) => apiClient.post('/auth/register', data),
};

export default apiClient;
