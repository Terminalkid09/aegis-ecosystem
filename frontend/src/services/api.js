import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
const API_KEY = process.env.REACT_APP_API_KEY || '';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    ...(API_KEY && { 'X-Api-Key': API_KEY }),
  },
});

// Add request interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// ALERTS API
export const alertsAPI = {
  getAlerts: (params = {}) => apiClient.get('/alerts', { params }),
  getAlert: (alertId) => apiClient.get(`/alerts/${alertId}`),
  resolveAlert: (alertId, resolved = true) =>
    apiClient.patch(`/alerts/${alertId}/resolve`, { resolved }),
};

// AGENTS API
export const agentsAPI = {
  getAgents: (params = {}) => apiClient.get('/agents', { params }),
};

// STATS API
export const statsAPI = {
  getStats: () => apiClient.get('/stats'),
};

export default apiClient;
