import React, { createContext, useState, useContext, useEffect, useRef, useCallback } from 'react';
import { authAPI, setAuthToken, apiClient } from '../services/api';

const DashboardContext = createContext();

const DEFAULT_SETTINGS = {
  notifications: true,
  autoRefresh: true,
  darkMode: true,
  soundAlerts: false,
};

export const DashboardProvider = ({ children }) => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [liveStats, setLiveStats] = useState(null);
  const [user, setUser] = useState(null);
  const [showDemo, setShowDemo] = useState(() => {
    try {
      return localStorage.getItem('aegis-show-demo') === 'true';
    } catch { return false; }
  });
  const [aiChatHistory, setAiChatHistory] = useState([
    { role: 'system', content: 'Aegis AI Security Analyst initialized. How can I assist with your forensic investigation?' }
  ]);

  // Discovery state (persists across SPA navigation)
  const [discoveryHosts, setDiscoveryHosts] = useState(() => {
    try { return JSON.parse(sessionStorage.getItem('aegis-discovery-hosts') || 'null') || []; } catch { return []; }
  });
  const [discoveryReputation, setDiscoveryReputation] = useState(() => {
    try { return JSON.parse(sessionStorage.getItem('aegis-discovery-reputation') || 'null') || []; } catch { return []; }
  });
  const [scanInProgress, setScanInProgress] = useState(() => {
    try { return sessionStorage.getItem('aegis-scan-in-progress') === 'true'; } catch { return false; }
  });
  const [scanMessage, setScanMessage] = useState(() => {
    try { return sessionStorage.getItem('aegis-scan-message') || ''; } catch { return ''; }
  });
  const [scanCidr, setScanCidr] = useState(() => {
    try { return localStorage.getItem('aegis-scan-cidr') || '192.168.1.0/24'; } catch { return '192.168.1.0/24'; }
  });

  // Persist discovery state to sessionStorage
  useEffect(() => {
    try { sessionStorage.setItem('aegis-discovery-hosts', JSON.stringify(discoveryHosts)); } catch {}
  }, [discoveryHosts]);
  useEffect(() => {
    try { sessionStorage.setItem('aegis-discovery-reputation', JSON.stringify(discoveryReputation)); } catch {}
  }, [discoveryReputation]);
  useEffect(() => {
    try { sessionStorage.setItem('aegis-scan-in-progress', String(scanInProgress)); } catch {}
  }, [scanInProgress]);
  useEffect(() => {
    try { sessionStorage.setItem('aegis-scan-message', scanMessage); } catch {}
  }, [scanMessage]);
  useEffect(() => {
    try { localStorage.setItem('aegis-scan-cidr', scanCidr); } catch {}
  }, [scanCidr]);

  useEffect(() => {
    try {
      const persisted = localStorage.getItem('aegis-settings');
      if (persisted) {
        const parsed = JSON.parse(persisted);
        setSettings((prev) => ({ ...prev, ...parsed }));
      }
    } catch (err) {
      console.warn('Failed to load persisted settings:', err);
    }
  }, []);

  useEffect(() => {
    const theme = settings.darkMode ? 'dark' : 'light';
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('aegis-settings', JSON.stringify(settings));
  }, [settings]);

  useEffect(() => {
    localStorage.setItem('aegis-show-demo', String(showDemo));
  }, [showDemo]);

  const wsRef = useRef(null);

  useEffect(() => {
    if (!settings.autoRefresh) return;
    const interval = setInterval(() => {
      setRefreshTrigger((prev) => prev + 1);
    }, Number(process.env.REACT_APP_REFRESH_INTERVAL) || 15000);
    return () => clearInterval(interval);
  }, [settings.autoRefresh]);

  useEffect(() => {
    if (!settings.autoRefresh) return;

    const apiUrl = process.env.REACT_APP_API_URL || 'https://aegis.local/api/v1';
    let token = '';
    const authHeader = apiClient.defaults.headers.common['Authorization'];
    if (authHeader) {
      token = authHeader.replace('Bearer ', '');
    } else {
      try { token = localStorage.getItem('aegis-jwt') || ''; } catch {}
    }
    const wsBase = apiUrl.startsWith('https://')
      ? apiUrl.replace(/^https/, 'wss')
      : apiUrl.replace(/^http/, 'ws');
    const wsUrl = wsBase.replace(/\/api\/v1$/, '/api/v1/ws/overview') + (token ? '?token=' + token : '');
    try {
      if (wsRef.current) {
        wsRef.current.close();
      }
      const socket = new WebSocket(wsUrl);
      wsRef.current = socket;
      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'overview' || data.active_agents !== undefined) {
            setLiveStats(data);
          }
        } catch (err) {
          // silent
        }
      };
      socket.onerror = () => {
        console.warn('WebSocket error, falling back to polling');
      };
    } catch (err) {
      console.warn('Live updates unavailable:', err);
    }
    return () => {
      if (wsRef.current && wsRef.current.readyState <= 1) {
        wsRef.current.close();
      }
    };
  }, [settings.autoRefresh]);

  const refreshData = useCallback(() => {
    setRefreshTrigger((prev) => prev + 1);
  }, []);

  const manualRefresh = useCallback(() => {
    refreshData();
  }, [refreshData]);

  const setSetting = useCallback((key, value) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
  }, []);

  const toggleSetting = useCallback((key) => {
    setSettings((prev) => ({ ...prev, [key]: !prev[key] }));
  }, []);

  const resetSettings = useCallback(() => {
    setSettings(DEFAULT_SETTINGS);
    localStorage.removeItem('aegis-settings');
  }, []);

  const checkAuth = useCallback(() => {
    authAPI.me()
      .then(res => setUser(res.data))
      .catch(() => setUser(null));
  }, []);

  const login = useCallback(async (email, password) => {
    const res = await authAPI.login(email, password);
    const body = res.data || res;
    const token = body.access_token || body.accessToken || body.token;
    if (token) {
      setAuthToken(token);
    }
    const userData = body.user || null;
    if (userData) {
      setUser(userData);
    } else {
      await checkAuth();
    }
    return body;
  }, [checkAuth]);

  const logout = useCallback(() => {
    setAuthToken(null);
    setUser(null);
  }, []);

  return (
    <DashboardContext.Provider
      value={{
        currentPage,
        setCurrentPage,
        refreshTrigger,
        refreshData,
        manualRefresh,
        settings,
        setSetting,
        toggleSetting,
        resetSettings,
        liveStats,
        user,
        checkAuth,
        login,
        logout,
        showDemo,
        setShowDemo,
        aiChatHistory,
        setAiChatHistory,
        discoveryHosts,
        setDiscoveryHosts,
        discoveryReputation,
        setDiscoveryReputation,
        scanInProgress,
        setScanInProgress,
        scanMessage,
        setScanMessage,
        scanCidr,
        setScanCidr
      }}
    >
      {children}
    </DashboardContext.Provider>
  );
};

export const useDashboard = () => {
  const context = useContext(DashboardContext);
  if (!context) {
    throw new Error('useDashboard must be used within DashboardProvider');
  }
  return context;
};
