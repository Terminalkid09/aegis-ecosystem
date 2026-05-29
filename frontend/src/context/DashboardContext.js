import React, { createContext, useState, useContext, useEffect } from 'react';

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
  const [aiChatHistory, setAiChatHistory] = useState([
    { role: 'system', content: 'Aegis AI Security Analyst initialized. How can I assist with your forensic investigation?' }
  ]);

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
    if (!settings.autoRefresh) {
      return;
    }

    const interval = setInterval(() => {
      setRefreshTrigger((prev) => prev + 1);
    }, Number(process.env.REACT_APP_REFRESH_INTERVAL) || 30000);

    return () => clearInterval(interval);
  }, [settings.autoRefresh]);

  const refreshData = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  const manualRefresh = () => {
    refreshData();
  };

  const setSetting = (key, value) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
  };

  const toggleSetting = (key) => {
    setSettings((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const resetSettings = () => {
    setSettings(DEFAULT_SETTINGS);
    localStorage.removeItem('aegis-settings');
  };

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
        aiChatHistory,
        setAiChatHistory
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
