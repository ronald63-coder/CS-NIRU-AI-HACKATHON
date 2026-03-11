// src/services/api.js
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 5000,
});

// Handle errors
api.interceptors.response.use(
  response => response.data,
  error => {
    console.error('API Error:', error);
    return {
      error: error.message || 'API request failed'
    };
  }
);

export const apiCalls = {
  // Health & Stats
  getHealth: () => api.get('/api/health'),
  getSystemStats: () => api.get('/api/system-stats'),
  
  // Threats
  getThreatHistory: (limit = 100) => api.get(`/api/threat-history?limit=${limit}`),
  getUnresolvedThreats: () => api.get('/api/agent/threats/unresolved'),
  
  // Users
  getUsers: () => api.get('/api/users'),
  getUserActivity: () => api.get('/api/user-activity'),
  getBlockedUsers: () => api.get('/api/blocked-users'),
  
  // Agent
  getAgentStatus: () => api.get('/api/agent/status'),
  getAgentLogs: (limit = 20) => api.get(`/api/agent/logs?limit=${limit}`),
  triggerAgentAction: (action, username, reason) =>
    api.post('/api/agent/trigger', null, {
      params: { action, username, reason }
    }),
  
  // System
  getSystemLogs: (limit = 5) => api.get(`/api/system-logs?limit=${limit}`),
  
  // Utility
  blockUser: (username) => api.post('/api/unblock-user', null, {
    params: { username }
  }),
};

export default api;