import axios from 'axios';
import { toast } from 'react-toastify';

const API_BASE_URL = process.env.REACT_APP_API_URL || '';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      if (window.location.pathname !== '/login' && window.location.pathname !== '/register') {
        window.location.href = '/login';
      }
    }
    
    if (error.response?.status >= 500) {
      toast.error('Server error occurred. Please try again later.');
    }
    
    if (error.code === 'ECONNABORTED') {
      toast.error('Request timeout. Please try again.');
    }
    
    if (error.response?.status === 429) {
      toast.error('Too many requests. Please wait before trying again.');
    }
    
    return Promise.reject(error);
  }
);

export const healthCheck = async () => {
  try {
    const response = await api.get('/health');
    return { status: 'online', data: response.data };
  } catch (error) {
    console.error('Health check failed:', error);
    return { status: 'offline', error: error.message };
  }
};

export const getMetrics = async () => {
  try {
    const response = await api.get('/metrics');
    return response.data;
  } catch (error) {
    console.error('Metrics fetch failed:', error);
    throw error;
  }
};

export const getReadiness = async () => {
  try {
    const response = await api.get('/readiness');
    return { ready: true, data: response.data };
  } catch (error) {
    return { ready: false, error: error.message };
  }
};

export default api;