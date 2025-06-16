import React, { useState } from 'react';
import { toast } from 'react-toastify';
import api from '../services/api';
import {
  BuildingOfficeIcon,
  KeyIcon,
  ChartBarIcon,
  CogIcon,
  ClipboardDocumentIcon
} from '@heroicons/react/24/outline';

const BusinessAPI = () => {
  const [businessData, setBusinessData] = useState(null);
  const [apiKey, setApiKey] = useState('');
  const [dashboardData, setDashboardData] = useState(null);
  const [formData, setFormData] = useState({
    company_name: '',
    contact_email: '',
    plan: 'basic'
  });
  const [verifyData, setVerifyData] = useState({
    user_id: '',
    code: ''
  });
  const [loading, setLoading] = useState(false);

  const registerBusiness = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await api.post('/api/business/v1/register', formData, {
        headers: {
          'X-API-Key': 'demo-api-key'
        }
      });
      setBusinessData(response.data);
      setApiKey(response.data.api_key);
      toast.success(`Business ${formData.company_name} registered successfully!`);
      setFormData({
        company_name: '',
        contact_email: '',
        plan: 'basic'
      });
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to register business');
    } finally {
      setLoading(false);
    }
  };

  const getDashboard = async () => {
    if (!apiKey) {
      toast.error('Please register a business first to get API key');
      return;
    }
    try {
      const response = await api.get('/api/business/v1/dashboard', {
        headers: {
          'X-API-Key': apiKey
        }
      });
      setDashboardData(response.data);
      toast.success('Dashboard data loaded');
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to load dashboard');
    }
  };

  const verifyTOTP = async (e) => {
    e.preventDefault();
    if (!apiKey) {
      toast.error('Please register a business first to get API key');
      return;
    }
    try {
      const response = await api.post('/api/business/v1/verify', verifyData, {
        headers: {
          'X-API-Key': apiKey
        }
      });
      toast.success(`TOTP verification: ${response.data.valid ? 'Valid' : 'Invalid'}`);
      setVerifyData({ user_id: '', code: '' });
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to verify TOTP');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard!');
  };

  return (
    <div className="space-y-8">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-gray-900 mb-4">
          Business API Integration
        </h1>
        <p className="text-xl text-gray-600 max-w-3xl mx-auto">
          Integrate post-quantum cryptographic TOTP authentication into your business applications.
        </p>
      </div>

      {/* Business Registration */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center">
            <BuildingOfficeIcon className="h-6 w-6 text-blue-600 mr-2" />
            <h2 className="text-xl font-semibold">Register Business</h2>
          </div>
        </div>
        <div className="card-body">
          <form onSubmit={registerBusiness} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Company Name
              </label>
              <input
                type="text"
                value={formData.company_name}
                onChange={(e) => setFormData({...formData, company_name: e.target.value})}
                className="input"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Contact Email
              </label>
              <input
                type="email"
                value={formData.contact_email}
                onChange={(e) => setFormData({...formData, contact_email: e.target.value})}
                className="input"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Plan
              </label>
              <select
                value={formData.plan}
                onChange={(e) => setFormData({...formData, plan: e.target.value})}
                className="input"
              >
                <option value="basic">Basic</option>
                <option value="premium">Premium</option>
                <option value="enterprise">Enterprise</option>
              </select>
            </div>
            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
            >
              {loading ? 'Registering...' : 'Register Business'}
            </button>
          </form>
        </div>
      </div>

      {/* API Key Display */}
      {businessData && (
        <div className="card">
          <div className="card-header">
            <div className="flex items-center">
              <KeyIcon className="h-6 w-6 text-green-600 mr-2" />
              <h2 className="text-xl font-semibold">API Key</h2>
            </div>
          </div>
          <div className="card-body">
            <div className="bg-gray-100 p-4 rounded-lg">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm">{apiKey}</span>
                <button
                  onClick={() => copyToClipboard(apiKey)}
                  className="btn-secondary"
                >
                  <ClipboardDocumentIcon className="h-4 w-4 mr-1" />
                  Copy
                </button>
              </div>
            </div>
            <p className="text-sm text-gray-600 mt-2">
              Keep this API key secure. Use it in the X-API-Key header for all requests.
            </p>
          </div>
        </div>
      )}

      {/* Dashboard Data */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <ChartBarIcon className="h-6 w-6 text-purple-600 mr-2" />
              <h2 className="text-xl font-semibold">Business Dashboard</h2>
            </div>
            <button
              onClick={getDashboard}
              className="btn-secondary"
            >
              Load Dashboard
            </button>
          </div>
        </div>
        <div className="card-body">
          {dashboardData ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-blue-50 p-4 rounded-lg">
                <p className="text-blue-600 font-medium">Total Users</p>
                <p className="text-2xl font-bold text-blue-800">{dashboardData.total_users}</p>
              </div>
              <div className="bg-green-50 p-4 rounded-lg">
                <p className="text-green-600 font-medium">Active Sessions</p>
                <p className="text-2xl font-bold text-green-800">{dashboardData.active_sessions}</p>
              </div>
              <div className="bg-purple-50 p-4 rounded-lg">
                <p className="text-purple-600 font-medium">API Calls Today</p>
                <p className="text-2xl font-bold text-purple-800">{dashboardData.api_calls_today}</p>
              </div>
            </div>
          ) : (
            <p className="text-gray-500">Click "Load Dashboard" to view business metrics</p>
          )}
        </div>
      </div>

      {/* TOTP Verification */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center">
            <CogIcon className="h-6 w-6 text-orange-600 mr-2" />
            <h2 className="text-xl font-semibold">Test TOTP Verification</h2>
          </div>
        </div>
        <div className="card-body">
          <form onSubmit={verifyTOTP} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                User ID
              </label>
              <input
                type="text"
                value={verifyData.user_id}
                onChange={(e) => setVerifyData({...verifyData, user_id: e.target.value})}
                className="input"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                TOTP Code
              </label>
              <input
                type="text"
                value={verifyData.code}
                onChange={(e) => setVerifyData({...verifyData, code: e.target.value})}
                className="input"
                required
              />
            </div>
            <button
              type="submit"
              className="btn-primary"
            >
              Verify TOTP
            </button>
          </form>
        </div>
      </div>

      {/* API Documentation */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center">
            <ClipboardDocumentIcon className="h-6 w-6 text-gray-600 mr-2" />
            <h2 className="text-xl font-semibold">API Endpoints</h2>
          </div>
        </div>
        <div className="card-body">
          <div className="space-y-4">
            <div className="border-l-4 border-blue-500 pl-4">
              <p className="font-mono text-sm">POST /api/business/v1/register</p>
              <p className="text-gray-600">Register a new business account</p>
            </div>
            <div className="border-l-4 border-green-500 pl-4">
              <p className="font-mono text-sm">GET /api/business/v1/dashboard</p>
              <p className="text-gray-600">Get business dashboard metrics</p>
            </div>
            <div className="border-l-4 border-purple-500 pl-4">
              <p className="font-mono text-sm">POST /api/business/v1/verify</p>
              <p className="text-gray-600">Verify TOTP codes for users</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BusinessAPI;