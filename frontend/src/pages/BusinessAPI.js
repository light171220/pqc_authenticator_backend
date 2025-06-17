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
      const tempApiKey = 'pqc_demo_' + Math.random().toString(36).substring(2, 15);
      
      const response = await api.post('/api/business/v1/register', formData, {
        headers: {
          'X-API-Key': tempApiKey
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
      const errorMsg = error.response?.data?.error || 'Failed to register business';
      toast.error(errorMsg);
      console.error('Business registration error:', error);
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
      const errorMsg = error.response?.data?.error || 'Failed to load dashboard';
      toast.error(errorMsg);
      console.error('Dashboard error:', error);
    }
  };

  const verifyTOTP = async (e) => {
    e.preventDefault();
    if (!apiKey) {
      toast.error('Please register a business first to get API key');
      return;
    }
    if (!verifyData.user_id || !verifyData.code) {
      toast.error('Please provide both User ID and TOTP code');
      return;
    }
    try {
      const response = await api.post('/api/business/v1/verify', verifyData, {
        headers: {
          'X-API-Key': apiKey
        }
      });
      const isValid = response.data.valid;
      toast.success(`TOTP verification: ${isValid ? 'Valid ✓' : 'Invalid ✗'}`);
      setVerifyData({ user_id: '', code: '' });
    } catch (error) {
      const errorMsg = error.response?.data?.error || 'Failed to verify TOTP';
      toast.error(errorMsg);
      console.error('TOTP verification error:', error);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      toast.success('Copied to clipboard!');
    }).catch(() => {
      toast.error('Failed to copy to clipboard');
    });
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
              <label className="form-label">
                Company Name
              </label>
              <input
                type="text"
                value={formData.company_name}
                onChange={(e) => setFormData({...formData, company_name: e.target.value})}
                className="form-input"
                placeholder="Enter company name"
                required
              />
            </div>
            <div>
              <label className="form-label">
                Contact Email
              </label>
              <input
                type="email"
                value={formData.contact_email}
                onChange={(e) => setFormData({...formData, contact_email: e.target.value})}
                className="form-input"
                placeholder="Enter contact email"
                required
              />
            </div>
            <div>
              <label className="form-label">
                Plan
              </label>
              <select
                value={formData.plan}
                onChange={(e) => setFormData({...formData, plan: e.target.value})}
                className="form-input"
              >
                <option value="basic">Basic</option>
                <option value="pro">Pro</option>
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
                <span className="font-mono text-sm break-all">{apiKey}</span>
                <button
                  onClick={() => copyToClipboard(apiKey)}
                  className="btn-secondary ml-4"
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
              disabled={!apiKey}
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
                <p className="text-2xl font-bold text-blue-800">{dashboardData.total_users || 0}</p>
              </div>
              <div className="bg-green-50 p-4 rounded-lg">
                <p className="text-green-600 font-medium">Active Users</p>
                <p className="text-2xl font-bold text-green-800">{dashboardData.active_users || 0}</p>
              </div>
              <div className="bg-purple-50 p-4 rounded-lg">
                <p className="text-purple-600 font-medium">Total Verifications</p>
                <p className="text-2xl font-bold text-purple-800">{dashboardData.total_verifications || 0}</p>
              </div>
            </div>
          ) : (
            <p className="text-gray-500">
              {!apiKey ? 'Register a business first to get an API key' : 'Click "Load Dashboard" to view business metrics'}
            </p>
          )}
        </div>
      </div>

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
              <label className="form-label">
                User ID
              </label>
              <input
                type="text"
                value={verifyData.user_id}
                onChange={(e) => setVerifyData({...verifyData, user_id: e.target.value})}
                className="form-input"
                placeholder="Enter user ID"
                required
              />
            </div>
            <div>
              <label className="form-label">
                TOTP Code
              </label>
              <input
                type="text"
                value={verifyData.code}
                onChange={(e) => setVerifyData({...verifyData, code: e.target.value})}
                className="form-input"
                placeholder="Enter 6-digit TOTP code"
                maxLength="6"
                pattern="[0-9]{6}"
                required
              />
            </div>
            <button
              type="submit"
              className="btn-primary"
              disabled={!apiKey}
            >
              Verify TOTP
            </button>
          </form>
          {!apiKey && (
            <p className="text-sm text-gray-500 mt-2">
              Register a business first to test TOTP verification
            </p>
          )}
        </div>
      </div>

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
            <div className="border-l-4 border-orange-500 pl-4">
              <p className="font-mono text-sm">POST /api/business/v1/provision</p>
              <p className="text-gray-600">Provision users for business account</p>
            </div>
            <div className="border-l-4 border-red-500 pl-4">
              <p className="font-mono text-sm">GET /api/business/v1/analytics</p>
              <p className="text-gray-600">Get business analytics and usage stats</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BusinessAPI;