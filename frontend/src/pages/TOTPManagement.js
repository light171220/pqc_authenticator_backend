import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import QRCode from 'qrcode';
import { useAuth } from '../contexts/AuthContext';
import api from '../services/api';
import {
  PlusIcon,
  QrCodeIcon,
  KeyIcon,
  ClockIcon,
  TrashIcon,
  EyeIcon,
  EyeSlashIcon
} from '@heroicons/react/24/outline';

const TOTPManagement = () => {
  const { isAuthenticated } = useAuth();
  const [accounts, setAccounts] = useState([]);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [selectedAccount, setSelectedAccount] = useState(null);
  const [qrCodeData, setQrCodeData] = useState('');
  const [currentCode, setCurrentCode] = useState('');
  const [timeRemaining, setTimeRemaining] = useState(30);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    service_name: '',
    service_url: '',
    issuer: '',
    digits: 6,
    period: 30
  });

  useEffect(() => {
    if (isAuthenticated) {
      loadAccounts();
    }
  }, [isAuthenticated]);

  useEffect(() => {
    if (currentCode) {
      const timer = setInterval(() => {
        setTimeRemaining(prev => {
          if (prev <= 1) {
            setCurrentCode('');
            return 30;
          }
          return prev - 1;
        });
      }, 1000);
      
      return () => clearInterval(timer);
    }
  }, [currentCode]);

  const loadAccounts = async () => {
    try {
      const response = await api.get('/api/v1/accounts');
      setAccounts(response.data.accounts || []);
    } catch (error) {
      toast.error('Failed to load accounts');
    }
  };

  const handleCreateAccount = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await api.post('/api/v1/accounts', formData);
      toast.success(`Account created for ${formData.service_name}`);
      setFormData({
        service_name: '',
        service_url: '',
        issuer: '',
        digits: 6,
        period: 30
      });
      setShowCreateForm(false);
      loadAccounts();
      
      await generateQRCode(response.data.id);
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to create account');
    } finally {
      setLoading(false);
    }
  };

  const generateQRCode = async (accountId) => {
    try {
      const response = await api.get(`/api/v1/totp/qr/${accountId}`);
      const qrDataURL = await QRCode.toDataURL(response.data.url);
      setQrCodeData(qrDataURL);
      setSelectedAccount(accountId);
    } catch (error) {
      toast.error('Failed to generate QR code');
    }
  };

  const generateTOTPCode = async (accountId) => {
    try {
      const response = await api.post('/api/v1/totp/generate', {
        account_id: accountId
      });
      setCurrentCode(response.data.code);
      setTimeRemaining(response.data.period);
      toast.success('TOTP code generated');
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to generate TOTP code');
    }
  };

  const deleteAccount = async (accountId) => {
    if (!window.confirm('Are you sure you want to delete this account?')) {
      return;
    }

    try {
      await api.delete(`/api/v1/accounts/${accountId}`);
      toast.success('Account deleted');
      loadAccounts();
      if (selectedAccount === accountId) {
        setSelectedAccount(null);
        setQrCodeData('');
      }
    } catch (error) {
      toast.error('Failed to delete account');
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="text-center py-12">
        <KeyIcon className="mx-auto h-16 w-16 text-gray-400 mb-4" />
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Authentication Required</h2>
        <p className="text-gray-600">Please login to manage your TOTP accounts.</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">TOTP Management</h1>
          <p className="text-gray-600 mt-2">
            Manage your Time-based One-Time Password accounts with post-quantum security.
          </p>
        </div>
        <button
          onClick={() => setShowCreateForm(true)}
          className="btn-primary"
        >
          <PlusIcon className="h-5 w-5 mr-2" />
          Add Account
        </button>
      </div>

      {showCreateForm && (
        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold">Create New TOTP Account</h2>
          </div>
          <div className="card-body">
            <form onSubmit={handleCreateAccount} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="form-label">Service Name</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g., Google, GitHub"
                    value={formData.service_name}
                    onChange={(e) => setFormData({...formData, service_name: e.target.value})}
                    required
                  />
                </div>
                <div>
                  <label className="form-label">Service URL</label>
                  <input
                    type="url"
                    className="form-input"
                    placeholder="https://example.com"
                    value={formData.service_url}
                    onChange={(e) => setFormData({...formData, service_url: e.target.value})}
                    required
                  />
                </div>
              </div>
              
              <div>
                <label className="form-label">Issuer</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="Company or Organization Name"
                  value={formData.issuer}
                  onChange={(e) => setFormData({...formData, issuer: e.target.value})}
                  required
                />
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="form-label">Digits</label>
                  <select
                    className="form-input"
                    value={formData.digits}
                    onChange={(e) => setFormData({...formData, digits: parseInt(e.target.value)})}
                  >
                    <option value={6}>6 digits</option>
                    <option value={7}>7 digits</option>
                    <option value={8}>8 digits</option>
                  </select>
                </div>
                <div>
                  <label className="form-label">Period (seconds)</label>
                  <select
                    className="form-input"
                    value={formData.period}
                    onChange={(e) => setFormData({...formData, period: parseInt(e.target.value)})}
                  >
                    <option value={15}>15 seconds</option>
                    <option value={30}>30 seconds</option>
                    <option value={60}>60 seconds</option>
                  </select>
                </div>
              </div>
              
              <div className="flex space-x-4">
                <button
                  type="submit"
                  disabled={loading}
                  className="btn-primary"
                >
                  {loading ? 'Creating...' : 'Create Account'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowCreateForm(false)}
                  className="btn-secondary"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div>
          <h2 className="text-xl font-semibold mb-4">Your Accounts</h2>
          {accounts.length === 0 ? (
            <div className="card">
              <div className="card-body text-center">
                <KeyIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                <p className="text-gray-600">No TOTP accounts found.</p>
                <button
                  onClick={() => setShowCreateForm(true)}
                  className="btn-primary mt-4"
                >
                  Create Your First Account
                </button>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              {accounts.map((account) => (
                <div key={account.id} className="card">
                  <div className="card-body">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-semibold text-gray-900">{account.service_name}</h3>
                        <p className="text-sm text-gray-600">{account.issuer}</p>
                        <p className="text-xs text-gray-500">
                          {account.digits} digits • {account.period}s period
                        </p>
                      </div>
                      <div className="flex space-x-2">
                        <button
                          onClick={() => generateQRCode(account.id)}
                          className="btn-secondary"
                          title="Show QR Code"
                        >
                          <QrCodeIcon className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => generateTOTPCode(account.id)}
                          className="btn-primary"
                          title="Generate Code"
                        >
                          <KeyIcon className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => deleteAccount(account.id)}
                          className="btn-danger"
                          title="Delete Account"
                        >
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="space-y-6">
          {currentCode && (
            <div className="card">
              <div className="card-header">
                <h3 className="text-lg font-semibold flex items-center">
                  <ClockIcon className="h-5 w-5 mr-2" />
                  Current TOTP Code
                </h3>
              </div>
              <div className="card-body text-center">
                <div className="code-display mb-4">
                  {currentCode}
                </div>
                <p className="text-sm text-gray-600">
                  Expires in {timeRemaining} seconds
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                  <div
                    className="bg-primary-600 h-2 rounded-full transition-all duration-1000"
                    style={{ width: `${(timeRemaining / 30) * 100}%` }}
                  ></div>
                </div>
              </div>
            </div>
          )}

          {qrCodeData && (
            <div className="card">
              <div className="card-header">
                <h3 className="text-lg font-semibold">QR Code Setup</h3>
              </div>
              <div className="card-body text-center">
                <img
                  src={qrCodeData}
                  alt="QR Code"
                  className="mx-auto mb-4 rounded-lg shadow-lg"
                />
                <p className="text-sm text-gray-600">
                  Scan this QR code with your authenticator app to set up TOTP.
                </p>
                <button
                  onClick={() => {
                    setQrCodeData('');
                    setSelectedAccount(null);
                  }}
                  className="btn-secondary mt-4"
                >
                  Close
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default TOTPManagement;