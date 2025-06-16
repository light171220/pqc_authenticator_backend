import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import {
  ShieldCheckIcon,
  UserIcon,
  KeyIcon,
  BuildingOfficeIcon,
  ChartBarIcon,
  ClockIcon
} from '@heroicons/react/24/outline';

const Dashboard = () => {
  const { isAuthenticated, user } = useAuth();
  const [stats, setStats] = useState({
    totalAccounts: 0,
    totalCodes: 0,
    lastActivity: null
  });

  useEffect(() => {
    if (isAuthenticated) {
      loadDashboardStats();
    }
  }, [isAuthenticated]);

  const loadDashboardStats = async () => {
    setStats({
      totalAccounts: 3,
      totalCodes: 157,
      lastActivity: new Date().toISOString()
    });
  };

  const features = [
    {
      title: 'Post-Quantum Security',
      description: 'Built with post-quantum cryptographic algorithms including Dilithium and Kyber for future-proof security.',
      icon: ShieldCheckIcon,
      color: 'text-blue-600'
    },
    {
      title: 'TOTP Authentication',
      description: 'Generate and verify time-based one-time passwords with quantum-resistant digital signatures.',
      icon: KeyIcon,
      color: 'text-green-600'
    },
    {
      title: 'Business Integration',
      description: 'Enterprise-ready APIs for seamless integration with your existing authentication systems.',
      icon: BuildingOfficeIcon,
      color: 'text-purple-600'
    },
    {
      title: 'Real-time Monitoring',
      description: 'Comprehensive system monitoring and analytics for security and performance insights.',
      icon: ChartBarIcon,
      color: 'text-orange-600'
    }
  ];

  const quickActions = [
    {
      title: 'Manage TOTP Accounts',
      description: 'Create, view, and manage your TOTP accounts',
      href: '/totp',
      icon: KeyIcon,
      color: 'bg-blue-500'
    },
    {
      title: 'Business API',
      description: 'Explore business integration features',
      href: '/business',
      icon: BuildingOfficeIcon,
      color: 'bg-purple-500'
    },
    {
      title: 'System Status',
      description: 'Monitor system health and performance',
      href: '/system',
      icon: ChartBarIcon,
      color: 'bg-green-500'
    }
  ];

  return (
    <div className="space-y-8">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-gray-900 mb-4">
          Welcome to PQC Authenticator
        </h1>
        <p className="text-xl text-gray-600 max-w-3xl mx-auto">
          The world's first post-quantum cryptographic TOTP authentication system. 
          Secure your digital assets against both classical and quantum computing threats.
        </p>
      </div>

      {isAuthenticated ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="card">
            <div className="card-body">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <UserIcon className="h-8 w-8 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Total Accounts</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.totalAccounts}</p>
                </div>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-body">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <KeyIcon className="h-8 w-8 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Codes Generated</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.totalCodes}</p>
                </div>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-body">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <ClockIcon className="h-8 w-8 text-purple-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Last Activity</p>
                  <p className="text-sm font-bold text-gray-900">
                    {stats.lastActivity ? new Date(stats.lastActivity).toLocaleString() : 'Never'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="text-center bg-gradient-to-r from-blue-50 to-purple-50 rounded-lg p-8">
          <ShieldCheckIcon className="mx-auto h-16 w-16 text-blue-600 mb-4" />
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Get Started with PQC Authentication</h2>
          <p className="text-gray-600 mb-6">
            Create an account to start using post-quantum cryptographic TOTP authentication.
          </p>
          <div className="space-x-4">
            <Link
              to="/register"
              className="btn-primary"
            >
              Create Account
            </Link>
            <Link
              to="/login"
              className="btn-secondary"
            >
              Sign In
            </Link>
          </div>
        </div>
      )}

      {isAuthenticated && (
        <div>
          <h2 className="text-2xl font-bold text-gray-900 mb-6">Quick Actions</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {quickActions.map((action, index) => (
              <Link
                key={index}
                to={action.href}
                className="group block"
              >
                <div className="card hover:shadow-xl transition-shadow duration-200">
                  <div className="card-body">
                    <div className="flex items-center">
                      <div className={`flex-shrink-0 p-3 rounded-lg ${action.color}`}>
                        <action.icon className="h-6 w-6 text-white" />
                      </div>
                      <div className="ml-4">
                        <h3 className="text-lg font-medium text-gray-900 group-hover:text-primary-600">
                          {action.title}
                        </h3>
                        <p className="text-sm text-gray-500">{action.description}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      <div>
        <h2 className="text-2xl font-bold text-gray-900 mb-6">Key Features</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {features.map((feature, index) => (
            <div key={index} className="card">
              <div className="card-body">
                <div className="flex items-start">
                  <div className="flex-shrink-0">
                    <feature.icon className={`h-8 w-8 ${feature.color}`} />
                  </div>
                  <div className="ml-4">
                    <h3 className="text-lg font-medium text-gray-900 mb-2">
                      {feature.title}
                    </h3>
                    <p className="text-gray-600">{feature.description}</p>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;