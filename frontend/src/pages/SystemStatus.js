import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { healthCheck, getMetrics } from '../services/api';
import {
  ServerIcon,
  CpuChipIcon,
  CircleStackIcon,
  ClockIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon
} from '@heroicons/react/24/outline';

const SystemStatus = () => {
  const [health, setHealth] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState([]);
  const [autoRefresh, setAutoRefresh] = useState(false);

  useEffect(() => {
    checkSystemHealth();
    loadMetrics();
  }, []);

  useEffect(() => {
    let interval;
    if (autoRefresh) {
      interval = setInterval(() => {
        checkSystemHealth();
        loadMetrics();
      }, 10000);
    }
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const checkSystemHealth = async () => {
    try {
      const result = await healthCheck();
      setHealth(result);
      addLog(`Health check: ${result.status}`, result.status === 'online' ? 'success' : 'error');
    } catch (error) {
      setHealth({ status: 'offline', error: error.message });
      addLog(`Health check failed: ${error.message}`, 'error');
    }
  };

  const loadMetrics = async () => {
    setLoading(true);
    try {
      const data = await getMetrics();
      setMetrics(data);
      addLog('Metrics loaded successfully', 'success');
    } catch (error) {
      toast.error('Failed to load metrics');
      addLog(`Metrics load failed: ${error.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const addLog = (message, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    const newLog = { timestamp, message, type };
    setLogs(prev => [newLog, ...prev.slice(0, 49)]);
  };

  const clearLogs = () => {
    setLogs([]);
    addLog('Logs cleared', 'info');
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatUptime = (uptime) => {
    if (!uptime) return 'Unknown';
    const days = Math.floor(uptime / (24 * 60 * 60 * 1000));
    const hours = Math.floor((uptime % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
    const minutes = Math.floor((uptime % (60 * 60 * 1000)) / (60 * 1000));
    return `${days}d ${hours}h ${minutes}m`;
  };

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">System Status</h1>
          <p className="text-gray-600 mt-2">
            Monitor system health, performance metrics, and server status.
          </p>
        </div>
        <div className="flex space-x-4">
          <label className="flex items-center">
            <input
              type="checkbox"
              className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            <span className="ml-2 text-sm text-gray-700">Auto-refresh</span>
          </label>
          <button onClick={checkSystemHealth} className="btn-primary">
            Refresh Status
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                {health?.status === 'online' ? (
                  <CheckCircleIcon className="h-8 w-8 text-green-600" />
                ) : (
                  <ExclamationTriangleIcon className="h-8 w-8 text-red-600" />
                )}
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Server Status</p>
                <p className={`text-lg font-bold ${
                  health?.status === 'online' ? 'text-green-600' : 'text-red-600'
                }`}>
                  {health?.status === 'online' ? 'Online' : 'Offline'}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <CpuChipIcon className="h-8 w-8 text-blue-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Goroutines</p>
                <p className="text-lg font-bold text-gray-900">
                  {metrics?.goroutines || 'N/A'}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <CircleStackIcon className="h-8 w-8 text-purple-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Memory Usage</p>
                <p className="text-lg font-bold text-gray-900">
                  {metrics?.memory?.alloc_bytes ? formatBytes(metrics.memory.alloc_bytes) : 'N/A'}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ClockIcon className="h-8 w-8 text-green-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Uptime</p>
                <p className="text-lg font-bold text-gray-900">
                  {metrics?.uptime ? formatUptime(Date.parse(metrics.uptime)) : 'N/A'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold flex items-center">
              <ServerIcon className="h-5 w-5 mr-2" />
              System Information
            </h2>
          </div>
          <div className="card-body">
            {metrics ? (
              <div className="space-y-4">
                <div>
                  <h3 className="font-medium text-gray-900 mb-2">Memory Statistics</h3>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-500">Allocated:</span>
                      <span className="ml-2 font-mono">
                        {formatBytes(metrics.memory?.alloc_bytes || 0)}
                      </span>
                    </div>
                    <div>
                      <span className="text-gray-500">Total Alloc:</span>
                      <span className="ml-2 font-mono">
                        {formatBytes(metrics.memory?.total_alloc_bytes || 0)}
                      </span>
                    </div>
                    <div>
                      <span className="text-gray-500">System:</span>
                      <span className="ml-2 font-mono">
                        {formatBytes(metrics.memory?.sys_bytes || 0)}
                      </span>
                    </div>
                    <div>
                      <span className="text-gray-500">Heap:</span>
                      <span className="ml-2 font-mono">
                        {formatBytes(metrics.memory?.heap_alloc_bytes || 0)}
                      </span>
                    </div>
                  </div>
                </div>

                {metrics.database && (
                  <div>
                    <h3 className="font-medium text-gray-900 mb-2">Database Status</h3>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-gray-500">Status:</span>
                        <span className={`ml-2 font-medium ${
                          metrics.database.status === 'healthy' ? 'text-green-600' : 'text-red-600'
                        }`}>
                          {metrics.database.status}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-500">Connections:</span>
                        <span className="ml-2 font-mono">
                          {metrics.database.open_connections || 0}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-500">In Use:</span>
                        <span className="ml-2 font-mono">
                          {metrics.database.in_use || 0}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-500">Idle:</span>
                        <span className="ml-2 font-mono">
                          {metrics.database.idle || 0}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                <div>
                  <h3 className="font-medium text-gray-900 mb-2">Application Info</h3>
                  <div className="space-y-1 text-sm">
                    <div>
                      <span className="text-gray-500">Version:</span>
                      <span className="ml-2 font-mono">{metrics.version || 'Unknown'}</span>
                    </div>
                    <div>
                      <span className="text-gray-500">Goroutines:</span>
                      <span className="ml-2 font-mono">{metrics.goroutines || 0}</span>
                    </div>
                    <div>
                      <span className="text-gray-500">GC Runs:</span>
                      <span className="ml-2 font-mono">{metrics.memory?.gc_runs || 0}</span>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-8">
                <ChartBarIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                <p className="text-gray-600">Loading system metrics...</p>
                <button
                  onClick={loadMetrics}
                  disabled={loading}
                  className="btn-primary mt-4"
                >
                  {loading ? 'Loading...' : 'Load Metrics'}
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-semibold">System Logs</h2>
              <button onClick={clearLogs} className="btn-secondary">
                Clear Logs
              </button>
            </div>
          </div>
          <div className="card-body">
            <div className="bg-gray-900 text-green-400 p-4 rounded-lg h-80 overflow-y-auto font-mono text-sm">
              {logs.length === 0 ? (
                <div className="text-gray-500">No logs available...</div>
              ) : (
                logs.map((log, index) => (
                  <div key={index} className={`mb-1 ${
                    log.type === 'error' ? 'text-red-400' : 
                    log.type === 'success' ? 'text-green-400' : 'text-blue-400'
                  }`}>
                    [{log.timestamp}] {log.message}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SystemStatus;