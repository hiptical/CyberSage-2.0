import React, { useState, useEffect, useCallback } from 'react';

const ScanStatistics = ({ scanId }) => {
  const [statistics, setStatistics] = useState({});
  const [loading, setLoading] = useState(false);
  
  const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;

  const fetchStatistics = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/scan/${scanId}/statistics`);
      const data = await response.json();
      setStatistics(data.statistics || {});
    } catch (error) {
      console.error('Error fetching statistics:', error);
    } finally {
      setLoading(false);
    }
  }, [backendUrl, scanId]);

  useEffect(() => {
    if (scanId) {
      fetchStatistics();
    }
  }, [scanId, fetchStatistics]);

  const formatNumber = (num) => {
    if (num === null || num === undefined) return '0';
    return num.toLocaleString();
  };

  const formatDuration = (seconds) => {
    if (!seconds) return '0s';
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  if (!scanId) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <h2 className="text-xl font-bold text-white mb-4 flex items-center">
          <span className="mr-2">📊</span>
          Scan Statistics
        </h2>
        <div className="text-center py-8 text-gray-500">
          Start a scan to see detailed statistics
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold text-white flex items-center">
          <span className="mr-2">📊</span>
          Scan Statistics
        </h2>
        <button
          onClick={fetchStatistics}
          disabled={loading}
          className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded disabled:opacity-50"
        >
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      {loading ? (
        <div className="text-center py-8 text-gray-500">Loading statistics...</div>
      ) : (
        <div className="space-y-6">
          {/* Overview Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Endpoints</span>
                <span className="text-blue-400">🌐</span>
              </div>
              <div className="text-2xl font-bold text-white">
                {formatNumber(statistics.endpoints_discovered)}
              </div>
              <div className="text-xs text-gray-500">discovered</div>
            </div>

            <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Parameters</span>
                <span className="text-green-400">🔍</span>
              </div>
              <div className="text-2xl font-bold text-white">
                {formatNumber(statistics.parameters_tested)}
              </div>
              <div className="text-xs text-gray-500">tested</div>
            </div>

            <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Payloads</span>
                <span className="text-yellow-400">⚡</span>
              </div>
              <div className="text-2xl font-bold text-white">
                {formatNumber(statistics.payloads_sent)}
              </div>
              <div className="text-xs text-gray-500">sent</div>
            </div>

            <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Vulnerabilities</span>
                <span className="text-red-400">🚨</span>
              </div>
              <div className="text-2xl font-bold text-white">
                {formatNumber(statistics.vulnerabilities_found)}
              </div>
              <div className="text-xs text-gray-500">found</div>
            </div>
          </div>

          {/* Performance Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
              <h3 className="text-white font-semibold mb-3 flex items-center">
                <span className="mr-2">⚡</span>
                Performance
              </h3>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-gray-400">Avg Response Time:</span>
                  <span className="text-white font-semibold">
                    {statistics.avg_response_time_ms ? `${statistics.avg_response_time_ms}ms` : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Coverage:</span>
                  <span className="text-white font-semibold">
                    {statistics.coverage_percentage ? `${statistics.coverage_percentage.toFixed(1)}%` : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Scan Duration:</span>
                  <span className="text-white font-semibold">
                    {statistics.scan_duration ? formatDuration(statistics.scan_duration) : 'N/A'}
                  </span>
                </div>
              </div>
            </div>

            <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
              <h3 className="text-white font-semibold mb-3 flex items-center">
                <span className="mr-2">🎯</span>
                Accuracy
              </h3>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-gray-400">True Positives:</span>
                  <span className="text-green-400 font-semibold">
                    {formatNumber(statistics.true_positives)}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">False Positives:</span>
                  <span className="text-red-400 font-semibold">
                    {formatNumber(statistics.false_positives)}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Accuracy Rate:</span>
                  <span className="text-white font-semibold">
                    {statistics.true_positives && statistics.vulnerabilities_found 
                      ? `${((statistics.true_positives / statistics.vulnerabilities_found) * 100).toFixed(1)}%`
                      : 'N/A'
                    }
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Tool Performance */}
          <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
            <h3 className="text-white font-semibold mb-3 flex items-center">
              <span className="mr-2">🛠️</span>
              Tool Performance
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-gray-800 rounded p-3">
                <div className="text-gray-400 text-sm">XSS Scanner</div>
                <div className="text-white font-bold text-lg">
                  {statistics.xss_scans || 0}
                </div>
                <div className="text-gray-500 text-xs">scans performed</div>
              </div>
              <div className="bg-gray-800 rounded p-3">
                <div className="text-gray-400 text-sm">SQL Injection</div>
                <div className="text-white font-bold text-lg">
                  {statistics.sqli_scans || 0}
                </div>
                <div className="text-gray-500 text-xs">scans performed</div>
              </div>
              <div className="bg-gray-800 rounded p-3">
                <div className="text-gray-400 text-sm">Directory Traversal</div>
                <div className="text-white font-bold text-lg">
                  {statistics.traversal_scans || 0}
                </div>
                <div className="text-gray-500 text-xs">scans performed</div>
              </div>
            </div>
          </div>

          {/* Network Statistics */}
          <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
            <h3 className="text-white font-semibold mb-3 flex items-center">
              <span className="mr-2">🌐</span>
              Network Statistics
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-400">
                  {formatNumber(statistics.total_requests)}
                </div>
                <div className="text-gray-400 text-sm">Total Requests</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-400">
                  {formatNumber(statistics.successful_requests)}
                </div>
                <div className="text-gray-400 text-sm">Successful</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-red-400">
                  {formatNumber(statistics.failed_requests)}
                </div>
                <div className="text-gray-400 text-sm">Failed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-400">
                  {formatNumber(statistics.timeout_requests)}
                </div>
                <div className="text-gray-400 text-sm">Timeouts</div>
              </div>
            </div>
          </div>

          {/* Data Transfer */}
          <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
            <h3 className="text-white font-semibold mb-3 flex items-center">
              <span className="mr-2">📡</span>
              Data Transfer
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-400">
                  {formatBytes(statistics.bytes_sent)}
                </div>
                <div className="text-gray-400 text-sm">Data Sent</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-400">
                  {formatBytes(statistics.bytes_received)}
                </div>
                <div className="text-gray-400 text-sm">Data Received</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-400">
                  {formatBytes((statistics.bytes_sent || 0) + (statistics.bytes_received || 0))}
                </div>
                <div className="text-gray-400 text-sm">Total Transfer</div>
              </div>
            </div>
          </div>

          {/* Scan Timeline */}
          {statistics.scan_phases && (
            <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
              <h3 className="text-white font-semibold mb-3 flex items-center">
                <span className="mr-2">⏱️</span>
                Scan Timeline
              </h3>
              <div className="space-y-2">
                {statistics.scan_phases.map((phase, index) => (
                  <div key={index} className="flex justify-between items-center py-2 border-b border-gray-800 last:border-b-0">
                    <span className="text-gray-300">{phase.name}</span>
                    <div className="flex items-center space-x-4">
                      <span className="text-gray-400 text-sm">{formatDuration(phase.duration)}</span>
                      <span className="text-gray-400 text-sm">{phase.findings || 0} findings</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          <div className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4">
            <h3 className="text-blue-400 font-semibold mb-3 flex items-center">
              <span className="mr-2">💡</span>
              Performance Recommendations
            </h3>
            <div className="text-blue-300 text-sm space-y-2">
              {statistics.avg_response_time_ms > 5000 && (
                <div>• Consider increasing timeout values for slow-responding targets</div>
              )}
              {statistics.false_positives > statistics.true_positives && (
                <div>• High false positive rate detected - review scanner configuration</div>
              )}
              {statistics.coverage_percentage < 50 && (
                <div>• Low coverage detected - consider extending scan depth</div>
              )}
              {statistics.failed_requests > statistics.successful_requests && (
                <div>• High failure rate - check target availability and network connectivity</div>
              )}
              {!statistics.vulnerabilities_found && statistics.parameters_tested > 0 && (
                <div>• No vulnerabilities found - target may be well-secured or scan needs adjustment</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanStatistics;