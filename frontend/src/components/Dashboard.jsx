import React, { useState, useEffect } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';

const Dashboard = () => {
  const { socket, connected } = useWebSocket();
  const [activeView, setActiveView] = useState('scan'); // scan, results, history, tools
  const [scanStatus, setScanStatus] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [chains, setChains] = useState([]);
  const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [currentScanId, setCurrentScanId] = useState(null);
  const [selectedVuln, setSelectedVuln] = useState(null);

  // Scan Config
  const [target, setTarget] = useState('');
  const [scanMode, setScanMode] = useState('elite');

  useEffect(() => {
    if (!socket) return;

    socket.on('scan_started', (data) => {
      setScanStatus('running');
      setProgress(0);
      setVulnerabilities([]);
      setChains([]);
      setStats({ critical: 0, high: 0, medium: 0, low: 0 });
      setCurrentScanId(data.scan_id);
      setActiveView('results');
    });

    socket.on('scan_progress', (data) => {
      setProgress(data.progress);
      setCurrentPhase(data.phase);
    });

    socket.on('vulnerability_found', (data) => {
      const newVuln = { ...data, id: Date.now() + Math.random() };
      setVulnerabilities(prev => [newVuln, ...prev]);
      setStats(prev => ({ ...prev, [data.severity]: prev[data.severity] + 1 }));
    });

    socket.on('chain_detected', (data) => {
      setChains(prev => [{ ...data, id: Date.now() }, ...prev]);
    });

    socket.on('scan_completed', (data) => {
      setScanStatus('completed');
      setProgress(100);
    });

    return () => {
      socket.off('scan_started');
      socket.off('scan_progress');
      socket.off('vulnerability_found');
      socket.off('chain_detected');
      socket.off('scan_completed');
    };
  }, [socket]);

  const startScan = () => {
    if (socket && connected && target) {
      socket.emit('start_scan', { target, mode: scanMode });
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Top Navigation */}
      <nav className="bg-gray-900 border-b border-gray-800 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">
            <div className="flex items-center space-x-8">
              <h1 className="text-xl font-bold bg-gradient-to-r from-purple-400 to-pink-600 bg-clip-text text-transparent">
                CyberSage v2.0
              </h1>
              <div className="hidden md:flex space-x-1">
                {[
                  { id: 'scan', label: 'New Scan', icon: '🎯' },
                  { id: 'results', label: 'Results', icon: '📊' },
                  { id: 'history', label: 'History', icon: '🗂️' },
                  { id: 'tools', label: 'Tools', icon: '🔧' }
                ].map(view => (
                  <button
                    key={view.id}
                    onClick={() => setActiveView(view.id)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
                      activeView === view.id
                        ? 'bg-purple-600 text-white'
                        : 'text-gray-400 hover:text-white hover:bg-gray-800'
                    }`}
                  >
                    <span className="mr-2">{view.icon}</span>
                    {view.label}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-sm ${
                connected ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'
              }`}>
                <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                <span className="font-medium">{connected ? 'Connected' : 'Offline'}</span>
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeView === 'scan' && (
          <div className="max-w-3xl mx-auto">
            <div className="bg-gray-900 rounded-xl border border-gray-800 p-8">
              <h2 className="text-2xl font-bold mb-6">Configure New Scan</h2>
              
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">
                    Target URL or Domain
                  </label>
                  <input
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-3">
                    Scan Mode
                  </label>
                  <div className="grid grid-cols-3 gap-4">
                    {[
                      { id: 'quick', label: 'Quick', time: '~5 min', icon: '⚡' },
                      { id: 'standard', label: 'Standard', time: '~15 min', icon: '🔍' },
                      { id: 'elite', label: 'Elite', time: '~30 min', icon: '🧠' }
                    ].map(mode => (
                      <button
                        key={mode.id}
                        onClick={() => setScanMode(mode.id)}
                        className={`p-4 rounded-lg border-2 transition ${
                          scanMode === mode.id
                            ? 'border-purple-500 bg-purple-900/20'
                            : 'border-gray-700 hover:border-gray-600'
                        }`}
                      >
                        <div className="text-2xl mb-2">{mode.icon}</div>
                        <div className="font-semibold">{mode.label}</div>
                        <div className="text-xs text-gray-500 mt-1">{mode.time}</div>
                      </button>
                    ))}
                  </div>
                </div>

                <button
                  onClick={startScan}
                  disabled={!target || !connected}
                  className="w-full py-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 rounded-lg font-bold text-lg transition disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  🚀 Start Elite Scan
                </button>
              </div>
            </div>
          </div>
        )}

        {activeView === 'results' && (
          <div className="space-y-6">
            {/* Progress */}
            {scanStatus === 'running' && (
              <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div className="flex justify-between mb-3">
                  <span className="text-gray-300 font-medium">{currentPhase}</span>
                  <span className="text-purple-400 font-bold text-lg">{progress}%</span>
                </div>
                <div className="w-full bg-gray-800 rounded-full h-3">
                  <div
                    className="h-3 bg-gradient-to-r from-purple-500 to-pink-500 rounded-full transition-all duration-500"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Critical', count: stats.critical, color: 'red', icon: '🔴' },
                { label: 'High', count: stats.high, color: 'orange', icon: '🟠' },
                { label: 'Medium', count: stats.medium, color: 'yellow', icon: '🟡' },
                { label: 'Low', count: stats.low, color: 'blue', icon: '🟢' }
              ].map(stat => (
                <div key={stat.label} className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400 text-sm">{stat.label}</span>
                    <span className="text-2xl">{stat.icon}</span>
                  </div>
                  <div className="text-3xl font-bold">{stat.count}</div>
                </div>
              ))}
            </div>

            {/* Vulnerabilities List */}
            <div className="bg-gray-900 rounded-xl border border-gray-800">
              <div className="p-6 border-b border-gray-800">
                <h2 className="text-xl font-bold">Vulnerabilities</h2>
              </div>
              <div className="divide-y divide-gray-800 max-h-[600px] overflow-y-auto">
                {vulnerabilities.length === 0 ? (
                  <div className="p-12 text-center text-gray-500">
                    No vulnerabilities detected yet
                  </div>
                ) : (
                  vulnerabilities.map((vuln) => (
                    <div
                      key={vuln.id}
                      onClick={() => setSelectedVuln(vuln)}
                      className="p-6 hover:bg-gray-800/50 cursor-pointer transition"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <h3 className="font-semibold text-lg">{vuln.type}</h3>
                            <span className={`px-2 py-1 rounded text-xs font-bold ${
                              vuln.severity === 'critical' ? 'bg-red-500' :
                              vuln.severity === 'high' ? 'bg-orange-500' :
                              vuln.severity === 'medium' ? 'bg-yellow-500 text-black' :
                              'bg-blue-500'
                            }`}>
                              {vuln.severity.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-gray-400 text-sm mb-2">{vuln.title}</p>
                          <div className="flex items-center space-x-4 text-xs text-gray-500">
                            <span>Confidence: {vuln.confidence}%</span>
                            <span className="truncate max-w-md">{vuln.url}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {activeView === 'history' && (
          <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
            <h2 className="text-xl font-bold mb-4">Scan History</h2>
            <div className="text-center py-12 text-gray-500">
              Coming soon - View past scans
            </div>
          </div>
        )}

        {activeView === 'tools' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
              <h2 className="text-xl font-bold mb-4">🛰️ Repeater</h2>
              <p className="text-gray-400 text-sm">Manual HTTP request testing</p>
            </div>
            <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
              <h2 className="text-xl font-bold mb-4">🔗 Integrations</h2>
              <p className="text-gray-400 text-sm">Import from Burp, Nmap, etc.</p>
            </div>
          </div>
        )}
      </main>

      {/* Vulnerability Detail Modal */}
      {selectedVuln && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4" onClick={() => setSelectedVuln(null)}>
          <div className="bg-gray-900 rounded-xl border border-gray-800 max-w-4xl w-full max-h-[90vh] overflow-auto" onClick={e => e.stopPropagation()}>
            <div className="sticky top-0 bg-gray-900 border-b border-gray-800 p-6 flex justify-between items-center">
              <h2 className="text-2xl font-bold">{selectedVuln.type}</h2>
              <button onClick={() => setSelectedVuln(null)} className="text-gray-400 hover:text-white text-3xl">×</button>
            </div>
            <div className="p-6 space-y-6">
              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="font-semibold mb-2">Description</h3>
                <p className="text-gray-300 text-sm">{selectedVuln.title}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-800 rounded-lg p-4">
                  <div className="text-sm text-gray-400 mb-1">Severity</div>
                  <div className="text-lg font-bold capitalize">{selectedVuln.severity}</div>
                </div>
                <div className="bg-gray-800 rounded-lg p-4">
                  <div className="text-sm text-gray-400 mb-1">Confidence</div>
                  <div className="text-lg font-bold">{selectedVuln.confidence}%</div>
                </div>
              </div>
              <div className="bg-gray-800 rounded-lg p-4">
                <div className="text-sm text-gray-400 mb-1">Affected URL</div>
                <div className="text-sm font-mono break-all">{selectedVuln.url}</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;