import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';

// Enhanced WebSocket Hook
const useWebSocket = () => {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const backendUrl = 'http://localhost:5000';
    const newSocket = io(`${backendUrl}/scan`, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 10,
      timeout: 20000,
      autoConnect: true
    });

    newSocket.on('connect', () => {
      console.log('✅ WebSocket Connected!');
      setConnected(true);
    });

    newSocket.on('disconnect', () => {
      console.log('❌ WebSocket Disconnected');
      setConnected(false);
    });

    setSocket(newSocket);

    return () => newSocket.close();
  }, []);

  return { socket, connected };
};

// Navigation Component
const Navigation = ({ currentPage, setCurrentPage, connected }) => {
  const navItems = [
    { id: 'dashboard', icon: '🏠', label: 'Dashboard' },
    { id: 'scanner', icon: '🔍', label: 'Scanner' },
    { id: 'reconnaissance', icon: '🎯', label: 'Recon' },
    { id: 'enumeration', icon: '🔢', label: 'Enumeration' },
    { id: 'vulnerabilities', icon: '⚠️', label: 'Vulnerabilities' },
    { id: 'tools', icon: '🛠️', label: 'Tools' },
    { id: 'reports', icon: '📊', label: 'Reports' },
    { id: 'settings', icon: '⚙️', label: 'Settings' }
  ];

  return (
    <nav className="bg-gray-900 border-r border-gray-700 w-64 min-h-screen p-4">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-600">
          CyberSage v2.0
        </h1>
        <p className="text-xs text-gray-500 mt-1">Elite Security Scanner</p>
        <div className={`flex items-center mt-3 text-xs px-3 py-2 rounded ${connected ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'}`}>
          <div className={`w-2 h-2 rounded-full mr-2 ${connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
          {connected ? 'Connected' : 'Offline'}
        </div>
      </div>

      <div className="space-y-1">
        {navItems.map(item => (
          <button
            key={item.id}
            onClick={() => setCurrentPage(item.id)}
            className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-all ${
              currentPage === item.id
                ? 'bg-purple-600 text-white shadow-lg'
                : 'text-gray-400 hover:bg-gray-800 hover:text-white'
            }`}
          >
            <span className="text-xl">{item.icon}</span>
            <span className="font-medium">{item.label}</span>
          </button>
        ))}
      </div>

      <div className="absolute bottom-4 left-4 right-4">
        <div className="bg-gray-800 rounded-lg p-3 border border-gray-700">
          <p className="text-xs text-gray-400">Active Scans</p>
          <p className="text-2xl font-bold text-white">0</p>
        </div>
      </div>
    </nav>
  );
};

// Dashboard Page
const Dashboard = ({ stats, recentScans }) => {
  const quickStats = [
    { label: 'Total Scans', value: stats.totalScans || 0, icon: '📊', color: 'blue' },
    { label: 'Critical Vulns', value: stats.critical || 0, icon: '🔴', color: 'red' },
    { label: 'High Risk', value: stats.high || 0, icon: '🟠', color: 'orange' },
    { label: 'Hosts Scanned', value: stats.hostsScanned || 0, icon: '🌐', color: 'green' }
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-white mb-2">Dashboard</h2>
        <p className="text-gray-400">Security scanning overview and recent activity</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {quickStats.map((stat, idx) => (
          <div key={idx} className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:border-purple-500 transition-all">
            <div className="flex items-center justify-between mb-3">
              <span className="text-3xl">{stat.icon}</span>
              <span className={`text-${stat.color}-400 text-sm font-semibold`}>Live</span>
            </div>
            <p className="text-gray-400 text-sm">{stat.label}</p>
            <p className="text-3xl font-bold text-white mt-2">{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 className="text-xl font-bold text-white mb-4">Recent Scans</h3>
          <div className="space-y-3">
            {recentScans.length === 0 ? (
              <p className="text-gray-500 text-center py-8">No recent scans</p>
            ) : (
              recentScans.slice(0, 5).map((scan, idx) => (
                <div key={idx} className="flex items-center justify-between p-3 bg-gray-900 rounded-lg">
                  <div>
                    <p className="text-white font-medium">{scan.target}</p>
                    <p className="text-xs text-gray-500">{scan.mode} scan</p>
                  </div>
                  <span className={`px-2 py-1 rounded text-xs ${
                    scan.status === 'completed' ? 'bg-green-600' : 
                    scan.status === 'running' ? 'bg-blue-600' : 'bg-gray-600'
                  } text-white`}>
                    {scan.status}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 className="text-xl font-bold text-white mb-4">Vulnerability Distribution</h3>
          <div className="space-y-3">
            {['Critical', 'High', 'Medium', 'Low'].map((severity, idx) => {
              const value = stats[severity.toLowerCase()] || 0;
              const colors = ['red', 'orange', 'yellow', 'blue'];
              const total = (stats.critical || 0) + (stats.high || 0) + (stats.medium || 0) + (stats.low || 0);
              const percentage = total > 0 ? (value / total * 100) : 0;
              
              return (
                <div key={idx}>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-gray-400">{severity}</span>
                    <span className="text-white font-semibold">{value}</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div 
                      className={`bg-${colors[idx]}-500 h-2 rounded-full transition-all duration-500`}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

// Scanner Page
const ScannerPage = ({ onStartScan, scanStatus }) => {
  const [target, setTarget] = useState('');
  const [scanMode, setScanMode] = useState('comprehensive');
  const [tools, setTools] = useState({
    // Recon Tools
    nmap: true,
    theHarvester: true,
    amass: true,
    whois: true,
    // Enumeration Tools
    ffuf: true,
    gobuster: true,
    dirb: false,
    // Vulnerability Tools
    sqlmap: true,
    nikto: true,
    wpscan: true,
    nuclei: true,
    // Custom
    customScanner: true
  });

  const scanModes = [
    { id: 'quick', name: 'Quick Scan', time: '5-10 min', desc: 'Basic vulnerability detection' },
    { id: 'standard', name: 'Standard Scan', time: '15-30 min', desc: 'Comprehensive security audit' },
    { id: 'comprehensive', name: 'Comprehensive', time: '30-60 min', desc: 'Deep analysis with all tools' },
    { id: 'custom', name: 'Custom Scan', time: 'Variable', desc: 'Select specific tools' }
  ];

  const handleStartScan = () => {
    if (!target.trim()) {
      alert('Please enter a target');
      return;
    }
    onStartScan(target, scanMode, { tools });
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-white mb-2">Security Scanner</h2>
        <p className="text-gray-400">Configure and launch comprehensive security scans</p>
      </div>

      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <label className="block text-sm font-semibold text-gray-300 mb-3">
          Target URL or IP Address
        </label>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="https://example.com or 192.168.1.1"
          className="w-full px-4 py-3 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500"
        />
      </div>

      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <label className="block text-sm font-semibold text-gray-300 mb-4">
          Scan Mode
        </label>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {scanModes.map(mode => (
            <button
              key={mode.id}
              onClick={() => setScanMode(mode.id)}
              className={`p-4 rounded-lg border-2 transition-all ${
                scanMode === mode.id
                  ? 'border-purple-500 bg-purple-500/20'
                  : 'border-gray-700 hover:border-gray-600'
              }`}
            >
              <h4 className="text-white font-semibold mb-1">{mode.name}</h4>
              <p className="text-xs text-purple-400 mb-2">{mode.time}</p>
              <p className="text-xs text-gray-400">{mode.desc}</p>
            </button>
          ))}
        </div>
      </div>

      {scanMode === 'custom' && (
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-4">Select Tools</h3>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {Object.keys(tools).map(tool => (
              <label key={tool} className="flex items-center space-x-2 p-3 bg-gray-900 rounded-lg cursor-pointer hover:bg-gray-850">
                <input
                  type="checkbox"
                  checked={tools[tool]}
                  onChange={(e) => setTools({ ...tools, [tool]: e.target.checked })}
                  className="w-4 h-4 text-purple-600 rounded focus:ring-purple-500"
                />
                <span className="text-sm text-gray-300">{tool}</span>
              </label>
            ))}
          </div>
        </div>
      )}

      <button
        onClick={handleStartScan}
        disabled={scanStatus === 'running'}
        className={`w-full py-4 rounded-lg font-bold text-lg transition-all ${
          scanStatus === 'running'
            ? 'bg-gray-600 cursor-not-allowed'
            : 'bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 transform hover:scale-105'
        } text-white shadow-lg`}
      >
        {scanStatus === 'running' ? (
          <span className="flex items-center justify-center">
            <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Scanning in Progress...
          </span>
        ) : (
          '🚀 Launch Security Scan'
        )}
      </button>
    </div>
  );
};

// Reconnaissance Page
const ReconnaissancePage = ({ scanId }) => {
  const [reconData, setReconData] = useState({
    subdomains: [],
    whoisInfo: {},
    dnsRecords: [],
    harvested: [],
    technologies: []
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-white mb-2">Reconnaissance</h2>
        <p className="text-gray-400">Information gathering and OSINT results</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-white">🌐 Subdomains</h3>
            <span className="text-sm text-gray-400">{reconData.subdomains.length} found</span>
          </div>
          <div className="space-y-2 max-h-80 overflow-auto">
            {reconData.subdomains.length === 0 ? (
              <p className="text-center py-8 text-gray-500">No data available</p>
            ) : (
              reconData.subdomains.map((sub, idx) => (
                <div key={idx} className="p-3 bg-gray-900 rounded-lg">
                  <p className="text-white font-mono text-sm">{sub}</p>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-white">📧 Email Harvesting</h3>
            <span className="text-sm text-gray-400">{reconData.harvested.length} found</span>
          </div>
          <div className="space-y-2 max-h-80 overflow-auto">
            {reconData.harvested.length === 0 ? (
              <p className="text-center py-8 text-gray-500">No data available</p>
            ) : (
              reconData.harvested.map((item, idx) => (
                <div key={idx} className="p-3 bg-gray-900 rounded-lg">
                  <p className="text-white text-sm">{item}</p>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 className="text-xl font-bold text-white mb-4">🔍 WHOIS Information</h3>
          <div className="space-y-2">
            {Object.keys(reconData.whoisInfo).length === 0 ? (
              <p className="text-center py-8 text-gray-500">No data available</p>
            ) : (
              Object.entries(reconData.whoisInfo).map(([key, value]) => (
                <div key={key} className="flex justify-between text-sm">
                  <span className="text-gray-400">{key}:</span>
                  <span className="text-white">{value}</span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 className="text-xl font-bold text-white mb-4">⚙️ Technologies Detected</h3>
          <div className="flex flex-wrap gap-2">
            {reconData.technologies.length === 0 ? (
              <p className="text-center py-8 text-gray-500 w-full">No data available</p>
            ) : (
              reconData.technologies.map((tech, idx) => (
                <span key={idx} className="px-3 py-1 bg-purple-600 text-white rounded-full text-sm">
                  {tech}
                </span>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Vulnerabilities Page
const VulnerabilitiesPage = ({ vulnerabilities }) => {
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  const filteredVulns = vulnerabilities.filter(v => {
    const matchesFilter = filter === 'all' || v.severity === filter;
    const matchesSearch = v.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         v.title?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const severityColors = {
    critical: 'border-red-500 bg-red-900/20',
    high: 'border-orange-500 bg-orange-900/20',
    medium: 'border-yellow-500 bg-yellow-900/20',
    low: 'border-blue-500 bg-blue-900/20'
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Vulnerabilities</h2>
          <p className="text-gray-400">Discovered security issues and weaknesses</p>
        </div>
        <div className="text-2xl font-bold text-white">
          {filteredVulns.length} Total
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <div className="flex flex-wrap gap-3">
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search vulnerabilities..."
            className="flex-1 min-w-[200px] px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500"
          />
          <div className="flex gap-2">
            {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className={`px-4 py-2 rounded-lg font-medium transition-all ${
                  filter === sev
                    ? 'bg-purple-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                {sev.charAt(0).toUpperCase() + sev.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="space-y-3">
        {filteredVulns.length === 0 ? (
          <div className="text-center py-12 bg-gray-800 rounded-lg border border-gray-700">
            <p className="text-gray-500 text-lg">No vulnerabilities found</p>
          </div>
        ) : (
          filteredVulns.map((vuln, idx) => (
            <div
              key={idx}
              className={`p-4 rounded-lg border-l-4 ${severityColors[vuln.severity]} backdrop-blur-sm`}
            >
              <div className="flex justify-between items-start mb-2">
                <div className="flex-1">
                  <h3 className="text-white font-semibold text-lg">{vuln.type}</h3>
                  <p className="text-gray-400 text-sm mt-1">{vuln.title}</p>
                </div>
                <span className={`px-3 py-1 rounded-full text-xs font-bold ml-4 ${
                  vuln.severity === 'critical' ? 'bg-red-500 text-white' :
                  vuln.severity === 'high' ? 'bg-orange-500 text-white' :
                  vuln.severity === 'medium' ? 'bg-yellow-500 text-black' :
                  'bg-blue-500 text-white'
                }`}>
                  {vuln.severity.toUpperCase()}
                </span>
              </div>
              <div className="flex items-center gap-4 text-xs text-gray-400 mt-3">
                <span className="flex items-center">
                  <span className="mr-1">🎯</span>
                  Confidence: {vuln.confidence}%
                </span>
                <span className="flex items-center">
                  <span className="mr-1">🛠️</span>
                  Tool: {vuln.tool}
                </span>
                {vuln.url && (
                  <span className="truncate max-w-md">
                    <span className="mr-1">🔗</span>
                    {vuln.url}
                  </span>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

// Main App Component
const CyberSageApp = () => {
  const { socket, connected } = useWebSocket();
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [scanStatus, setScanStatus] = useState('idle');
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [stats, setStats] = useState({
    totalScans: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    hostsScanned: 0
  });
  const [recentScans, setRecentScans] = useState([]);
  const [currentScanId, setCurrentScanId] = useState(null);

  useEffect(() => {
    if (!socket) return;

    socket.on('scan_started', (data) => {
      setScanStatus('running');
      setCurrentScanId(data.scan_id);
      setVulnerabilities([]);
    });

    socket.on('vulnerability_found', (data) => {
      setVulnerabilities(prev => [{ ...data, id: Date.now() }, ...prev]);
      setStats(prev => ({
        ...prev,
        [data.severity]: prev[data.severity] + 1
      }));
    });

    socket.on('scan_completed', (data) => {
      setScanStatus('completed');
      setRecentScans(prev => [{
        target: data.target || 'Unknown',
        mode: data.mode || 'unknown',
        status: 'completed'
      }, ...prev].slice(0, 10));
      setStats(prev => ({ ...prev, totalScans: prev.totalScans + 1 }));
    });

    return () => {
      socket.off('scan_started');
      socket.off('vulnerability_found');
      socket.off('scan_completed');
    };
  }, [socket]);

  const startScan = (target, mode, options = {}) => {
    if (socket && connected) {
      socket.emit('start_scan', { target, mode, ...options });
    }
  };

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard stats={stats} recentScans={recentScans} />;
      case 'scanner':
        return <ScannerPage onStartScan={startScan} scanStatus={scanStatus} />;
      case 'reconnaissance':
        return <ReconnaissancePage scanId={currentScanId} />;
      case 'vulnerabilities':
        return <VulnerabilitiesPage vulnerabilities={vulnerabilities} />;
      default:
        return <Dashboard stats={stats} recentScans={recentScans} />;
    }
  };

  return (
    <div className="flex min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900">
      <Navigation currentPage={currentPage} setCurrentPage={setCurrentPage} connected={connected} />
      <main className="flex-1 p-8 overflow-auto">
        {renderPage()}
      </main>
    </div>
  );
};

export default CyberSageApp;