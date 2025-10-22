import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';

// ============================================================================
// COMPLETE CYBERSAGE V2.0 PROFESSIONAL APPLICATION
// Single file with all components - no import errors
// ============================================================================

const CyberSageApp = () => {
  // WebSocket connection
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  
  // Navigation
  const [currentPage, setCurrentPage] = useState('dashboard');
  
  // Scan state
  const [scanStatus, setScanStatus] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('');
  const [currentScanId, setCurrentScanId] = useState(null);
  
  // Data
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [chains, setChains] = useState([]);
  const [toolActivity, setToolActivity] = useState([]);
  const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [correlations, setCorrelations] = useState([]);

  // WebSocket setup
  useEffect(() => {
    const backendUrl = 'http://localhost:5000';
    const newSocket = io(`${backendUrl}/scan`, {
      transports: ['polling', 'websocket'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 10,
      timeout: 20000,
    });

    newSocket.on('connect', () => {
      console.log('✅ WebSocket Connected');
      setConnected(true);
    });

    newSocket.on('disconnect', () => {
      console.log('❌ WebSocket Disconnected');
      setConnected(false);
    });

    newSocket.on('connect_error', (error) => {
      console.error('Connection error:', error.message);
      setConnected(false);
    });

    setSocket(newSocket);
    return () => newSocket.close();
  }, []);

  // WebSocket event handlers
  useEffect(() => {
    if (!socket) return;

    socket.on('scan_started', (data) => {
      setScanStatus('running');
      setProgress(0);
      setVulnerabilities([]);
      setChains([]);
      setToolActivity([]);
      setCorrelations([]);
      setStats({ critical: 0, high: 0, medium: 0, low: 0 });
      setCurrentScanId(data.scan_id);
    });

    socket.on('scan_progress', (data) => {
      setProgress(data.progress);
      setCurrentPhase(data.phase);
    });

    socket.on('tool_started', (data) => {
      setToolActivity(prev => [{
        tool: data.tool,
        target: data.target,
        status: 'running',
        timestamp: data.timestamp
      }, ...prev].slice(0, 10));
    });

    socket.on('tool_completed', (data) => {
      setToolActivity(prev => 
        prev.map(item => 
          item.tool === data.tool 
            ? { ...item, status: 'completed', findings: data.findings_count }
            : item
        )
      );
    });

    socket.on('vulnerability_found', (data) => {
      const newVuln = { ...data, id: Date.now() + Math.random() };
      setVulnerabilities(prev => {
        const updated = [newVuln, ...prev];
        detectCorrelations(updated);
        return updated;
      });
      setStats(prev => ({
        ...prev,
        [data.severity]: prev[data.severity] + 1
      }));
    });

    socket.on('chain_detected', (data) => {
      setChains(prev => [{ ...data, id: Date.now() }, ...prev]);
    });

    socket.on('scan_completed', () => {
      setScanStatus('completed');
      setProgress(100);
    });

    socket.on('scan_error', (data) => {
      setScanStatus('error');
      console.error('Scan error:', data.error);
    });

    return () => {
      socket.off('scan_started');
      socket.off('scan_progress');
      socket.off('tool_started');
      socket.off('tool_completed');
      socket.off('vulnerability_found');
      socket.off('chain_detected');
      socket.off('scan_completed');
      socket.off('scan_error');
    };
  }, [socket]);

  // AI Correlation Detection
  const detectCorrelations = (vulns) => {
    const newCorrelations = [];
    
    const xssVulns = vulns.filter(v => v.type?.includes('XSS'));
    const corsVulns = vulns.filter(v => v.type?.includes('CORS'));
    
    if (xssVulns.length > 0 && corsVulns.length > 0) {
      newCorrelations.push({
        id: 'corr-xss-cors',
        type: 'correlation',
        title: 'XSS + CORS Misconfiguration',
        severity: 'critical',
        description: 'XSS combined with CORS issues enables cross-origin data theft',
        vulns: [...xssVulns.slice(0, 2), ...corsVulns.slice(0, 1)]
      });
    }

    const authVulns = vulns.filter(v => 
      v.type?.includes('Auth') || v.type?.includes('Session') || v.type?.includes('Cookie')
    );
    if (authVulns.length >= 2) {
      newCorrelations.push({
        id: 'corr-auth',
        type: 'correlation',
        title: 'Multiple Authentication Weaknesses',
        severity: 'high',
        description: 'Multiple authentication issues detected, increasing account takeover risk',
        vulns: authVulns.slice(0, 3)
      });
    }

    const sqliVulns = vulns.filter(v => v.type?.includes('SQL'));
    const uploadVulns = vulns.filter(v => v.type?.includes('Upload') || v.type?.includes('File'));
    if (sqliVulns.length > 0 && uploadVulns.length > 0) {
      newCorrelations.push({
        id: 'corr-sqli-upload',
        type: 'correlation',
        title: 'SQL Injection + File Upload',
        severity: 'critical',
        description: 'Combined vulnerabilities may lead to remote code execution',
        vulns: [...sqliVulns.slice(0, 1), ...uploadVulns.slice(0, 1)]
      });
    }

    setCorrelations(newCorrelations);
  };

  const startScan = (target, mode, options = {}) => {
    if (socket && connected) {
      socket.emit('start_scan', {
        target,
        mode,
        intensity: options.intensity || 'normal',
        tools: options.tools || {
          nmap: true,
          theHarvester: true,
          amass: true,
          whois: true,
          ffuf: true,
          gobuster: true,
          sqlmap: true,
          nikto: true,
          wpscan: true,
          nuclei: true,
          customScanner: true
        }
      });
    }
  };

  const renderPage = () => {
    switch (currentPage) {
      case 'scanner':
        return <ScannerPage startScan={startScan} connected={connected} scanStatus={scanStatus} />;
      case 'vulnerabilities':
        return <VulnerabilitiesPage vulnerabilities={vulnerabilities} />;
      case 'correlation':
        return <CorrelationPage vulnerabilities={vulnerabilities} correlations={correlations} />;
      case 'repeater':
        return <RepeaterPage currentScanId={currentScanId} />;
      case 'tools':
        return <ToolsPage toolActivity={toolActivity} />;
      default:
        return <DashboardPage 
          stats={stats}
          vulnerabilities={vulnerabilities}
          scanStatus={scanStatus}
          progress={progress}
          currentPhase={currentPhase}
          correlations={correlations}
          chains={chains}
        />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Top Navigation */}
      <nav className="bg-gray-900 border-b border-gray-800 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex justify-between h-16 items-center">
            <div className="flex items-center space-x-8">
              <h1 className="text-xl font-bold bg-gradient-to-r from-purple-400 to-pink-600 bg-clip-text text-transparent">
                CyberSage v2.0 Professional
              </h1>
              <div className="flex space-x-1">
                {[
                  { id: 'dashboard', label: 'Dashboard', icon: '📊' },
                  { id: 'scanner', label: 'Scanner', icon: '🎯' },
                  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '⚠️' },
                  { id: 'correlation', label: 'AI Correlation', icon: '🧠' },
                  { id: 'repeater', label: 'Repeater', icon: '🛰️' },
                  { id: 'tools', label: 'Tools', icon: '🔧' }
                ].map(page => (
                  <button
                    key={page.id}
                    onClick={() => setCurrentPage(page.id)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
                      currentPage === page.id
                        ? 'bg-purple-600 text-white'
                        : 'text-gray-400 hover:text-white hover:bg-gray-800'
                    }`}
                  >
                    <span className="mr-2">{page.icon}</span>
                    <span className="hidden md:inline">{page.label}</span>
                  </button>
                ))}
              </div>
            </div>
            <div className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-sm ${
              connected ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'
            }`}>
              <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
              <span className="font-medium">{connected ? 'Connected' : 'Offline'}</span>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {!connected && (
          <div className="mb-6 bg-red-900/30 border border-red-500 rounded-lg p-4">
            <p className="text-red-400 font-medium">
              ⚠️ Backend not connected. Start backend: <code className="bg-black/30 px-2 py-1 rounded ml-2">cd backend && python app.py</code>
            </p>
          </div>
        )}
        {renderPage()}
      </main>
    </div>
  );
};

// ============================================================================
// DASHBOARD PAGE
// ============================================================================
const DashboardPage = ({ stats, vulnerabilities, scanStatus, progress, currentPhase, correlations, chains }) => (
  <div className="space-y-6">
    <h2 className="text-3xl font-bold">Dashboard</h2>
    
    {/* Progress Bar */}
    {scanStatus === 'running' && (
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <div className="flex justify-between mb-3">
          <span className="text-gray-300 font-medium">{currentPhase}</span>
          <span className="text-purple-400 font-bold text-lg">{progress}%</span>
        </div>
        <div className="w-full bg-gray-800 rounded-full h-3">
          <div 
            className="h-3 bg-gradient-to-r from-purple-500 to-pink-500 rounded-full transition-all duration-500"
            style={{ width: `${Math.max(1, progress)}%` }}
          />
        </div>
      </div>
    )}

    {/* Stats Cards */}
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {[
        { key: 'critical', label: 'Critical', icon: '🔴', color: 'red' },
        { key: 'high', label: 'High', icon: '🟠', color: 'orange' },
        { key: 'medium', label: 'Medium', icon: '🟡', color: 'yellow' },
        { key: 'low', label: 'Low', icon: '🟢', color: 'blue' }
      ].map(stat => (
        <div key={stat.key} className="bg-gray-900 rounded-xl border border-gray-800 p-6 hover:border-purple-500 transition">
          <div className="flex items-center justify-between mb-2">
            <span className="text-gray-400 text-sm">{stat.label}</span>
            <span className="text-2xl">{stat.icon}</span>
          </div>
          <p className="text-3xl font-bold">{stats[stat.key]}</p>
        </div>
      ))}
    </div>

    {/* AI Correlations */}
    {correlations.length > 0 && (
      <div className="bg-gradient-to-br from-purple-900/50 to-pink-900/50 rounded-xl border-2 border-purple-500 p-6 animate-pulse-glow">
        <h3 className="text-xl font-bold mb-4 flex items-center">
          <span className="mr-2">🧠</span>
          AI Detected {correlations.length} Correlation{correlations.length !== 1 ? 's' : ''}
        </h3>
        <div className="space-y-3">
          {correlations.map(corr => (
            <div key={corr.id} className="bg-black/30 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-bold">{corr.title}</h4>
                <span className="px-2 py-1 bg-red-500 rounded text-xs font-bold">
                  {corr.severity.toUpperCase()}
                </span>
              </div>
              <p className="text-sm text-gray-300">{corr.description}</p>
              <p className="text-xs text-gray-400 mt-2">Involves {corr.vulns.length} vulnerabilities</p>
            </div>
          ))}
        </div>
      </div>
    )}

    {/* Attack Chains */}
    {chains.length > 0 && (
      <div className="bg-gradient-to-br from-red-900/50 to-pink-900/50 rounded-xl border-2 border-red-500 p-6">
        <h3 className="text-xl font-bold mb-4">⚠️ Attack Chains Detected</h3>
        <div className="space-y-3">
          {chains.map(chain => (
            <div key={chain.id} className="bg-black/30 rounded-lg p-4">
              <h4 className="font-bold">{chain.name}</h4>
              <p className="text-sm text-gray-300 mt-1">{chain.impact}</p>
            </div>
          ))}
        </div>
      </div>
    )}

    {/* Recent Vulnerabilities */}
    <div className="bg-gray-900 rounded-xl border border-gray-800">
      <div className="p-6 border-b border-gray-800">
        <h3 className="text-xl font-bold">Recent Vulnerabilities</h3>
      </div>
      <div className="divide-y divide-gray-800 max-h-96 overflow-y-auto">
        {vulnerabilities.length === 0 ? (
          <div className="p-12 text-center text-gray-500">
            No vulnerabilities detected yet. Start a scan to begin.
          </div>
        ) : (
          vulnerabilities.slice(0, 10).map(vuln => (
            <div key={vuln.id} className="p-4 hover:bg-gray-800/50 transition">
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-1">
                    <h4 className="font-semibold">{vuln.type}</h4>
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                      vuln.severity === 'critical' ? 'bg-red-500' :
                      vuln.severity === 'high' ? 'bg-orange-500' :
                      vuln.severity === 'medium' ? 'bg-yellow-500 text-black' : 'bg-blue-500'
                    }`}>
                      {vuln.severity?.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-sm text-gray-400">{vuln.title}</p>
                  <div className="flex items-center space-x-4 text-xs text-gray-500 mt-2">
                    <span>Confidence: {vuln.confidence}%</span>
                    <span>Tool: {vuln.tool}</span>
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  </div>
);

// ============================================================================
// SCANNER PAGE
// ============================================================================
const ScannerPage = ({ startScan, connected, scanStatus }) => {
  const [target, setTarget] = useState('');
  const [scanMode, setScanMode] = useState('elite');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [tools, setTools] = useState({
    nmap: true,
    theHarvester: true,
    amass: true,
    ffuf: true,
    sqlmap: true,
    nikto: true,
    nuclei: true
  });

  const modes = [
    { id: 'quick', name: 'Quick', time: '5-10 min', desc: 'Basic checks', icon: '⚡' },
    { id: 'standard', name: 'Standard', time: '15-30 min', desc: 'Comprehensive', icon: '🔍' },
    { id: 'elite', name: 'Elite', time: '30-60 min', desc: 'Full analysis', icon: '🧠' }
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <h2 className="text-3xl font-bold">Security Scanner</h2>
      
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <label className="block text-sm font-medium text-gray-300 mb-3">Target URL or IP</label>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="https://example.com or 192.168.1.1"
          disabled={scanStatus === 'running'}
          className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50"
        />
      </div>

      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <label className="block text-sm font-medium text-gray-300 mb-4">Scan Mode</label>
        <div className="grid grid-cols-3 gap-4">
          {modes.map(mode => (
            <button
              key={mode.id}
              onClick={() => setScanMode(mode.id)}
              disabled={scanStatus === 'running'}
              className={`p-4 rounded-lg border-2 transition ${
                scanMode === mode.id 
                  ? 'border-purple-500 bg-purple-900/20' 
                  : 'border-gray-700 hover:border-gray-600'
              } disabled:opacity-50`}
            >
              <div className="text-3xl mb-2">{mode.icon}</div>
              <div className="font-semibold">{mode.name}</div>
              <div className="text-xs text-gray-400 mt-1">{mode.time}</div>
              <div className="text-xs text-gray-500 mt-1">{mode.desc}</div>
            </button>
          ))}
        </div>
      </div>

      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center justify-between w-full text-left"
        >
          <span className="font-medium">Advanced Options</span>
          <span className="text-gray-400">{showAdvanced ? '▼' : '▶'}</span>
        </button>
        
        {showAdvanced && (
          <div className="mt-4 pt-4 border-t border-gray-800">
            <label className="block text-sm text-gray-400 mb-3">Professional Tools</label>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {Object.keys(tools).map(tool => (
                <label key={tool} className="flex items-center space-x-2 p-2 bg-gray-800 rounded cursor-pointer hover:bg-gray-750">
                  <input
                    type="checkbox"
                    checked={tools[tool]}
                    onChange={(e) => setTools({ ...tools, [tool]: e.target.checked })}
                    className="w-4 h-4 text-purple-600 rounded"
                  />
                  <span className="text-sm">{tool}</span>
                </label>
              ))}
            </div>
          </div>
        )}
      </div>

      <button
        onClick={() => startScan(target, scanMode, { tools })}
        disabled={!target || !connected || scanStatus === 'running'}
        className="w-full py-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 rounded-lg font-bold text-lg transition disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {scanStatus === 'running' ? (
          <span className="flex items-center justify-center">
            <svg className="animate-spin -ml-1 mr-3 h-5 w-5" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Scanning...
          </span>
        ) : (
          '🚀 Start Security Scan'
        )}
      </button>
    </div>
  );
};

// ============================================================================
// VULNERABILITIES PAGE
// ============================================================================
const VulnerabilitiesPage = ({ vulnerabilities }) => {
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  const filtered = vulnerabilities.filter(v => {
    const matchesFilter = filter === 'all' || v.severity === filter;
    const matchesSearch = !searchTerm || 
      v.type?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      v.title?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-3xl font-bold">Vulnerabilities</h2>
        <div className="text-2xl font-bold">{filtered.length} Found</div>
      </div>

      <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
        <div className="flex flex-wrap gap-3">
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search vulnerabilities..."
            className="flex-1 min-w-[200px] px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500"
          />
          <div className="flex gap-2">
            {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition ${
                  filter === sev ? 'bg-purple-600 text-white' : 'bg-gray-800 hover:bg-gray-700'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="space-y-3">
        {filtered.length === 0 ? (
          <div className="bg-gray-900 rounded-xl border border-gray-800 p-12 text-center">
            <p className="text-gray-500 text-lg">
              {vulnerabilities.length === 0 
                ? 'No vulnerabilities detected yet'
                : 'No vulnerabilities match your filters'}
            </p>
          </div>
        ) : (
          filtered.map(vuln => (
            <div key={vuln.id} className="bg-gray-900 rounded-xl border border-gray-800 p-6 hover:border-purple-500 transition">
              <div className="flex justify-between items-start mb-3">
                <div className="flex-1">
                  <h3 className="text-lg font-bold">{vuln.type}</h3>
                  <p className="text-gray-400 text-sm mt-1">{vuln.title}</p>
                </div>
                <span className={`px-3 py-1 rounded-full text-xs font-bold ml-4 ${
                  vuln.severity === 'critical' ? 'bg-red-500 text-white' :
                  vuln.severity === 'high' ? 'bg-orange-500 text-white' :
                  vuln.severity === 'medium' ? 'bg-yellow-500 text-black' : 'bg-blue-500 text-white'
                }`}>
                  {vuln.severity?.toUpperCase()}
                </span>
              </div>
              <div className="flex flex-wrap gap-4 text-xs text-gray-500">
                <span className="flex items-center">
                  <span className="mr-1">🎯</span>
                  Confidence: {vuln.confidence}%
                </span>
                <span className="flex items-center">
                  <span className="mr-1">🛠️</span>
                  Tool: {vuln.tool}
                </span>
                {vuln.url && (
                  <span className="flex items-center truncate max-w-md">
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

// ============================================================================
// AI CORRELATION PAGE
// ============================================================================
const CorrelationPage = ({ vulnerabilities, correlations }) => {
  const riskScore = vulnerabilities.length > 15 ? 'Critical' : 
                    vulnerabilities.length > 8 ? 'High' : 
                    vulnerabilities.length > 3 ? 'Medium' : 'Low';

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold mb-2">🧠 AI-Powered Vulnerability Correlation</h2>
        <p className="text-gray-400">Machine learning analysis to detect related vulnerabilities and attack patterns</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <p className="text-gray-400 text-sm">Total Vulnerabilities</p>
          <p className="text-3xl font-bold">{vulnerabilities.length}</p>
        </div>
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <p className="text-gray-400 text-sm">Correlations Found</p>
          <p className="text-3xl font-bold text-purple-400">{correlations.length}</p>
        </div>
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <p className="text-gray-400 text-sm">Risk Level</p>
          <p className={`text-3xl font-bold ${
            riskScore === 'Critical' ? 'text-red-500' :
            riskScore === 'High' ? 'text-orange-500' :
            riskScore === 'Medium' ? 'text-yellow-500' : 'text-green-500'
          }`}>
            {riskScore}
          </p>
        </div>
      </div>

      {correlations.length > 0 ? (
        <div className="space-y-4">
          {correlations.map(corr => (
            <div key={corr.id} className="bg-gradient-to-br from-purple-900/50 to-pink-900/50 rounded-xl border-2 border-purple-500 p-6">
              <div className="flex items-start justify-between mb-3">
                <h3 className="text-xl font-bold">{corr.title}</h3>
                <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                  corr.severity === 'critical' ? 'bg-red-500' : 'bg-orange-500'
                }`}>
                  {corr.severity.toUpperCase()}
                </span>
              </div>
              <p className="text-gray-300 mb-4">{corr.description}</p>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-purple-400">Related Vulnerabilities:</p>
                {corr.vulns.map((v, idx) => (
                  <div key={idx} className="bg-black/30 rounded p-3 text-sm">
                    <span className="font-semibold">{v.type}</span>
                    <span className="text-gray-400 ml-2">- {v.title}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-12 text-center">
          <div className="text-6xl mb-4">
            {vulnerabilities.length === 0 ? '🔍' : '✅'}
          </div>
          <p className="text-gray-500 text-lg">
            {vulnerabilities.length === 0 
              ? 'No vulnerabilities yet. Start a scan to see AI correlations.'
              : 'No significant correlations detected. This is a good security posture!'}
          </p>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// REPEATER PAGE
// ============================================================================
const RepeaterPage = ({ currentScanId }) => {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('');
  const [headers, setHeaders] = useState('{"User-Agent": "CyberSage/2.0"}');
  const [body, setBody] = useState('');
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);

  const sendRequest = async () => {
    if (!url) {
      alert('Please enter a URL');
      return;
    }

    setLoading(true);
    try {
      let parsedHeaders = {};
      try {
        parsedHeaders = JSON.parse(headers);
      } catch (e) {
        alert('Invalid JSON in headers');
        setLoading(false);
        return;
      }

      const res = await fetch('http://localhost:5000/api/repeater/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method,
          url,
          headers: parsedHeaders,
          body,
          scan_id: currentScanId || `manual_${Date.now()}`
        })
      });

      const data = await res.json();
      const newResponse = data.response || { error: data.error };
      setResponse(newResponse);
      
      setHistory(prev => [{
        id: Date.now(),
        method,
        url,
        timestamp: new Date().toLocaleTimeString(),
        response: newResponse
      }, ...prev].slice(0, 10));
    } catch (error) {
      setResponse({ error: error.message });
    }
    setLoading(false);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold mb-2">🛰️ HTTP Repeater</h2>
        <p className="text-gray-400">Manual HTTP request testing and exploit verification</p>
      </div>
      
      {/* Request Builder */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 space-y-4">
        <div className="flex space-x-2">
          <select
            value={method}
            onChange={(e) => setMethod(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
          >
            {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://target.com/api/endpoint"
            className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500"
          />
          <button
            onClick={sendRequest}
            disabled={loading}
            className="px-6 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg font-bold transition disabled:opacity-50"
          >
            {loading ? 'Sending...' : 'Send'}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Headers (JSON)</label>
            <textarea
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
              className="w-full h-32 p-3 bg-gray-800 border border-gray-700 rounded-lg text-white font-mono text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
              placeholder='{"Authorization": "Bearer token"}'
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Request Body</label>
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              className="w-full h-32 p-3 bg-gray-800 border border-gray-700 rounded-lg text-white font-mono text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
              placeholder='{"key": "value"}'
            />
          </div>
        </div>
      </div>

      {/* Response Viewer */}
      {response && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <h3 className="text-lg font-bold mb-4">Response</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div className="bg-gray-800 rounded-lg p-3">
              <p className="text-xs text-gray-400">Status Code</p>
              <p className={`text-lg font-bold ${
                response.code >= 200 && response.code < 300 ? 'text-green-400' :
                response.code >= 400 ? 'text-red-400' : 'text-yellow-400'
              }`}>
                {response.code || 'N/A'}
              </p>
            </div>
            <div className="bg-gray-800 rounded-lg p-3">
              <p className="text-xs text-gray-400">Response Time</p>
              <p className="text-lg font-bold text-blue-400">{response.time_ms || 0} ms</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-3">
              <p className="text-xs text-gray-400">Body Size</p>
              <p className="text-lg font-bold">{response.body?.length || 0} bytes</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-3">
              <p className="text-xs text-gray-400">Headers</p>
              <p className="text-lg font-bold">{Object.keys(response.headers || {}).length}</p>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Response Body</label>
              <pre className="p-4 bg-gray-800 rounded-lg text-xs text-gray-300 overflow-auto max-h-96 font-mono">
                {response.body || response.error || 'No response body'}
              </pre>
            </div>

            {response.headers && Object.keys(response.headers).length > 0 && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Response Headers</label>
                <div className="bg-gray-800 rounded-lg p-4 space-y-1 max-h-48 overflow-auto">
                  {Object.entries(response.headers).map(([key, value]) => (
                    <div key={key} className="flex text-xs font-mono">
                      <span className="text-purple-400 font-semibold mr-2">{key}:</span>
                      <span className="text-gray-300">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Request History */}
      {history.length > 0 && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <h3 className="text-lg font-bold mb-4">Request History</h3>
          <div className="space-y-2">
            {history.map(item => (
              <button
                key={item.id}
                onClick={() => {
                  setMethod(item.method);
                  setUrl(item.url);
                  setResponse(item.response);
                }}
                className="w-full text-left p-3 bg-gray-800 hover:bg-gray-750 rounded-lg transition"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className="px-2 py-1 bg-purple-600 rounded text-xs font-bold">{item.method}</span>
                    <span className="text-sm font-mono truncate max-w-md">{item.url}</span>
                  </div>
                  <span className="text-xs text-gray-500">{item.timestamp}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// TOOLS PAGE
// ============================================================================
const ToolsPage = ({ toolActivity }) => (
  <div className="space-y-6">
    <h2 className="text-3xl font-bold">Professional Tools Activity</h2>

    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {[
        { name: 'Nmap', desc: 'Network & port scanning', icon: '🌐' },
        { name: 'SQLMap', desc: 'SQL injection detection', icon: '💉' },
        { name: 'Nikto', desc: 'Web server scanner', icon: '🕸️' },
        { name: 'Nuclei', desc: 'Template-based scanning', icon: '🎯' },
        { name: 'Ffuf', desc: 'Web fuzzing', icon: '🔍' },
        { name: 'theHarvester', desc: 'OSINT gathering', icon: '📧' }
      ].map(tool => (
        <div key={tool.name} className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <div className="flex items-center space-x-3 mb-3">
            <span className="text-3xl">{tool.icon}</span>
            <div>
              <h3 className="font-bold">{tool.name}</h3>
              <p className="text-xs text-gray-400">{tool.desc}</p>
            </div>
          </div>
          <div className="flex items-center space-x-2 text-sm">
            <div className={`w-2 h-2 rounded-full ${
              toolActivity.some(a => a.tool === tool.name && a.status === 'running')
                ? 'bg-green-500 animate-pulse'
                : 'bg-gray-600'
            }`} />
            <span className="text-gray-400">
              {toolActivity.some(a => a.tool === tool.name && a.status === 'running')
                ? 'Running'
                : 'Idle'}
            </span>
          </div>
        </div>
      ))}
    </div>

    <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
      <h3 className="text-lg font-bold mb-4">Recent Activity</h3>
      <div className="space-y-2">
        {toolActivity.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            No tool activity yet. Start a scan to see tools in action.
          </div>
        ) : (
          toolActivity.map((activity, idx) => (
            <div key={idx} className="flex items-center justify-between p-3 bg-gray-800 rounded-lg">
              <div className="flex items-center space-x-3">
                <div className={`w-2 h-2 rounded-full ${
                  activity.status === 'running' ? 'bg-green-500 animate-pulse' : 'bg-blue-500'
                }`} />
                <div>
                  <p className="font-semibold text-sm">{activity.tool}</p>
                  <p className="text-xs text-gray-400">{activity.target}</p>
                </div>
              </div>
              {activity.findings !== undefined && (
                <span className="px-2 py-1 bg-purple-600 rounded text-xs font-bold">
                  {activity.findings} found
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  </div>
);

export default CyberSageApp;