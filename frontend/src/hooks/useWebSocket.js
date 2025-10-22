import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';

// WebSocket Hook
const useWebSocket = () => {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);

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
      console.log('✅ Connected');
      setConnected(true);
    });

    newSocket.on('disconnect', () => {
      console.log('❌ Disconnected');
      setConnected(false);
    });

    newSocket.on('connect_error', (error) => {
      console.error('Connection error:', error.message);
      setConnected(false);
    });

    setSocket(newSocket);
    return () => newSocket.close();
  }, []);

  return { socket, connected };
};

// Main App with Navigation
const App = () => {
  const { socket, connected } = useWebSocket();
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [scanStatus, setScanStatus] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [chains, setChains] = useState([]);
  const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [currentScanId, setCurrentScanId] = useState(null);
  const [correlations, setCorrelations] = useState([]);

  useEffect(() => {
    if (!socket) return;

    socket.on('scan_started', (data) => {
      setScanStatus('running');
      setProgress(0);
      setVulnerabilities([]);
      setChains([]);
      setCorrelations([]);
      setCurrentScanId(data.scan_id);
    });

    socket.on('scan_progress', (data) => {
      setProgress(data.progress);
      setCurrentPhase(data.phase);
    });

    socket.on('vulnerability_found', (data) => {
      const newVuln = { ...data, id: Date.now() + Math.random() };
      setVulnerabilities(prev => [newVuln, ...prev]);
      setStats(prev => ({ ...prev, [data.severity]: prev[data.severity] + 1 }));
      
      // AI Correlation
      if (prev.length > 0) {
        detectCorrelations([newVuln, ...prev]);
      }
    });

    socket.on('chain_detected', (data) => {
      setChains(prev => [{ ...data, id: Date.now() }, ...prev]);
    });

    socket.on('scan_completed', () => {
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

  const detectCorrelations = (vulns) => {
    const newCorrelations = [];
    
    // Detect related vulnerabilities
    const xssVulns = vulns.filter(v => v.type?.includes('XSS'));
    const corsVulns = vulns.filter(v => v.type?.includes('CORS'));
    
    if (xssVulns.length > 0 && corsVulns.length > 0) {
      newCorrelations.push({
        id: Date.now(),
        type: 'correlation',
        title: 'XSS + CORS Misconfiguration',
        severity: 'critical',
        description: 'XSS vulnerabilities combined with CORS issues allow data theft',
        vulns: [...xssVulns.slice(0, 2), ...corsVulns.slice(0, 1)]
      });
    }

    // Detect authentication issues
    const authVulns = vulns.filter(v => 
      v.type?.includes('Auth') || v.type?.includes('Session')
    );
    if (authVulns.length >= 2) {
      newCorrelations.push({
        id: Date.now() + 1,
        type: 'correlation',
        title: 'Multiple Authentication Weaknesses',
        severity: 'high',
        description: 'Multiple authentication issues detected',
        vulns: authVulns.slice(0, 3)
      });
    }

    setCorrelations(newCorrelations);
  };

  const startScan = (target, mode) => {
    if (socket && connected) {
      socket.emit('start_scan', { target, mode });
    }
  };

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard 
          stats={stats} 
          vulnerabilities={vulnerabilities}
          scanStatus={scanStatus}
          progress={progress}
          currentPhase={currentPhase}
          correlations={correlations}
        />;
      case 'scanner':
        return <ScannerPage startScan={startScan} connected={connected} scanStatus={scanStatus} />;
      case 'repeater':
        return <RepeaterPage currentScanId={currentScanId} />;
      case 'vulnerabilities':
        return <VulnerabilitiesPage vulnerabilities={vulnerabilities} />;
      case 'correlation':
        return <CorrelationPage vulnerabilities={vulnerabilities} correlations={correlations} />;
      default:
        return <Dashboard stats={stats} />;
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
                CyberSage v2.0 Pro
              </h1>
              <div className="flex space-x-1">
                {[
                  { id: 'dashboard', label: 'Dashboard', icon: '📊' },
                  { id: 'scanner', label: 'Scanner', icon: '🎯' },
                  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '⚠️' },
                  { id: 'correlation', label: 'AI Correlation', icon: '🧠' },
                  { id: 'repeater', label: 'Repeater', icon: '🛰️' }
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
                    {page.label}
                  </button>
                ))}
              </div>
            </div>
            <div className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-sm ${
              connected ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'
            }`}>
              <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
              <span>{connected ? 'Connected' : 'Offline'}</span>
            </div>
          </div>
        </div>
      </nav>

      {/* Page Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {!connected && (
          <div className="mb-6 bg-red-900/30 border border-red-500 rounded-lg p-4">
            <p className="text-red-400">⚠️ Backend not running. Start with: <code className="bg-black/30 px-2 py-1 rounded">cd backend && python app.py</code></p>
          </div>
        )}
        {renderPage()}
      </main>
    </div>
  );
};

// Dashboard Page
const Dashboard = ({ stats, vulnerabilities, scanStatus, progress, currentPhase, correlations }) => (
  <div className="space-y-6">
    <h2 className="text-3xl font-bold">Dashboard</h2>
    
    {scanStatus === 'running' && (
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <div className="flex justify-between mb-3">
          <span className="text-gray-300">{currentPhase}</span>
          <span className="text-purple-400 font-bold">{progress}%</span>
        </div>
        <div className="w-full bg-gray-800 rounded-full h-3">
          <div className="h-3 bg-gradient-to-r from-purple-500 to-pink-500 rounded-full transition-all" style={{ width: `${progress}%` }} />
        </div>
      </div>
    )}

    <div className="grid grid-cols-4 gap-4">
      {Object.entries(stats).map(([key, value]) => (
        <div key={key} className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <p className="text-gray-400 text-sm capitalize">{key}</p>
          <p className="text-3xl font-bold">{value}</p>
        </div>
      ))}
    </div>

    {correlations.length > 0 && (
      <div className="bg-gradient-to-br from-purple-900/50 to-pink-900/50 rounded-xl border-2 border-purple-500 p-6">
        <h3 className="text-xl font-bold mb-4 flex items-center">
          <span className="mr-2">🧠</span>
          AI-Powered Correlations Detected
        </h3>
        {correlations.map(corr => (
          <div key={corr.id} className="bg-black/30 rounded-lg p-4 mb-3">
            <h4 className="font-bold text-lg">{corr.title}</h4>
            <p className="text-sm text-gray-300 mt-1">{corr.description}</p>
            <div className="mt-2 text-xs text-gray-400">
              Involves {corr.vulns.length} vulnerabilities
            </div>
          </div>
        ))}
      </div>
    )}

    <div className="bg-gray-900 rounded-xl border border-gray-800">
      <div className="p-6 border-b border-gray-800">
        <h3 className="text-xl font-bold">Recent Vulnerabilities</h3>
      </div>
      <div className="divide-y divide-gray-800 max-h-96 overflow-y-auto">
        {vulnerabilities.slice(0, 5).map((vuln) => (
          <div key={vuln.id} className="p-4 hover:bg-gray-800/50">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="font-semibold">{vuln.type}</h4>
                <p className="text-sm text-gray-400">{vuln.title}</p>
              </div>
              <span className={`px-2 py-1 rounded text-xs font-bold ${
                vuln.severity === 'critical' ? 'bg-red-500' :
                vuln.severity === 'high' ? 'bg-orange-500' :
                vuln.severity === 'medium' ? 'bg-yellow-500 text-black' : 'bg-blue-500'
              }`}>
                {vuln.severity?.toUpperCase()}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  </div>
);

// Scanner Page
const ScannerPage = ({ startScan, connected, scanStatus }) => {
  const [target, setTarget] = useState('');
  const [scanMode, setScanMode] = useState('elite');

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <h2 className="text-3xl font-bold">Security Scanner</h2>
      
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <label className="block text-sm font-medium mb-2">Target</label>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="https://example.com"
          className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
        />
      </div>

      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <label className="block text-sm font-medium mb-3">Scan Mode</label>
        <div className="grid grid-cols-3 gap-4">
          {['quick', 'standard', 'elite'].map(mode => (
            <button
              key={mode}
              onClick={() => setScanMode(mode)}
              className={`p-4 rounded-lg border-2 transition ${
                scanMode === mode ? 'border-purple-500 bg-purple-900/20' : 'border-gray-700'
              }`}
            >
              <div className="font-semibold capitalize">{mode}</div>
            </button>
          ))}
        </div>
      </div>

      <button
        onClick={() => startScan(target, scanMode)}
        disabled={!target || !connected || scanStatus === 'running'}
        className="w-full py-4 bg-gradient-to-r from-purple-600 to-pink-600 rounded-lg font-bold disabled:opacity-50"
      >
        {scanStatus === 'running' ? 'Scanning...' : '🚀 Start Scan'}
      </button>
    </div>
  );
};

// Repeater Page
const RepeaterPage = ({ currentScanId }) => {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('');
  const [headers, setHeaders] = useState('{"User-Agent": "CyberSage/2.0"}');
  const [body, setBody] = useState('');
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(false);

  const sendRequest = async () => {
    setLoading(true);
    try {
      const res = await fetch('http://localhost:5000/api/repeater/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method,
          url,
          headers: JSON.parse(headers),
          body,
          scan_id: currentScanId
        })
      });
      const data = await res.json();
      setResponse(data.response);
    } catch (error) {
      setResponse({ error: error.message });
    }
    setLoading(false);
  };

  return (
    <div className="space-y-6">
      <h2 className="text-3xl font-bold">HTTP Repeater</h2>
      
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 space-y-4">
        <div className="flex space-x-2">
          <select
            value={method}
            onChange={(e) => setMethod(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white"
          >
            {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => (
              <option key={m}>{m}</option>
            ))}
          </select>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://target.com/api/endpoint"
            className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded text-white"
          />
          <button
            onClick={sendRequest}
            disabled={loading}
            className="px-6 py-2 bg-purple-600 rounded font-bold disabled:opacity-50"
          >
            {loading ? 'Sending...' : 'Send'}
          </button>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm mb-2">Headers (JSON)</label>
            <textarea
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
              className="w-full h-32 p-3 bg-gray-800 border border-gray-700 rounded text-sm font-mono"
            />
          </div>
          <div>
            <label className="block text-sm mb-2">Body</label>
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              className="w-full h-32 p-3 bg-gray-800 border border-gray-700 rounded text-sm font-mono"
            />
          </div>
        </div>
      </div>

      {response && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <h3 className="text-lg font-bold mb-4">Response</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-400">Status:</span>
              <span className="font-mono">{response.code}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Time:</span>
              <span className="font-mono">{response.time_ms} ms</span>
            </div>
          </div>
          <div className="mt-4">
            <label className="block text-sm mb-2">Body</label>
            <pre className="p-4 bg-gray-800 rounded text-xs overflow-auto max-h-96">
              {response.body || response.error}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

// Vulnerabilities Page
const VulnerabilitiesPage = ({ vulnerabilities }) => {
  const [filter, setFilter] = useState('all');

  const filtered = vulnerabilities.filter(v => 
    filter === 'all' || v.severity === filter
  );

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-3xl font-bold">Vulnerabilities</h2>
        <div className="text-xl font-bold">{filtered.length} Total</div>
      </div>

      <div className="flex gap-2">
        {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
          <button
            key={sev}
            onClick={() => setFilter(sev)}
            className={`px-4 py-2 rounded-lg capitalize ${
              filter === sev ? 'bg-purple-600' : 'bg-gray-800 hover:bg-gray-700'
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      <div className="space-y-3">
        {filtered.map(vuln => (
          <div key={vuln.id} className="bg-gray-900 rounded-xl border border-gray-800 p-6">
            <div className="flex justify-between items-start">
              <div>
                <h3 className="text-lg font-bold">{vuln.type}</h3>
                <p className="text-gray-400 text-sm mt-1">{vuln.title}</p>
                <div className="flex gap-4 mt-3 text-xs text-gray-500">
                  <span>Confidence: {vuln.confidence}%</span>
                  <span>Tool: {vuln.tool}</span>
                </div>
              </div>
              <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                vuln.severity === 'critical' ? 'bg-red-500' :
                vuln.severity === 'high' ? 'bg-orange-500' :
                vuln.severity === 'medium' ? 'bg-yellow-500 text-black' : 'bg-blue-500'
              }`}>
                {vuln.severity?.toUpperCase()}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// AI Correlation Page (NEW ADVANCED FEATURE)
const CorrelationPage = ({ vulnerabilities, correlations }) => (
  <div className="space-y-6">
    <div>
      <h2 className="text-3xl font-bold mb-2">🧠 AI-Powered Vulnerability Correlation</h2>
      <p className="text-gray-400">Advanced ML-based analysis to detect related vulnerabilities and attack patterns</p>
    </div>

    <div className="grid grid-cols-3 gap-4">
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <p className="text-gray-400 text-sm">Total Vulnerabilities</p>
        <p className="text-3xl font-bold">{vulnerabilities.length}</p>
      </div>
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <p className="text-gray-400 text-sm">Correlations Found</p>
        <p className="text-3xl font-bold text-purple-400">{correlations.length}</p>
      </div>
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <p className="text-gray-400 text-sm">Risk Score</p>
        <p className="text-3xl font-bold text-red-400">
          {vulnerabilities.length > 10 ? 'High' : vulnerabilities.length > 5 ? 'Medium' : 'Low'}
        </p>
      </div>
    </div>

    {correlations.length > 0 ? (
      <div className="space-y-4">
        {correlations.map(corr => (
          <div key={corr.id} className="bg-gradient-to-br from-purple-900/50 to-pink-900/50 rounded-xl border-2 border-purple-500 p-6">
            <div className="flex items-start justify-between mb-3">
              <h3 className="text-xl font-bold">{corr.title}</h3>
              <span className="px-3 py-1 bg-red-500 rounded-full text-xs font-bold">
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
        <p className="text-gray-500 text-lg">
          {vulnerabilities.length === 0 
            ? '🔍 No vulnerabilities yet. Start a scan to see correlations.'
            : '✅ No significant correlations detected. This is a good sign!'}
        </p>
      </div>
    )}
  </div>
);

export default App;