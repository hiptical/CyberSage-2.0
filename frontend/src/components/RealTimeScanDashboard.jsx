// frontend/src/components/RealTimeScanDashboard.jsx
import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import { motion, AnimatePresence } from 'framer-motion';

const RealTimeScanDashboard = () => {
  const [socket, setSocket] = useState(null);
  const [scanStatus, setScanStatus] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [toolActivity, setToolActivity] = useState([]);
  const [chains, setChains] = useState([]);
  const [stats, setStats] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });

  useEffect(() => {
    // Connect to WebSocket
    const newSocket = io('http://localhost:5000/scan', {
      transports: ['websocket']
    });

    newSocket.on('connected', (data) => {
      console.log('Connected to CyberSage backend');
    });

    newSocket.on('tool_started', (data) => {
      setToolActivity(prev => [{
        tool: data.tool,
        target: data.target,
        status: 'running',
        timestamp: data.timestamp
      }, ...prev].slice(0, 10));
    });

    newSocket.on('vulnerability_found', (data) => {
      // Add vulnerability with animation
      setVulnerabilities(prev => [data, ...prev]);
      
      // Update stats
      setStats(prev => ({
        ...prev,
        [data.severity]: prev[data.severity] + 1
      }));
      
      // Show notification
      showVulnNotification(data);
    });

    newSocket.on('scan_progress', (data) => {
      setProgress(data.progress);
      setCurrentPhase(data.phase);
    });

    newSocket.on('chain_detected', (data) => {
      setChains(prev => [data, ...prev]);
      showChainAlert(data);
    });

    setSocket(newSocket);

    return () => newSocket.close();
  }, []);

  const startScan = (target, mode) => {
    if (socket) {
      setScanStatus('running');
      setVulnerabilities([]);
      setStats({ critical: 0, high: 0, medium: 0, low: 0 });
      
      socket.emit('start_scan', {
        target: target,
        mode: mode
      });
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900">
      {/* Animated Background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse"></div>
        <div className="absolute top-1/3 right-1/4 w-96 h-96 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse delay-1000"></div>
      </div>

      <div className="relative z-10 container mx-auto px-4 py-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-600">
            CyberSage v2.0
          </h1>
          <p className="text-gray-400 mt-2">Elite Vulnerability Intelligence Platform</p>
        </motion.div>

        {/* Scan Control */}
        <ScanControl onStartScan={startScan} scanStatus={scanStatus} />

        {/* Real-Time Progress */}
        <AnimatePresence>
          {scanStatus === 'running' && (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              className="mb-8"
            >
              <ProgressBar progress={progress} phase={currentPhase} />
            </motion.div>
          )}
        </AnimatePresence>

        {/* Stats Dashboard */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <StatCard
            title="Critical"
            count={stats.critical}
            color="from-red-500 to-pink-500"
            icon="🔴"
          />
          <StatCard
            title="High"
            count={stats.high}
            color="from-orange-500 to-yellow-500"
            icon="🟠"
          />
          <StatCard
            title="Medium"
            count={stats.medium}
            color="from-yellow-500 to-green-500"
            icon="🟡"
          />
          <StatCard
            title="Low"
            count={stats.low}
            color="from-green-500 to-blue-500"
            icon="🟢"
          />
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Vulnerability Feed */}
          <div className="lg:col-span-2">
            <VulnerabilityFeed vulnerabilities={vulnerabilities} />
          </div>

          {/* Tool Activity Sidebar */}
          <div>
            <ToolActivity activity={toolActivity} />
            
            {/* Chain Detection Alert */}
            {chains.length > 0 && (
              <ChainAlerts chains={chains} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const ProgressBar = ({ progress, phase }) => (
  <div className="bg-gray-800 rounded-lg p-6 border border-purple-500/20">
    <div className="flex justify-between mb-2">
      <span className="text-gray-300">Current Phase: {phase}</span>
      <span className="text-purple-400 font-bold">{progress}%</span>
    </div>
    <div className="w-full bg-gray-700 rounded-full h-3 overflow-hidden">
      <motion.div
        className="h-full bg-gradient-to-r from-purple-500 to-pink-500"
        initial={{ width: 0 }}
        animate={{ width: `${progress}%` }}
        transition={{ duration: 0.5, ease: "easeOut" }}
      />
    </div>
  </div>
);

const StatCard = ({ title, count, color, icon }) => (
  <motion.div
    whileHover={{ scale: 1.05 }}
    className="bg-gray-800 rounded-lg p-6 border border-gray-700"
  >
    <div className="flex items-center justify-between">
      <div>
        <p className="text-gray-400 text-sm">{title}</p>
        <motion.p
          key={count}
          initial={{ scale: 1.5, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="text-3xl font-bold text-white mt-1"
        >
          {count}
        </motion.p>
      </div>
      <span className="text-4xl">{icon}</span>
    </div>
    <div className={`mt-4 h-1 bg-gradient-to-r ${color} rounded-full`} />
  </motion.div>
);

const VulnerabilityFeed = ({ vulnerabilities }) => (
  <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
    <h2 className="text-xl font-bold text-white mb-4">Live Vulnerability Feed</h2>
    <div className="space-y-3 max-h-[600px] overflow-y-auto custom-scrollbar">
      <AnimatePresence>
        {vulnerabilities.map((vuln, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            className={`p-4 rounded-lg border-l-4 ${getSeverityColor(vuln.severity)} bg-gray-900`}
          >
            <div className="flex justify-between items-start">
              <div>
                <h3 className="text-white font-semibold">{vuln.type}</h3>
                <p className="text-gray-400 text-sm mt-1">{vuln.preview}</p>
              </div>
              <span className={`px-3 py-1 rounded-full text-xs font-bold ${getSeverityBadge(vuln.severity)}`}>
                {vuln.severity}
              </span>
            </div>
            <div className="mt-2 flex items-center text-xs text-gray-500">
              <span>Confidence: {vuln.confidence}%</span>
              <span className="mx-2">•</span>
              <span>{new Date(vuln.timestamp * 1000).toLocaleTimeString()}</span>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  </div>
);

const ToolActivity = ({ activity }) => (
  <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 mb-6">
    <h2 className="text-xl font-bold text-white mb-4">Tool Activity</h2>
    <div className="space-y-2">
      <AnimatePresence>
        {activity.map((item, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            className="flex items-center p-3 bg-gray-900 rounded-lg"
          >
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse mr-3" />
            <div className="flex-1">
              <p className="text-white text-sm font-medium">{item.tool}</p>
              <p className="text-gray-500 text-xs">{item.target}</p>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  </div>
);

const ChainAlerts = ({ chains }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className="bg-gradient-to-br from-red-900 to-pink-900 rounded-lg border-2 border-red-500 p-6"
  >
    <h2 className="text-xl font-bold text-white mb-4 flex items-center">
      <span className="mr-2">⚠️</span>
      Attack Chains Detected
    </h2>
    <div className="space-y-3">
      {chains.map((chain, index) => (
        <div key={index} className="bg-black/30 rounded p-3">
          <p className="text-white font-bold">{chain.name}</p>
          <p className="text-red-300 text-sm mt-1">{chain.impact}</p>
          <div className="mt-2">
            {chain.steps.map((step, si) => (
              <div key={si} className="text-xs text-gray-300 flex items-center mt-1">
                <span className="mr-2">→</span>
                {step[1]}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  </motion.div>
);

// Helper functions
const getSeverityColor = (severity) => {
  const colors = {
    critical: 'border-red-500',
    high: 'border-orange-500',
    medium: 'border-yellow-500',
    low: 'border-blue-500'
  };
  return colors[severity] || 'border-gray-500';
};

const getSeverityBadge = (severity) => {
  const badges = {
    critical: 'bg-red-500 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-500 text-black',
    low: 'bg-blue-500 text-white'
  };
  return badges[severity] || 'bg-gray-500 text-white';
};

export default RealTimeScanDashboard;