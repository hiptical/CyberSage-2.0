import React, { useState } from 'react';

const ScanControl = ({ onStartScan, scanStatus, connected }) => {
  const [target, setTarget] = useState('');
  const [scanMode, setScanMode] = useState('elite');

  const handleStartScan = (e) => {
    e.preventDefault();
    
    if (!target.trim()) {
      alert('Please enter a target URL or domain');
      return;
    }
    
    if (!connected) {
      alert('Not connected to backend');
      return;
    }
    
    onStartScan(target, scanMode);
  };

  const isScanning = scanStatus === 'running';

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 shadow-xl">
      <form onSubmit={handleStartScan} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Target URL or Domain
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com or example.com"
            disabled={isScanning}
            className="w-full px-4 py-3 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent disabled:opacity-50 disabled:cursor-not-allowed transition"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Scan Mode
          </label>
          <div className="grid grid-cols-3 gap-3">
            <button
              type="button"
              onClick={() => setScanMode('quick')}
              disabled={isScanning}
              className={`px-4 py-3 rounded-lg font-medium transition ${
                scanMode === 'quick'
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              } disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              ⚡ Quick
            </button>
            <button
              type="button"
              onClick={() => setScanMode('standard')}
              disabled={isScanning}
              className={`px-4 py-3 rounded-lg font-medium transition ${
                scanMode === 'standard'
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              } disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              🔍 Standard
            </button>
            <button
              type="button"
              onClick={() => setScanMode('elite')}
              disabled={isScanning}
              className={`px-4 py-3 rounded-lg font-medium transition ${
                scanMode === 'elite'
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              } disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              🧠 Elite
            </button>
          </div>
          <p className="text-xs text-gray-500 mt-2">
            {scanMode === 'quick' && '~5 mins: Basic vulnerabilities'}
            {scanMode === 'standard' && '~15 mins: Comprehensive scan'}
            {scanMode === 'elite' && '~30 mins: Advanced detection + AI analysis'}
          </p>
        </div>

        <button
          type="submit"
          disabled={isScanning || !connected}
          className={`w-full px-6 py-4 rounded-lg font-bold text-lg transition transform ${
            isScanning
              ? 'bg-gray-600 cursor-not-allowed'
              : 'bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 hover:scale-105 active:scale-95'
          } text-white shadow-lg disabled:opacity-50`}
        >
          {isScanning ? (
            <span className="flex items-center justify-center">
              <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Scanning in Progress...
            </span>
          ) : (
            '🚀 Start Elite Scan'
          )}
        </button>
      </form>

      {scanStatus === 'completed' && (
        <div className="mt-4 p-4 bg-green-900/30 border border-green-700 rounded-lg">
          <p className="text-green-400 font-medium">✅ Scan completed successfully!</p>
        </div>
      )}

      {scanStatus === 'error' && (
        <div className="mt-4 p-4 bg-red-900/30 border border-red-700 rounded-lg">
          <p className="text-red-400 font-medium">❌ Scan failed. Please try again.</p>
        </div>
      )}
    </div>
  );
};

export default ScanControl;