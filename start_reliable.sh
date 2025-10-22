#!/bin/bash

echo "🔧 CyberSage Complete Fix Script"
echo "================================"
echo ""

cd ~/CyberSage-2.0 || exit 1

# Step 1: Kill everything
echo "1. Cleaning up processes..."
pkill -9 -f "python"
pkill -9 -f "node"
pkill -9 -f "npm"
sleep 3

# Step 2: Fix backend
echo ""
echo "2. Fixing backend..."
cd backend

# Clean and recreate venv
echo "  - Recreating virtual environment..."
rm -rf venv
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "  - Installing dependencies..."
pip install --upgrade pip
pip install Flask==3.0.0 flask-socketio==5.3.6 flask-cors==4.0.0 python-socketio==5.11.0 requests==2.31.0 pyyaml==6.0.1 python-dotenv==1.0.0 urllib3==2.1.0 selenium==4.15.2 webdriver-manager==4.0.1 reportlab==4.0.7 jinja2==3.1.2

# Test import
echo "  - Testing imports..."
python3 -c "import flask, flask_socketio, flask_cors; print('✅ All imports successful')"

if [ $? -ne 0 ]; then
    echo "❌ Backend setup failed"
    exit 1
fi

cd ..

# Step 3: Fix frontend
echo ""
echo "3. Fixing frontend..."
cd frontend

# Fix React components
echo "  - Fixing React components..."

# Fix ScanStatistics.jsx
cat > src/components/ScanStatistics.jsx << 'EOFSTATS'
import React, { useState, useEffect, useCallback } from 'react';

const ScanStatistics = ({ scanId }) => {
  const [statistics, setStatistics] = useState({});
  const [loading, setLoading] = useState(false);
  
  const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;

  const fetchStatistics = useCallback(async () => {
    if (!scanId) return;
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

  if (!scanId) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <h2 className="text-xl font-bold text-white mb-4">📊 Statistics</h2>
        <div className="text-center py-8 text-gray-500">
          Start a scan to see statistics
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold text-white">📊 Statistics</h2>
        <button
          onClick={fetchStatistics}
          disabled={loading}
          className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded disabled:opacity-50"
        >
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-gray-900 rounded p-3">
          <div className="text-gray-400 text-sm">Endpoints</div>
          <div className="text-white font-bold text-xl">{statistics.endpoints_discovered || 0}</div>
        </div>
        <div className="bg-gray-900 rounded p-3">
          <div className="text-gray-400 text-sm">Payloads</div>
          <div className="text-white font-bold text-xl">{statistics.payloads_sent || 0}</div>
        </div>
      </div>
    </div>
  );
};

export default ScanStatistics;
EOFSTATS

# Fix VulnerabilityDetails.jsx
cat > src/components/VulnerabilityDetails.jsx << 'EOFVULN'
import React, { useState, useEffect, useCallback } from 'react';

const VulnerabilityDetails = ({ vulnerabilityId, onClose }) => {
  const [vulnerability, setVulnerability] = useState(null);
  const [loading, setLoading] = useState(true);
  
  const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;

  const fetchDetails = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch(`${backendUrl}/api/vulnerability/${vulnerabilityId}`);
      const data = await response.json();
      setVulnerability(data.vulnerability);
    } catch (error) {
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  }, [backendUrl, vulnerabilityId]);

  useEffect(() => {
    if (vulnerabilityId) {
      fetchDetails();
    }
  }, [vulnerabilityId, fetchDetails]);

  if (loading) {
    return <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6">Loading...</div>
    </div>;
  }

  if (!vulnerability) {
    return <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="text-red-400">Not found</div>
        <button onClick={onClose} className="mt-4 px-4 py-2 bg-gray-600 rounded">Close</button>
      </div>
    </div>;
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 rounded-lg border border-gray-700 max-w-4xl w-full max-h-[90vh] overflow-auto">
        <div className="flex justify-between items-center p-6 border-b border-gray-700">
          <h2 className="text-2xl font-bold text-white">Vulnerability Details</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white text-2xl">×</button>
        </div>
        <div className="p-6">
          <div className="bg-gray-900 rounded-lg p-4 mb-4">
            <h3 className="text-white font-semibold mb-2">Type: {vulnerability.type}</h3>
            <p className="text-gray-300">{vulnerability.description || vulnerability.title}</p>
          </div>
          <div className="bg-gray-900 rounded-lg p-4">
            <h3 className="text-white font-semibold mb-2">Details</h3>
            <div className="text-sm text-gray-300">
              <div>Severity: {vulnerability.severity}</div>
              <div>Confidence: {vulnerability.confidence || vulnerability.confidence_score || 0}%</div>
              <div>URL: {vulnerability.url || vulnerability.affected_url}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default VulnerabilityDetails;
EOFVULN

echo "✅ React components fixed"

cd ..

# Step 4: Create reliable start script
echo ""
echo "4. Creating reliable start script..."

cat > start_reliable.sh << 'EOFSTART'
#!/bin/bash

echo "🚀 Starting CyberSage v2.0 (Reliable Mode)"
echo ""

# Kill existing
pkill -9 -f "python app.py"
pkill -9 -f "npm start"
sleep 2

# Start backend
echo "Starting backend..."
cd ~/CyberSage-2.0/backend
source venv/bin/activate

# Run backend in foreground with logging
python app.py 2>&1 | tee backend.log &
BACKEND_PID=$!

echo "Backend PID: $BACKEND_PID"
echo "Waiting 8 seconds for backend to initialize..."
sleep 8

# Check if backend is alive
if ! kill -0 $BACKEND_PID 2>/dev/null; then
    echo "❌ Backend failed to start! Check backend.log"
    cat backend.log
    exit 1
fi

# Test backend
if curl -s http://localhost:5000/api/health > /dev/null; then
    echo "✅ Backend is healthy!"
else
    echo "❌ Backend not responding!"
    cat backend.log
    exit 1
fi

# Start frontend in new terminal or same
echo ""
echo "Starting frontend..."
cd ~/CyberSage-2.0/frontend
npm start 2>&1 | tee frontend.log &
FRONTEND_PID=$!

echo "Frontend PID: $FRONTEND_PID"

echo ""
echo "=================================="
echo "✅ Both services started!"
echo "=================================="
echo ""
echo "Backend:  http://localhost:5000"
echo "Frontend: http://localhost:3000"
echo ""
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"
echo ""
echo "Logs:"
echo "  Backend:  ~/CyberSage-2.0/backend/backend.log"
echo "  Frontend: ~/CyberSage-2.0/frontend/frontend.log"
echo ""
echo "To stop:"
echo "  kill $BACKEND_PID $FRONTEND_PID"
echo ""

# Keep script running
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
EOFSTART

chmod +x start_reliable.sh

echo "✅ Complete fix applied!"
echo ""
echo "=================================="
echo "🎯 To start CyberSage:"
echo "=================================="
echo ""
echo "  ./start_reliable.sh"
echo ""
echo "This will start both backend and frontend with detailed logging."
echo ""