#!/bin/bash

echo "🚀 Starting CyberSage v2.0..."
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping servers..."
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null
        echo "Backend stopped"
    fi
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null
        echo "Frontend stopped"
    fi
    exit 0
}

# Trap Ctrl+C and errors
trap cleanup INT TERM EXIT

# Kill any existing processes
echo "Cleaning up old processes..."
pkill -f "python app.py" 2>/dev/null
pkill -f "npm start" 2>/dev/null
sleep 2

# Check if virtual environment exists
if [ ! -d "backend/venv" ]; then
    echo "❌ Virtual environment not found. Please run ./setup.sh first"
    exit 1
fi

# Start Backend
echo "📡 Starting backend..."
cd backend
source venv/bin/activate

# Check if Flask is installed
python -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Flask not installed. Installing dependencies..."
    pip install -r requirements.txt
fi

# Run backend in background but keep output visible
python app.py 2>&1 | tee backend.log &
BACKEND_PID=$!
cd ..

echo "⏳ Waiting for backend to start..."
sleep 8

# Check if backend is actually running
if ! kill -0 $BACKEND_PID 2>/dev/null; then
    echo "❌ Backend failed to start!"
    echo "Check backend.log for errors"
    exit 1
fi

# Test backend health
if curl -s http://localhost:5000/api/health > /dev/null 2>&1; then
    echo "✅ Backend is running on http://localhost:5000"
else
    echo "❌ Backend not responding to health check"
    echo "Backend PID: $BACKEND_PID"
    echo "Check if port 5000 is already in use: sudo lsof -i :5000"
    exit 1
fi

# Start Frontend
echo "🎨 Starting frontend..."
cd frontend

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "❌ Node modules not found. Installing..."
    npm install
fi

npm start 2>&1 | tee frontend.log &
FRONTEND_PID=$!
cd ..

echo ""
echo "=================================="
echo "✅ CyberSage v2.0 is running!"
echo "=================================="
echo ""
echo "Backend:  http://localhost:5000"
echo "Frontend: http://localhost:3000"
echo ""
echo "Backend PID:  $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"
echo ""
echo "Logs:"
echo "  Backend:  backend/backend.log"
echo "  Frontend: frontend/frontend.log"
echo ""
echo "Press Ctrl+C to stop both servers"
echo ""

# Wait for processes
wait