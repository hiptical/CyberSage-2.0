#!/bin/bash

echo "============================================"
echo "🧠 CyberSage v2.0 - Starting Application"
echo "============================================"
echo ""

# Check if backend virtual environment exists
if [ ! -d "backend/venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "   Please run: ./setup.sh first"
    exit 1
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "============================================"
    echo "🛑 Stopping CyberSage v2.0..."
    echo "============================================"
    if [ ! -z "$BACKEND_PID" ]; then
        echo "Stopping backend (PID: $BACKEND_PID)..."
        kill $BACKEND_PID 2>/dev/null
    fi
    if [ ! -z "$FRONTEND_PID" ]; then
        echo "Stopping frontend (PID: $FRONTEND_PID)..."
        kill $FRONTEND_PID 2>/dev/null
    fi
    echo "✅ Shutdown complete"
    exit 0
}

# Trap Ctrl+C
trap cleanup INT TERM

# Start Backend
echo "🔧 Starting Backend..."
cd backend

# Activate virtual environment
source venv/bin/activate

# Check if Flask is installed
python -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Flask not installed. Installing dependencies..."
    pip install -r requirements.txt
fi

# Start backend in background
python app.py > ../backend.log 2>&1 &
BACKEND_PID=$!
cd ..

echo "✅ Backend started (PID: $BACKEND_PID)"
echo "   Logs: backend.log"
echo "   URL:  http://localhost:5000"

# Wait for backend to be ready
echo ""
echo "⏳ Waiting for backend to initialize..."
sleep 3

# Check if backend is responding
for i in {1..10}; do
    if curl -s http://localhost:5000/api/health > /dev/null 2>&1; then
        echo "✅ Backend is ready!"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "❌ Backend failed to start. Check backend.log for errors."
        cleanup
        exit 1
    fi
    sleep 1
done

# Start Frontend
echo ""
echo "🎨 Starting Frontend..."
cd frontend

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "⚠️  Node modules not found. Installing..."
    npm install
fi

# Start frontend in background
npm start > ../frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

echo "✅ Frontend started (PID: $FRONTEND_PID)"
echo "   Logs: frontend.log"
echo "   URL:  http://localhost:3000"

echo ""
echo "============================================"
echo "✅ CyberSage v2.0 is now running!"
echo "============================================"
echo ""
echo "📊 Backend:  http://localhost:5000"
echo "🌐 Frontend: http://localhost:3000"
echo ""
echo "📝 Logs:"
echo "   Backend:  tail -f backend.log"
echo "   Frontend: tail -f frontend.log"
echo ""
echo "Press Ctrl+C to stop all services"
echo "============================================"
echo ""

# Wait for processes
wait