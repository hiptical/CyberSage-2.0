#!/bin/bash

echo "=================================="
echo "🧠 CyberSage v2.0 Setup Script"
echo "=================================="
echo ""

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

echo "✅ Python3 found: $(python3 --version)"

# Check if pip3 is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip3."
    exit 1
fi

echo "✅ pip3 found"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 14 or higher."
    exit 1
fi

echo "✅ Node.js found: $(node --version)"

# Backend Setup
echo ""
echo "📦 Setting up backend..."
cd backend

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment and install dependencies
echo "Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip

# Install main requirements (not dev requirements to avoid line_profiler issue)
echo "Installing production dependencies..."
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file..."
    cat > .env << EOF
SECRET_KEY=cybersage_v2_secret_$(date +%s)
# OPENROUTER_API_KEY=your_api_key_here
EOF
    echo "✅ .env file created"
else
    echo "✅ .env file already exists"
fi

deactivate
cd ..

# Frontend Setup
echo ""
echo "📦 Setting up frontend..."
cd frontend

# Install Node dependencies
echo "Installing Node.js dependencies..."
npm install

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating frontend .env file..."
    cat > .env << EOF
REACT_APP_BACKEND_URL=http://localhost:5000
EOF
    echo "✅ Frontend .env file created"
else
    echo "✅ Frontend .env file already exists"
fi

cd ..

# Create start scripts if they don't exist
echo ""
echo "📝 Creating start scripts..."

# Backend start script
if [ ! -f "start_backend.sh" ]; then
    cat > start_backend.sh << 'EOF'
#!/bin/bash
cd backend
source venv/bin/activate
python app.py
EOF
    chmod +x start_backend.sh
    echo "✅ Created start_backend.sh"
fi

# Frontend start script
if [ ! -f "start_frontend.sh" ]; then
    cat > start_frontend.sh << 'EOF'
#!/bin/bash
cd frontend
npm start
EOF
    chmod +x start_frontend.sh
    echo "✅ Created start_frontend.sh"
fi

# Combined start script
if [ ! -f "start.sh" ]; then
    cat > start.sh << 'EOF'
#!/bin/bash

echo "🚀 Starting CyberSage v2.0..."
echo ""

# Check if virtual environment exists
if [ ! -d "backend/venv" ]; then
    echo "❌ Virtual environment not found. Please run ./setup.sh first"
    exit 1
fi

# Start backend in background
echo "Starting backend..."
cd backend
source venv/bin/activate

# Check if Flask is installed
python -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Flask not installed. Installing dependencies..."
    pip install -r requirements.txt
fi

python app.py &
BACKEND_PID=$!
cd ..

# Wait for backend to start
echo "Waiting for backend to initialize..."
sleep 5

# Start frontend
echo "Starting frontend..."
cd frontend

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "❌ Node modules not found. Installing..."
    npm install
fi

npm start &
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
echo "Press Ctrl+C to stop both servers"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Stopping servers..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    exit 0
}

# Trap Ctrl+C
trap cleanup INT

# Wait for interrupt
wait
EOF
    chmod +x start.sh
    echo "✅ Created start.sh"
fi

echo ""
echo "=================================="
echo "✅ Setup Complete!"
echo "=================================="
echo ""
echo "To start CyberSage v2.0, run:"
echo "  ./start.sh"
echo ""
echo "Or start components separately:"
echo "  Backend:  ./start_backend.sh"
echo "  Frontend: ./start_frontend.sh"
echo ""
echo "🎯 Ready to scan!"
echo "=================================="