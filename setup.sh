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
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file..."
    cat > .env << EOF
SECRET_KEY=cybersage_v2_secret_$(date +%s)
OPENROUTER_API_KEY=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
EOF
    echo "✅ .env file created"
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

# Create postcss.config.js if it doesn't exist
if [ ! -f "postcss.config.js" ]; then
    cat > postcss.config.js << EOF
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
EOF
    echo "✅ PostCSS config created"
fi

cd ..

# Create start scripts
echo ""
echo "📝 Creating start scripts..."

# Backend start script
cat > start_backend.sh << 'EOF'
#!/bin/bash
cd backend
source venv/bin/activate
python app.py
EOF
chmod +x start_backend.sh

# Frontend start script
cat > start_frontend.sh << 'EOF'
#!/bin/bash
cd frontend
npm start
EOF
chmod +x start_frontend.sh

# Combined start script
cat > start.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting CyberSage v2.0..."
echo ""

# Start backend in background
echo "Starting backend..."
cd backend
source venv/bin/activate
python app.py &
BACKEND_PID=$!
cd ..

# Wait for backend to start
sleep 3

# Start frontend
echo "Starting frontend..."
cd frontend
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

# Wait for interrupt
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait
EOF
chmod +x start.sh

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
echo "🎯 Competition Ready! Good luck on October 30!"
echo "=================================="

# Frontend Setup
echo ""
echo "📦 Setting up frontend..."
cd frontend

# Install Node dependencies
echo "Installing Node.js dependencies..."
npm install

# Create postcss.config.js if it doesn't exist
if [ ! -f "postcss.config.js" ]; then
    cat > postcss.config.js << EOF
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
EOF
    echo "✅ PostCSS config created"
fi

cd ..

# Create start scripts
echo ""
echo "📝 Creating start scripts..."

# Backend start script
cat > start_backend.sh << 'EOF'
#!/bin/bash
cd backend
source venv/bin/activate
python app.py
EOF
chmod +x start_backend.sh

# Frontend start script
cat > start_frontend.sh << 'EOF'
#!/bin/bash
cd frontend
npm start
EOF
chmod +x start_frontend.sh

# Combined start script
cat > start.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting CyberSage v2.0..."
echo ""

# Start backend in background
echo "Starting backend..."
cd backend
source venv/bin/activate
python app.py &
BACKEND_PID=$!
cd ..

# Wait for backend to start
sleep 3

# Start frontend
echo "Starting frontend..."
cd frontend
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

# Wait for interrupt
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait
EOF
chmod +x start.sh

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
echo 