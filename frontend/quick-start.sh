#!/usr/bin/env bash

# AEGIS EDR Dashboard - Quick Start Script
# This script automates the installation and startup process

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║       AEGIS EDR Dashboard - Quick Start Installer              ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Check Node.js
echo "📦 Checking Node.js installation..."
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 14+ from https://nodejs.org"
    exit 1
fi
NODE_VERSION=$(node --version)
echo "✅ Node.js $NODE_VERSION found"

# Check npm
echo "📦 Checking npm installation..."
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed"
    exit 1
fi
NPM_VERSION=$(npm --version)
echo "✅ npm $NPM_VERSION found"

# Navigate to frontend directory
echo ""
echo "📂 Setting up frontend directory..."
cd "$(dirname "$0")" || exit 1
echo "✅ Current directory: $(pwd)"

# Check if node_modules exists
if [ -d "node_modules" ]; then
    echo "⚠️  node_modules directory already exists"
    read -p "Reinstall dependencies? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🗑️  Removing old dependencies..."
        rm -rf node_modules
        rm -f package-lock.json
    fi
else
    echo "📥 Installing dependencies..."
    npm install
    echo "✅ Dependencies installed"
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo ""
    echo "⚙️  Creating .env file..."
    cp .env.example .env
    echo "✅ .env file created with default values"
    echo "   Backend URL: http://localhost:8000/api/v1"
    echo "   Edit .env if your backend runs on a different address"
else
    echo ""
    echo "✅ .env file already exists"
fi

# Check backend connectivity
echo ""
echo "🔗 Checking backend connectivity..."
if command -v curl &> /dev/null; then
    if curl -s http://localhost:8000/api/v1/stats > /dev/null 2>&1; then
        echo "✅ Backend is running and accessible"
    else
        echo "⚠️  Could not connect to backend at http://localhost:8000"
        echo "   Make sure aegis-brain is running on port 8000"
        echo "   You can start it with: cd ../aegis-brain && python main.py"
    fi
else
    echo "⚠️  curl not found, skipping backend check"
fi

# Final instructions
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    Ready to Start! 🚀                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "📌 Next Steps:"
echo "   1. Ensure aegis-brain backend is running (http://localhost:8000)"
echo "   2. Run: npm start"
echo "   3. Dashboard will open at http://localhost:3000"
echo ""
echo "📚 Documentation:"
echo "   - README.md - Installation and feature guide"
echo "   - DEVELOPMENT.md - Architecture and development guide"
echo "   - INSTALLATION_CHECKLIST.md - Detailed verification steps"
echo ""
echo "💡 Quick Commands:"
echo "   npm start         - Start development server"
echo "   npm run build     - Build for production"
echo "   npm test          - Run tests (when available)"
echo ""
echo "🤔 Need help?"
echo "   Check DEVELOPMENT.md for troubleshooting"
echo ""

# Ask if user wants to start now
read -p "Start development server now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🌐 Starting development server..."
    npm start
fi
