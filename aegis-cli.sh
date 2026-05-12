#!/bin/bash

# AEGIS CLI - Unix/Linux Management Script
# Unified tool for start, stop and status

APP_NAME="Aegis EDR Ecosystem"
FRONTEND_DIR="frontend"
DOCKER_COMPOSE="docker-compose.yml"

show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  (no args)  Start all services"
    echo "  --stop     Stop all services"
    echo "  --status   Check services status"
}

stop_services() {
    echo "[INFO] Stopping $APP_NAME..."
    docker-compose -f "$DOCKER_COMPOSE" down
    # Kill frontend if running on port 3000
    FE_PID=$(lsof -t -i:3000)
    if [ ! -z "$FE_PID" ]; then
        echo "[INFO] Killing frontend process (PID: $FE_PID)..."
        kill -9 $FE_PID
    fi
    echo "[SUCCESS] All services stopped."
}

check_status() {
    echo "[INFO] Checking status of $APP_NAME..."
    echo ""
    echo "--- Docker Containers ---"
    docker-compose ps
    echo ""
    echo "--- Frontend Reachability ---"
    if curl -s -I http://localhost:3000 | grep -q "200 OK"; then
        echo "[OK] Frontend is UP (http://localhost:3000)"
    else
        echo "[WARN] Frontend seems to be DOWN."
    fi
}

start_services() {
    echo "[INFO] Starting $APP_NAME..."

    # Check for .env file
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            echo "[WARN] .env file not found. Creating from .env.example..."
            cp .env.example .env
            echo "[IMPORTANT] Please edit .env with your configuration and restart."
            exit 1
        else
            echo "[ERROR] .env.example not found. Cannot continue."
            exit 1
        fi
    fi

    # Check Docker
    if ! docker info > /dev/null 2>&1; then
        echo "[ERROR] Docker is not running. Please start Docker and try again."
        exit 1
    fi

    # Start Backend
    echo "[INFO] Launching backend services (Docker)..."
    docker-compose up -d --build

    # Check Node for Frontend
    if ! command -v npm &> /dev/null; then
        echo "[WARN] npm not found. Skipping frontend auto-start."
    else
        echo "[INFO] Launching frontend dashboard..."
        cd "$FRONTEND_DIR"
        npm start &
        cd ..
    fi

    # Trap Ctrl+C (SIGINT)
    trap stop_services SIGINT

    echo ""
    echo "=================================================="
    echo "   $APP_NAME is being deployed!"
    echo "=================================================="
    echo "   - Dashboard: http://localhost:3000"
    echo "   - Brain API: http://localhost:8000/docs"
    echo "   - Link API:  http://localhost:8080/api/v1/health"
    echo "=================================================="
    echo ""
    echo "[KEEP THIS TERMINAL OPEN]"
    echo "Press Ctrl+C to stop ALL services."
    echo ""
    
    # Wait for background processes
    wait
}

case "$1" in
    --stop)
        stop_services
        ;;
    --status)
        check_status
        ;;
    --help)
        show_help
        ;;
    "")
        start_services
        ;;
    *)
        echo "Unknown option: $1"
        show_help
        exit 1
        ;;
esac
