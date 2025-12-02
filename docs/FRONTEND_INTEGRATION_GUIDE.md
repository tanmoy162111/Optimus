# 🎯 Optimus Frontend-Backend Integration Guide

## Overview
This guide provides complete instructions for integrating the Optimus React frontend with the Python/Flask backend. Follow these steps to ensure seamless communication between all components.

## Project Structure
```
optimus/
├── backend/                    # Python Flask backend
│   ├── app.py                  # Main Flask application
│   ├── api/                    # REST API endpoints
│   │   ├── __init__.py
│   │   ├── routes.py           # Main API endpoints
│   │   ├── scan_routes.py      # Scan-specific endpoints
│   │   └── tool_routes.py      # Tool-specific endpoints
│   ├── websocket/              # WebSocket handlers
│   │   ├── __init__.py
│   │   └── handlers.py         # WebSocket event handlers
│   └── tools/                  # Hybrid Tool System
├── frontend/                   # React frontend
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── stores/
│   │   └── config/
│   └── vite.config.ts          # Vite configuration
├── scripts/                    # Start/stop scripts
└── logs/                       # Application logs
```

## Backend Setup

### Main Flask Application (`backend/app.py`)
The main application file configures Flask with proper CORS settings, SocketIO, and registers all API routes.

Key features:
- CORS configuration for frontend origins (localhost:5173, localhost:3000)
- SocketIO with proper CORS settings for WebSocket communication
- Route registration for API, scan, and tool endpoints
- WebSocket handler registration
- Proper logging configuration

### API Routes
Three main API route files handle different aspects of the application:

1. `api/routes.py` - Main API endpoints including dashboard statistics
2. `api/scan_routes.py` - Scan management endpoints
3. `api/tool_routes.py` - Tool management endpoints

### WebSocket Handlers (`websocket/handlers.py`)
Handles real-time communication between frontend and backend:
- Client connection/disconnection management
- Room-based communication for scan updates
- Event emission for various system activities
- Tool execution and finding notifications

## Frontend Configuration

### Environment Variables (`.env`)
```
VITE_API_URL=http://localhost:5000
VITE_WS_URL=http://localhost:5000
VITE_APP_VERSION=1.0.0
```

### Vite Configuration (`vite.config.ts`)
Proxy configuration for API and WebSocket communication:
```typescript
server: {
  port: 5173,
  proxy: {
    '/api': {
      target: 'http://localhost:5000',
      changeOrigin: true,
    },
    '/socket.io': {
      target: 'http://localhost:5000',
      changeOrigin: true,
      ws: true,
    },
  },
}
```

## Start/Stop Scripts

### Unix Scripts
- `scripts/start.sh` - Starts both backend and frontend servers
- `scripts/stop.sh` - Stops both servers and cleans up processes
- `scripts/health_check.sh` - Verifies system health

### Windows Scripts
- `start.bat` - Starts both backend and frontend servers
- `stop.bat` - Stops both servers and cleans up processes

## Common Issues and Solutions

### Input Redirection Error
**Problem**: `bash: cannot set terminal process group: Inappropriate ioctl for device`
**Solution**: Use `nohup` with proper output redirection

### Path Not Found
**Problem**: Module imports fail with `ModuleNotFoundError`
**Solution**: Set `PYTHONPATH` before running

### Port Already in Use
**Problem**: `Address already in use`
**Solution**: Kill existing process with `lsof` or `taskkill`

### WebSocket Connection Failed
**Problem**: Frontend can't connect to WebSocket
**Solution**: Ensure CORS origins include frontend URL

## Testing the Integration

### Backend Health Check
```bash
curl http://localhost:5000/health
```

### API Test
```bash
curl http://localhost:5000/api/dashboard/stats
```

### WebSocket Test
In browser console:
```javascript
const socket = io('http://localhost:5000');
socket.on('connect', () => console.log('Connected!'));
```

## Integration Checklist
- [x] Backend configured with CORS and SocketIO
- [x] All API routes registered
- [x] WebSocket handlers registered
- [x] Frontend environment configured
- [x] Vite proxy configured
- [x] Start/stop scripts working
- [x] Health check passing

## Quick Start Commands
```bash
# Start everything
./scripts/start.sh

# Check status
./scripts/health_check.sh

# Stop everything
./scripts/stop.sh

# View logs
tail -f logs/backend.log
tail -f logs/frontend.log
```