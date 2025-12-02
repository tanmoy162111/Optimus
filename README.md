# Optimus - AI-Driven Autonomous Penetration Testing Platform

## Overview
Optimus is an advanced AI-driven autonomous penetration testing platform that combines machine learning, automated tool execution, and intelligent decision-making to perform comprehensive security assessments.

## Project Structure
```
optimus/
├── backend/                    # Python Flask backend
│   ├── api/                    # API endpoints
│   ├── websocket/              # WebSocket handlers
│   ├── tools/                  # Hybrid Tool System
│   ├── intelligence/           # AI/ML modules
│   ├── data/                   # Runtime data
│   └── app.py                 # Main Flask application
│
├── frontend/                   # React frontend
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── stores/
│   └── public/
│
├── scripts/                    # Start/stop scripts
├── logs/                       # Application logs
└── docs/                       # Documentation
```

## Getting Started

### Prerequisites
- Python 3.13
- Node.js 16+
- npm 8+

### Installation

1. Install backend dependencies:
```bash
cd backend
pip install -r requirements.txt
```

2. Install frontend dependencies:
```bash
cd frontend
npm install
```

### Running the Application

#### Using Scripts
```bash
# Start the application
./scripts/start.sh  # On Unix/Linux/Mac
start.bat          # On Windows

# Stop the application
./scripts/stop.sh   # On Unix/Linux/Mac
stop.bat           # On Windows

# Check health
./scripts/health_check.sh  # On Unix/Linux/Mac
```

#### Manual Start
1. Start the backend:
```bash
cd backend
python app.py
```

2. Start the frontend:
```bash
cd frontend
npm run dev
```

## Accessing the Application
- Frontend: http://localhost:5173
- Backend API: http://localhost:5000
- Health Check: http://localhost:5000/health

## Features
- AI-driven autonomous scanning
- Real-time dashboard with scan progress
- Comprehensive tool management
- Intelligent tool recommendation
- WebSocket-based real-time updates
- Detailed reporting and findings visualization

## Documentation
- [Frontend-Backend Integration Guide](docs/FRONTEND_INTEGRATION_GUIDE.md)
- [Hybrid Tool System Documentation](docs/HYBRID_TOOL_SYSTEM.md)
- [API Documentation](docs/API.md)
- [User Guide](docs/USER_GUIDE.md)

## License
This project is licensed under the MIT License - see the LICENSE file for details.