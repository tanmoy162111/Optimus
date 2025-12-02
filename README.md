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
- VirtualBox with Kali Linux VM (named "kali")

### Installation

1. Install backend dependencies:
```bash
cd backend
"C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python313\python.exe" -m pip install -r requirements.txt
```

2. Install frontend dependencies:
```bash
cd frontend
npm install
```

### Running the Application

#### Using Scripts
```bash
# Start the application (Windows)
start.bat

# Start the application (Cross-platform)
python start_optimus.py

# Stop the application (Windows)
stop.bat

# Stop the application (Cross-platform)
python stop_optimus.py
```

#### Manual Start
1. Start the backend:
```bash
cd backend
"C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python313\python.exe" app.py
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
- Kali VM SSH: 127.0.0.1:2222 (when running)

## Features
- AI-driven autonomous scanning
- Real-time dashboard with scan progress
- Comprehensive tool management
- Intelligent tool recommendation
- WebSocket-based real-time updates
- Detailed reporting and findings visualization
- Kali Linux VM integration for tool execution

## Documentation
- [Frontend-Backend Integration Guide](docs/FRONTEND_INTEGRATION_GUIDE.md)
- [Hybrid Tool System Documentation](docs/HYBRID_TOOL_SYSTEM.md)
- [API Documentation](docs/API.md)
- [User Guide](docs/USER_GUIDE.md)
- [Troubleshooting Guide](TROUBLESHOOTING_SUMMARY.md)

## License
This project is licensed under the MIT License - see the LICENSE file for details.