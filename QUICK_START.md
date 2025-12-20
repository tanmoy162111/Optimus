# Optimus - Quick Start Guide

## Prerequisites

1. **Windows 10/11** with administrator privileges
2. **Oracle VirtualBox** installed with Kali Linux VM named "Kali"
3. **Python 3.8+** installed
4. **Node.js 16+** and npm installed
5. **Git Bash** or similar terminal

## Installation

### 1. Configure Environment

Copy `.env.example` to `.env` in the backend folder:

```bash
cd backend
cp .env.example .env
```

Edit `.env` and configure:

```
KALI_HOST=192.168.56.101       # Your Kali VM IP
KALI_PORT=22
KALI_USER=kali
KALI_PASSWORD=kali
```

### 2. Install Dependencies

#### Backend:
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

#### Frontend:
```bash
cd frontend
npm install
```

## Running Optimus

### Automated Start (Recommended)

Simply double-click:
```
START_OPTIMUS.bat
```

This will:
1. Start Kali VM (headless mode)
2. Start Backend server (http://localhost:5000)
3. Start Frontend dev server (http://localhost:5173)

### Automated Stop

Double-click:
```
STOP_OPTIMUS.bat
```

### Manual Start

#### Terminal 1 - Backend:
```bash
cd backend
venv\Scripts\activate
python app.py
```

#### Terminal 2 - Frontend:
```bash
cd frontend
npm run dev
```

#### Terminal 3 - Kali VM:
```bash
VBoxManage startvm "Kali" --type headless
```

## Accessing Optimus

- **Frontend UI**: http://localhost:5173
- **Backend API**: http://localhost:5000
- **API Health**: http://localhost:5000/health

## First Scan

1. Open http://localhost:5173
2. Click "New Scan"
3. Enter target URL (e.g., http://testphp.vulnweb.com)
4. Configure scan options
5. Click "Start Scan"

## Troubleshooting

### Backend won't start
- Verify Python is installed: `python --version`
- Check virtual environment is activated
- Ensure all dependencies installed: `pip install -r requirements.txt`

### Frontend won't start
- Verify Node.js: `node --version`
- Delete node_modules and reinstall: `rm -rf node_modules && npm install`

### Kali VM not connecting
- Check VM is running: `VBoxManage list runningvms`
- Verify SSH credentials in `.env`
- Test SSH: `ssh kali@192.168.56.101`

### No findings in scans
- Verify Kali VM network connectivity
- Check backend logs in `logs/backend.log`
- Ensure security tools installed in Kali

## Project Structure

```
Optimus/
├── backend/              # Python Flask API
│   ├── api/             # REST endpoints
│   ├── core/            # Scan engine
│   ├── inference/       # AI agent
│   ├── intelligence/    # Advanced AI modules
│   └── app.py           # Main entry point
├── frontend/            # React + TypeScript UI
│   └── src/
├── START_OPTIMUS.bat    # Automated start
└── STOP_OPTIMUS.bat     # Automated stop
```

## Support

For issues, check:
- Backend logs: `logs/backend.log`
- Frontend console: Browser DevTools
- Kali VM status: VirtualBox Manager

## Next Steps

- Configure Kali VM tools
- Review scan results
- Generate reports
- Train ML models with real data
