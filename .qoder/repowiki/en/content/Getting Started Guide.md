# Getting Started Guide

<cite>
**Referenced Files in This Document**
- [README.md](file://README.md)
- [QUICK_START.md](file://QUICK_START.md)
- [START_GUIDE.txt](file://START_GUIDE.txt)
- [frontend/README.md](file://frontend/README.md)
- [backend/requirements.txt](file://backend/requirements.txt)
- [frontend/package.json](file://frontend/package.json)
- [scripts/start.sh](file://scripts/start.sh)
- [scripts/health_check.sh](file://scripts/health_check.sh)
- [.env.example](file://.env.example)
- [frontend/.env.example](file://frontend/.env.example)
- [backend/config.py](file://backend/config.py)
- [backend/app.py](file://backend/app.py)
- [START_OPTIMUS.bat](file://START_OPTIMUS.bat)
- [STOP_OPTIMUS.bat](file://STOP_OPTIMUS.bat)
- [VERIFY_SYSTEM.bat](file://VERIFY_SYSTEM.bat)
- [install_missing_tools.sh](file://install_missing_tools.sh)
</cite>

## Table of Contents
1. [Introduction](#introduction)
2. [Prerequisites and System Requirements](#prerequisites-and-system-requirements)
3. [Installation Overview](#installation-overview)
4. [Backend Setup](#backend-setup)
5. [Frontend Setup](#frontend-setup)
6. [Environment Configuration](#environment-configuration)
7. [Kali Linux VM Setup](#kali-linux-vm-setup)
8. [Ollama Integration](#ollama-integration)
9. [Initial System Verification](#initial-system-verification)
10. [Running Optimus](#running-optimus)
11. [First Scan Workflow](#first-scan-workflow)
12. [Troubleshooting Guide](#troubleshooting-guide)
13. [Network and Hardware Considerations](#network-and-hardware-considerations)
14. [Conclusion](#conclusion)

## Introduction
This guide helps you quickly set up and begin using the Optimus platform. Optimus is an AI-powered security testing platform featuring autonomous scanning, intelligent vulnerability detection, and automated exploitation. It consists of:
- A Python Flask backend with WebSocket support
- A React-based frontend with real-time monitoring
- Optional integration with a Kali Linux VM for tool execution
- Local LLM integration via Ollama

By the end of this guide, you will have installed both backend and frontend components, configured environment variables, prepared your Kali Linux VM, integrated Ollama, verified the system, and run your first scan.

## Prerequisites and System Requirements
Before installing Optimus, ensure your system meets the following minimum requirements:
- Operating system: Windows 10/11 (for the included Windows batch scripts) or Linux/macOS (for shell scripts)
- Python: 3.10 or newer
- Node.js: 16 or newer
- Git: Required for cloning the repository
- Optional: Oracle VirtualBox with a configured Kali Linux VM for tool execution
- Optional: Ollama for local LLM integration

These requirements are confirmed by the project’s documentation and configuration files.

**Section sources**
- [README.md](file://README.md#L23-L30)
- [frontend/README.md](file://frontend/README.md#L15-L26)
- [backend/requirements.txt](file://backend/requirements.txt#L1-L49)

## Installation Overview
Optimus provides multiple installation paths:
- Automated Windows scripts for quick start
- Manual installation steps for backend and frontend
- Shell scripts for Linux/macOS environments

The recommended approach is to use the automated scripts for a streamlined setup.

**Section sources**
- [QUICK_START.md](file://QUICK_START.md#L11-L87)
- [START_GUIDE.txt](file://START_GUIDE.txt#L1-L209)
- [scripts/start.sh](file://scripts/start.sh#L1-L53)

## Backend Setup
Follow these steps to set up the backend:
1. Navigate to the backend directory.
2. Create a Python virtual environment.
3. Activate the virtual environment.
4. Install the required dependencies.

The backend uses Flask and Flask-SocketIO, with numerous machine learning and security-related packages.

Verification steps:
- Confirm the virtual environment is active.
- Ensure all dependencies from the requirements file are installed.

**Section sources**
- [README.md](file://README.md#L39-L45)
- [QUICK_START.md](file://QUICK_START.md#L31-L45)
- [backend/requirements.txt](file://backend/requirements.txt#L1-L49)

## Frontend Setup
Set up the frontend as follows:
1. Navigate to the frontend directory.
2. Install dependencies using npm.
3. Configure environment variables for the backend URL.

The frontend is a React application built with Vite, TypeScript, and Tailwind CSS. It communicates with the backend via REST and WebSocket connections.

**Section sources**
- [README.md](file://README.md#L47-L51)
- [frontend/README.md](file://frontend/README.md#L73-L100)
- [frontend/package.json](file://frontend/package.json#L1-L50)

## Environment Configuration
Configure environment variables for both backend and frontend:
- Backend: Copy the example environment file and edit it to match your setup.
- Frontend: Copy the example environment file and set the API and WebSocket URLs.

Key backend configuration points include:
- Kali VM SSH settings
- Ollama base URL, model, and timeout
- Training and intelligence module toggles

Key frontend configuration points include:
- API URL pointing to the backend
- WebSocket URL for real-time updates

**Section sources**
- [README.md](file://README.md#L53-L58)
- [.env.example](file://.env.example#L1-L77)
- [backend/config.py](file://backend/config.py#L1-L115)
- [frontend/.env.example](file://frontend/.env.example#L1-L11)

## Kali Linux VM Setup
Optimus integrates with a Kali Linux VM for executing security tools. The VM requires:
- SSH access configured and reachable from your host
- VirtualBox installed and managing the VM
- Correct credentials and host configuration in the backend environment

Configuration steps:
1. Ensure VirtualBox is installed and the Kali VM is created.
2. Configure SSH access on the VM.
3. Set the Kali VM credentials in the backend environment file.
4. Verify connectivity using the provided verification script.

Verification:
- Use the system verification script to check VirtualBox presence, VM existence, and SSH reachability.
- Confirm that the backend can connect to the VM using the configured credentials.

**Section sources**
- [README.md](file://README.md#L28-L28)
- [QUICK_START.md](file://QUICK_START.md#L13-L30)
- [VERIFY_SYSTEM.bat](file://VERIFY_SYSTEM.bat#L51-L68)
- [backend/config.py](file://backend/config.py#L30-L35)

## Ollama Integration
Optimus supports local LLM integration via Ollama. To enable and configure:
1. Install Ollama locally.
2. Pull a suitable model (e.g., codellama:7b-instruct).
3. Configure the backend environment to point to the Ollama base URL and model.
4. Enable Ollama in the backend configuration.

Validation:
- Confirm the backend health endpoint indicates the intelligence component is operational.
- Ensure the frontend can connect to the backend WebSocket for real-time updates.

**Section sources**
- [README.md](file://README.md#L27-L27)
- [.env.example](file://.env.example#L48-L52)
- [backend/config.py](file://backend/config.py#L48-L52)
- [backend/app.py](file://backend/app.py#L276-L290)

## Initial System Verification
Perform a system-wide verification to ensure all components are ready:
- Check Python and Node.js versions.
- Verify VirtualBox and Kali VM status.
- Confirm backend and frontend dependencies are installed.
- Validate port availability for the backend (default 5000) and frontend (default 5173).
- Run the system verification script to detect any critical issues.

The verification script also checks for existing virtual environments and node_modules directories.

**Section sources**
- [VERIFY_SYSTEM.bat](file://VERIFY_SYSTEM.bat#L16-L123)
- [scripts/health_check.sh](file://scripts/health_check.sh#L1-L63)

## Running Optimus
Choose one of the following approaches to start Optimus:

Automated Windows scripts (recommended):
- Double-click the start script to launch the Kali VM, backend, and frontend automatically.
- The stop script halts all services cleanly.

Manual start (for advanced users):
- Start the backend server in the backend directory.
- Start the frontend development server in the frontend directory.
- Ensure the Kali VM is running and accessible.

Ports and URLs:
- Backend API: http://localhost:5000
- Frontend UI: http://localhost:5173
- Backend WebSocket: ws://localhost:5000

**Section sources**
- [QUICK_START.md](file://QUICK_START.md#L49-L87)
- [START_OPTIMUS.bat](file://START_OPTIMUS.bat#L1-L91)
- [START_GUIDE.txt](file://START_GUIDE.txt#L64-L76)

## First Scan Workflow
After starting Optimus:
1. Open the frontend at http://localhost:5173.
2. Click “New Scan” and enter a target URL (e.g., a test site).
3. Configure scan options as needed.
4. Start the scan and monitor progress in real-time via the dashboard.

The backend exposes health and status endpoints, and the frontend connects via WebSocket for live updates.

**Section sources**
- [QUICK_START.md](file://QUICK_START.md#L94-L101)
- [backend/app.py](file://backend/app.py#L276-L308)
- [frontend/README.md](file://frontend/README.md#L135-L153)

## Troubleshooting Guide
Common issues and resolutions:
- Backend fails to start:
  - Verify Python installation and virtual environment activation.
  - Ensure all backend dependencies are installed.
- Frontend fails to start:
  - Verify Node.js and npm installation.
  - Reinstall node_modules if necessary.
- Kali VM connectivity issues:
  - Confirm the VM is running and SSH credentials are correct.
  - Test SSH access manually.
- No findings in scans:
  - Verify Kali VM network connectivity.
  - Check backend logs and ensure security tools are installed on the VM.
- Port conflicts:
  - Change backend or frontend ports in the start scripts or configuration.
- Missing tools on Kali:
  - Use the provided script to install missing tools.

Additional diagnostics:
- Use the health check script to verify backend and frontend responsiveness.
- Review logs in the designated log directories.

**Section sources**
- [QUICK_START.md](file://QUICK_START.md#L102-L122)
- [scripts/health_check.sh](file://scripts/health_check.sh#L1-L63)
- [install_missing_tools.sh](file://install_missing_tools.sh#L1-L92)

## Network and Hardware Considerations
Network prerequisites:
- The backend listens on port 5000 by default; ensure it is not blocked by firewalls.
- The frontend runs on port 5173; ensure it is accessible.
- WebSocket connections require bidirectional access to the backend URL.

Hardware considerations:
- The first startup may take longer due to VM boot time, npm install, and backend initialization.
- Subsequent startups are faster as dependencies are cached.

Port assignments:
- Kali VM SSH: 2222 (forwarded to 127.0.0.1)
- Backend API: 5000
- Backend WebSocket: 5000
- Frontend development: 5173

**Section sources**
- [START_GUIDE.txt](file://START_GUIDE.txt#L139-L149)
- [scripts/start.sh](file://scripts/start.sh#L16-L47)

## Conclusion
You now have the foundational knowledge to install, configure, and run the Optimus platform. Use the automated scripts for a quick start, verify your environment with the provided scripts, and refer to the troubleshooting section for resolving common issues. Once everything is running, proceed with your first scan and explore the intelligent features of the platform.