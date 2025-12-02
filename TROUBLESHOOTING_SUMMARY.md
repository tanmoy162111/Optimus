# 🛠️ Optimus Platform Troubleshooting Summary

## Issues Identified and Resolved

### 1. Python and Vite Not Recognized
**Problem**: Commands `python` and `vite` were not recognized as internal or external commands.
**Solution**: 
- Identified Python 3.13.9 installed at `C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python313\python.exe`
- Confirmed Node.js v24.11.1 and npm v11.6.2 were available
- Updated startup scripts to use full paths to executables

### 2. Missing Dependencies
**Problem**: Required packages not installed or outdated.
**Solution**:
- Installed all backend dependencies using pip with full Python path
- Installed frontend dependencies using npm
- Added psutil dependency for process management in Python scripts

### 3. Kali VM Integration
**Problem**: Kali VM was not being managed with the start/stop scripts.
**Solution**:
- Updated start.bat to check for VirtualBox and start Kali VM
- Updated stop.bat to properly shutdown Kali VM
- Created Python-based startup/shutdown scripts with Kali VM management

## Changes Made

### Backend Dependencies
Installed all required Python packages:
- Core packages: flask, flask-socketio, flask-cors, python-socketio
- Data science: numpy, pandas, scikit-learn, tensorflow
- Utilities: requests, pyyaml, python-dotenv, paramiko
- Reporting: reportlab, weasyprint, python-docx
- NLP: sentence-transformers, langchain
- Others: aiohttp, matplotlib, seaborn, PyPDF2

### Frontend Dependencies
Installed all required npm packages for the React frontend with Vite.

### Startup Scripts

#### Windows Batch Scripts
- **start.bat**: Enhanced to include Kali VM startup and proper Python path detection
- **stop.bat**: Enhanced to include Kali VM shutdown

#### Python Scripts
- **start_optimus.py**: Cross-platform Python startup script with proper error handling
- **stop_optimus.py**: Cross-platform Python shutdown script with process management

## How to Use

### Starting the Platform
```bash
# Using batch script (Windows)
start.bat

# Using Python script (Cross-platform)
python start_optimus.py

# Skip specific components
python start_optimus.py --skip-vm
python start_optimus.py --skip-backend --skip-frontend
```

### Stopping the Platform
```bash
# Using batch script (Windows)
stop.bat

# Using Python script (Cross-platform)
python stop_optimus.py

# Force kill processes on standard ports
python stop_optimus.py --force-ports
```

## Verification Commands

### Check Python
```bash
# Check Python version
"C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python313\python.exe" --version
```

### Check Node.js and npm
```bash
node --version
npm --version
```

### Check Vite
```bash
npx vite --version
```

### Check VirtualBox
```bash
"D:\Virtualbox\VBoxManage.exe" --version
```

## Access Points
- **Backend API**: http://localhost:5000
- **Frontend UI**: http://localhost:5173
- **Kali VM SSH**: 127.0.0.1:2222 (when running)

## Troubleshooting Tips

1. **If Python is not found**: Use the full path to Python executable
2. **If VirtualBox is not found**: Update the VBOX_PATH in the scripts
3. **If Kali VM doesn't start**: Ensure the VM is named "kali" in VirtualBox
4. **If ports are in use**: Use the force-ports option in stop script
5. **If frontend fails**: Ensure all npm dependencies are installed

## Next Steps

1. Run `start.bat` or `python start_optimus.py` to start the platform
2. Access the frontend at http://localhost:5173
3. Verify backend is running at http://localhost:5000/health
4. Check that Kali VM is accessible via SSH at 127.0.0.1:2222