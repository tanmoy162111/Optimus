@echo off
:: Optimus Start Script for Windows
:: Starts both backend and frontend servers

setlocal enabledelayedexpansion

echo 🚀 Starting Optimus Platform...

:: Set project paths
set PROJECT_ROOT=%~dp0
set BACKEND_DIR=%PROJECT_ROOT%backend
set FRONTEND_DIR=%PROJECT_ROOT%frontend
set LOGS_DIR=%PROJECT_ROOT%logs

:: Create logs directory
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"

:: Change to backend directory and start server
echo 🔧 Starting Backend Server...
cd /d "%BACKEND_DIR%"
start "Optimus Backend" cmd /k "python app.py"

:: Wait a moment for backend to start
timeout /t 5 /nobreak >nul

:: Change to frontend directory and start server
echo 🎨 Starting Frontend Server...
cd /d "%FRONTEND_DIR%"
start "Optimus Frontend" cmd /k "npm run dev"

echo ✅ Optimus Platform Started!
echo 🌐 Frontend: http://localhost:5173
echo 🔧 Backend API: http://localhost:5000
echo 📝 Logs: %LOGS_DIR%

pause