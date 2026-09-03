@echo off
setlocal enabledelayedexpansion
title NetShield-NIDS System Launcher

cd /d "%~dp0"

echo ============================================================
echo           NETSHIELD-NIDS SOC SYSTEM LAUNCHER
echo ============================================================
echo.
echo [1/3] Starting FastAPI REST Backend (Port 8000)...
start "NetShield Backend API (Port 8000)" cmd /k "cd /d "%~dp0" && uvicorn backend.api:app --host 0.0.0.0 --port 8000"

echo [2/3] Starting React SOC Web Dashboard (Port 5173)...
start "NetShield Frontend Dashboard (Port 5173)" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo Waiting for services to initialize...
powershell -Command "Start-Sleep -Seconds 3" >nul 2>&1 || timeout /t 3 /nobreak >nul

echo [3/3] Opening NetShield SOC Web Dashboard in default browser...
start http://localhost:5173

echo.
echo ============================================================
echo SUCCESS: NetShield-NIDS Complete System is Running!
echo.
echo  • React SOC Dashboard:   http://localhost:5173
echo  • FastAPI REST Service:   http://localhost:8000
echo  • Interactive API Docs:   http://localhost:8000/docs
echo.
echo Keep the Backend & Frontend command windows open while using NetShield.
echo ============================================================
echo.
pause
