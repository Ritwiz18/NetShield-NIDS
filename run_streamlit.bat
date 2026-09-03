@echo off
title NetShield-NIDS Legacy Streamlit App

cd /d "%~dp0"

echo ============================================================
echo      NETSHIELD-NIDS LEGACY STREAMLIT WEB APP
echo ============================================================
echo.
echo Launching Streamlit interface (app/app.py)...
echo.

streamlit run app\app.py

pause
