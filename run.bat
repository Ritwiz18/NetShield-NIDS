@echo off
cd /d "%~dp0"

echo Starting NIDS Web Application...
echo.

streamlit run app\app.py

pause
