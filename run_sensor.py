"""
==================================================
NetShield-NIDS — Native Sensor Execution Script
==================================================
run_sensor.py

Launches the native Windows Scapy packet capture NIDS sensor
and streams live flow detections & metrics to the FastAPI backend.

Usage:
    python run_sensor.py
"""

import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from live.sensor_client import main

if __name__ == "__main__":
    main()
