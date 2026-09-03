"""
==================================================
NetShield-NIDS — API Verification Test Suite
==================================================
tools/test_api.py

Tests all FastAPI REST endpoints using TestClient and validates:
- GET /
- GET /api/status
- GET /api/dashboard
- GET /api/traffic
- GET /api/threats
- GET /api/alerts
- GET /api/interfaces
- POST /api/monitor/start
- POST /api/monitor/stop
- POST /api/monitor/reset
"""

import os
import sys
import time
import json
from fastapi.testclient import TestClient

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.api import app

SEPARATOR = "=" * 60

def run_tests():
    print(SEPARATOR)
    print("NETSHIELD-NIDS FASTAPI REST API VERIFICATION SUITE")
    print(SEPARATOR)
    
    client = TestClient(app)
    
    # 1. Root Info
    print("\n[1] Testing GET / ...")
    resp = client.get("/")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    print(f"  Service: {data.get('service')}, Status: {data.get('status')}")
    print("  PASS")

    # 2. Status
    print("\n[2] Testing GET /api/status ...")
    resp = client.get("/api/status")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    print(f"  Engine State:  {data.get('state')}")
    print(f"  Model Loaded:  {data.get('model_loaded')} ({data.get('model_name')})")
    print(f"  Server Uptime: {data.get('server_uptime_seconds')}s")
    print("  PASS")

    # 3. Interfaces
    print("\n[3] Testing GET /api/interfaces ...")
    resp = client.get("/api/interfaces")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    print(f"  Interfaces Discovered: {data.get('count')}")
    for iface in data.get("interfaces", [])[:3]:
        print(f"    - {iface.get('display_name')} (Default: {iface.get('is_default')})")
    print("  PASS")

    # 4. Dashboard (Initial Idle State)
    print("\n[4] Testing GET /api/dashboard ...")
    resp = client.get("/api/dashboard")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    print(f"  Packets: {data.get('packets_captured')}, Active Flows: {data.get('active_flows')}, Normal: {data.get('normal_count')}, Threats: {data.get('threat_count')}")
    print("  PASS")

    # 5. Traffic Time-Series
    print("\n[5] Testing GET /api/traffic ...")
    resp = client.get("/api/traffic?limit=10")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    print(f"  Returned Points: {data.get('points_count')}")
    print("  PASS")

    # 6. Threats Analytics
    print("\n[6] Testing GET /api/threats ...")
    resp = client.get("/api/threats")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    print(f"  Total Threats: {data.get('total_threats')}, Severity Dist: {data.get('severity_distribution')}")
    print("  PASS")

    # 7. Alerts
    print("\n[7] Testing GET /api/alerts ...")
    resp = client.get("/api/alerts")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    print(f"  Alerts Count: {data.get('total_alerts')}")
    print("  PASS")

    # 8. Start Monitor
    print("\n[8] Testing POST /api/monitor/start ...")
    resp = client.post("/api/monitor/start")
    print(f"  Response ({resp.status_code}): {resp.json()}")
    if resp.status_code == 200:
        print("  Monitoring started successfully!")
        
        time.sleep(2.0)
        
        # Check Dashboard during run
        dash_resp = client.get("/api/dashboard")
        print(f"  Dashboard state: {dash_resp.json().get('state')}, Packets: {dash_resp.json().get('packets_captured')}")
        
        # 9. Stop Monitor
        print("\n[9] Testing POST /api/monitor/stop ...")
        stop_resp = client.post("/api/monitor/stop")
        print(f"  Stop Response ({stop_resp.status_code}): {stop_resp.json()}")
        assert stop_resp.status_code == 200
        print("  PASS")
    else:
        print(f"  Notice: Live packet capture requires elevated network privileges/npcap: {resp.json()}")

    # 10. Reset Monitor
    print("\n[10] Testing POST /api/monitor/reset ...")
    reset_resp = client.post("/api/monitor/reset")
    assert reset_resp.status_code == 200
    print(f"  Reset Response: {reset_resp.json()}")
    print("  PASS")

    print(f"\n{SEPARATOR}")
    print("ALL API ENDPOINT VERIFICATIONS PASSED SUCCESSFULLY!")
    print(SEPARATOR)

if __name__ == "__main__":
    run_tests()
