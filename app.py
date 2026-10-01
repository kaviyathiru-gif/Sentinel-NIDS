"""
Sentinel MLDL NIDS - Real-Time API Server
Zero mock data. Real-time OTP email delivery, physical device permission capture,
live flow ingestion, and PyTorch deep learning inference.
"""

import sys
import os
import json
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

# Add parent directory to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from model.inference import SentinelInferenceEngine
from backend.geotagging import GeoTaggingService
from backend.firestore_service import FirestoreService
from backend.alert_service import AlertNotificationService
from backend.auth_service import AuthService

inference_engine = SentinelInferenceEngine(
    checkpoint_path=os.path.join(BASE_DIR, "model", "checkpoints", "sentinel_ids_best.pth"),
    preprocessor_path=os.path.join(BASE_DIR, "model", "checkpoints", "preprocessor_params.json")
)
geotag_service = GeoTaggingService()
firestore_service = FirestoreService()
alert_service = AlertNotificationService()
auth_service = AuthService()

# Real-time state counters strictly initialized to ZERO (no default mock numbers)
live_state = {
    "total_flows": 0,
    "normal_users": 0,
    "blocked_hackers": 0,
    "port_scans": 0,
    "brute_force": 0,
    "mitigations_enforced": 0,
    "real_time_incidents": [],
    "verified_devices": []
}

class SentinelAPIHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ["/", "/login", "/login.html"]:
            self.path = "/frontend/login.html"
            return super().do_GET()
        elif path in ["/dashboard", "/index.html"]:
            self.path = "/frontend/index.html"
            return super().do_GET()
        elif path.startswith("/frontend/"):
            return super().do_GET()
        elif path == "/api/stats":
            self._json_response(live_state)
        elif path == "/api/incidents":
            self._json_response({"incidents": live_state["real_time_incidents"]})
        elif path == "/api/notifications":
            self._json_response({
                "notifications": alert_service.notification_log,
                "blocked_ips": list(alert_service.blocked_ips)
            })
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        if path == "/api/auth/send-otp":
            email = data.get("email", "")
            res = auth_service.request_email_otp(email)
            self._json_response(res, code=200 if res["success"] else 400)

        elif path == "/api/auth/verify-otp":
            email = data.get("email", "")
            otp = data.get("otp", "")
            device_telemetry = data.get("device_telemetry", {})
            res = auth_service.verify_otp_and_register_device(email, otp, device_telemetry)
            if res["success"]:
                live_state["verified_devices"].append(res["device"])
                firestore_service.record_incident({
                    "incident_id": f"AUTH-{int(time.time() * 1000)}",
                    "type": "ADMIN_AUTHENTICATION_SUCCESS",
                    "email": email,
                    "device": res["device"],
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                })
            self._json_response(res, code=200 if res["success"] else 400)

        elif path == "/api/ingest":
            # Live, real-time packet flow ingestion from network sniffer or user telemetry
            self._handle_live_ingest(data)

        elif path == "/api/mitigate":
            ip = data.get("ip")
            inc_id = data.get("incident_id", "MANUAL-TRIGGER")
            if not ip:
                self._json_response({"error": "Missing IP parameter"}, 400)
                return
            res = alert_service.execute_threat_mitigation(ip, inc_id)
            firestore_service.record_mitigation(res)
            live_state["mitigations_enforced"] += 1
            self._json_response({"status": "mitigation_enforced", "details": res})

        else:
            self.send_error(404, "Endpoint not found")

    def _json_response(self, payload, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload, indent=2).encode("utf-8"))

    def _handle_live_ingest(self, data):
        flow = data.get("flow", {})
        src_ip = data.get("src_ip", "")
        dst_ip = data.get("dst_ip", "10.0.0.1")
        dst_port = int(data.get("dst_port", 443))

        if not src_ip or not flow:
            self._json_response({"success": False, "error": "Invalid real-time packet payload."}, 400)
            return

        # 1. Run PyTorch Deep Learning Model
        analysis = inference_engine.analyze_flow(flow)

        # 2. Real-time Geo-Tagging of source IP
        geo = geotag_service.lookup_ip(src_ip)

        incident_record = {
            "incident_id": f"SEC-{int(time.time() * 1000)}",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "geo": geo,
            "is_hacker": analysis["is_hacker"],
            "user_status": analysis["user_status"],
            "attack_type": analysis["attack_type"],
            "confidence": analysis["confidence"],
            "severity": analysis["severity"],
            "indicators": analysis["indicators"],
            "class_distribution": analysis["class_distribution"],
            "flow_summary": {
                "packets": flow.get("total_fwd_packets", 0) + flow.get("total_bwd_packets", 0),
                "bytes": flow.get("total_fwd_bytes", 0) + flow.get("total_bwd_bytes", 0),
                "duration_ms": flow.get("flow_duration_ms", 0)
            }
        }

        # Update real-time state counters
        live_state["total_flows"] += 1
        if analysis["is_hacker"]:
            live_state["blocked_hackers"] += 1
            if analysis["attack_type"] == "Port Scanning":
                live_state["port_scans"] += 1
            elif analysis["attack_type"] == "Brute Force":
                live_state["brute_force"] += 1
        else:
            live_state["normal_users"] += 1

        live_state["real_time_incidents"].insert(0, incident_record)
        if len(live_state["real_time_incidents"]) > 100:
            live_state["real_time_incidents"].pop()

        # 3. Store into Firebase Firestore
        firestore_service.record_incident(incident_record)
        firestore_service.record_traffic(flow)

        # 4. Trigger Automated Threat Notification & Escalation if malicious
        mitigation_results = None
        if analysis["is_hacker"] and analysis["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]:
            mitigation_results = alert_service.handle_incident_escalation(incident_record)
            incident_record["mitigation_action"] = mitigation_results
            if mitigation_results.get("mitigation"):
                live_state["mitigations_enforced"] += 1

        self._json_response({
            "success": True,
            "incident": incident_record,
            "mitigation_results": mitigation_results,
            "live_stats": {
                "total_flows": live_state["total_flows"],
                "normal_users": live_state["normal_users"],
                "blocked_hackers": live_state["blocked_hackers"],
                "port_scans": live_state["port_scans"],
                "brute_force": live_state["brute_force"],
                "mitigations_enforced": live_state["mitigations_enforced"]
            }
        })

def run_server(port=8080):
    os.chdir(BASE_DIR)
    server_address = ("", port)
    httpd = HTTPServer(server_address, SentinelAPIHandler)
    print(f"============================================================")
    print(f" Sentinel Real-Time NIDS Active on port {port}")
    print(f" Zero Mock Data. Real Email OTP + Physical Device Geolocation Enforced.")
    print(f"============================================================")
    httpd.serve_forever()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
