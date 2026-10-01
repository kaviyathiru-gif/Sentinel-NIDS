"""
Sentinel Firebase Firestore Database Service
Manages real-time persistence of intrusion events, traffic logs, and mitigation actions.
Supports live Firebase Admin SDK connection and in-memory mock fallback for zero-dependency execution.
"""

import os
import json
import time
from datetime import datetime

class FirestoreService:
    def __init__(self, credentials_path=None, project_id=None):
        self.client = None
        self.is_connected = False
        self.mock_store = {
            "incidents": [],
            "traffic_logs": [],
            "mitigations": [],
            "notifications": []
        }

        # Try initializing Firebase Admin SDK if installed
        try:
            import firebase_admin
            from firebase_admin import credentials, firestore

            if credentials_path and os.path.exists(credentials_path):
                cred = credentials.Certificate(credentials_path)
                firebase_admin.initialize_app(cred)
                self.client = firestore.client()
                self.is_connected = True
                print(" Successfully connected to live Firebase Firestore via Service Account.")
            elif project_id:
                firebase_admin.initialize_app(options={"projectId": project_id})
                self.client = firestore.client()
                self.is_connected = True
                print(f" Successfully connected to Firebase Firestore project: {project_id}")
        except Exception as e:
            self.is_connected = False
            # Mock mode ensures seamless demo and offline testing

    def record_incident(self, incident_data):
        """
        Stores an intrusion incident in the 'sentinel_incidents' collection.
        """
        doc_id = incident_data.get("incident_id") or f"INC-{int(time.time() * 1000)}"
        incident_data["incident_id"] = doc_id
        incident_data["timestamp"] = incident_data.get("timestamp") or datetime.utcnow().isoformat() + "Z"

        if self.is_connected and self.client:
            try:
                self.client.collection("sentinel_incidents").document(doc_id).set(incident_data)
                return doc_id
            except Exception as e:
                print(f"Firestore write error: {e}")

        # Local fallback store
        self.mock_store["incidents"].insert(0, incident_data)
        if len(self.mock_store["incidents"]) > 200:
            self.mock_store["incidents"].pop()
        return doc_id

    def record_traffic(self, flow_data):
        """
        Logs incoming network traffic flow in 'sentinel_traffic_logs'.
        """
        log_id = f"FLOW-{int(time.time() * 1000)}"
        flow_data["flow_id"] = log_id
        flow_data["timestamp"] = flow_data.get("timestamp") or datetime.utcnow().isoformat() + "Z"

        if self.is_connected and self.client:
            try:
                self.client.collection("sentinel_traffic_logs").document(log_id).set(flow_data)
                return log_id
            except Exception:
                pass

        self.mock_store["traffic_logs"].insert(0, flow_data)
        if len(self.mock_store["traffic_logs"]) > 500:
            self.mock_store["traffic_logs"].pop()
        return log_id

    def record_mitigation(self, mitigation_data):
        """
        Logs an automated mitigation action (e.g., IP blocking, firewall rule addition).
        """
        action_id = f"MIT-{int(time.time() * 1000)}"
        mitigation_data["action_id"] = action_id
        mitigation_data["timestamp"] = datetime.utcnow().isoformat() + "Z"

        if self.is_connected and self.client:
            try:
                self.client.collection("sentinel_mitigations").document(action_id).set(mitigation_data)
                return action_id
            except Exception:
                pass

        self.mock_store["mitigations"].insert(0, mitigation_data)
        return action_id

    def get_recent_incidents(self, limit=50):
        if self.is_connected and self.client:
            try:
                docs = self.client.collection("sentinel_incidents")\
                    .order_by("timestamp", direction="DESCENDING")\
                    .limit(limit)\
                    .stream()
                return [d.to_dict() for d in docs]
            except Exception:
                pass
        return self.mock_store["incidents"][:limit]

    def get_mitigation_history(self, limit=20):
        if self.is_connected and self.client:
            try:
                docs = self.client.collection("sentinel_mitigations")\
                    .order_by("timestamp", direction="DESCENDING")\
                    .limit(limit)\
                    .stream()
                return [d.to_dict() for d in docs]
            except Exception:
                pass
        return self.mock_store["mitigations"][:limit]
