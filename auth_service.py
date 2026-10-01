"""
Sentinel Real-Time Authentication & Device Verification Service
Handles:
  1. Real-time 6-digit Email OTP generation and SMTP dispatch
  2. Device permission enforcement (Geolocation coordinates, Push Notifications)
  3. Session token issuance without default/mock accounts
"""

import os
import secrets
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta

class AuthService:
    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", 587))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.pending_otps = {}  # email -> {otp, expires_at, attempts}
        self.active_sessions = {}  # token -> session_data

    def request_email_otp(self, email: str) -> dict:
        """Generates a secure 6-digit OTP and sends it in real-time to the user's email."""
        clean_email = email.strip().lower()
        if not clean_email or "@" not in clean_email:
            return {"success": False, "error": "Invalid email address format."}

        # Generate cryptographically secure 6-digit OTP
        otp_code = str(secrets.randbelow(900000) + 100000)
        expires_at = datetime.utcnow() + timedelta(minutes=5)

        self.pending_otps[clean_email] = {
            "otp": otp_code,
            "expires_at": expires_at,
            "attempts": 0
        }

        # Send via real SMTP if credentials exist
        email_sent = False
        delivery_message = ""
        if self.smtp_user and self.smtp_password:
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = f"[Sentinel NIDS] Your Live Security Verification Code: {otp_code}"
                msg["From"] = f"Sentinel Cyber Operations <{self.smtp_user}>"
                msg["To"] = clean_email

                html_body = f"""
                <div style="font-family: sans-serif; background-color: #0f172a; color: #f8fafc; padding: 24px; border-radius: 8px;">
                    <h2 style="color: #38bdf8; margin-top: 0;">Sentinel SOC Identity Verification</h2>
                    <p style="color: #cbd5e1; font-size: 14px;">A live login request was initiated for your administrator account.</p>
                    <div style="background-color: #1e293b; padding: 16px; border-radius: 6px; text-align: center; margin: 20px 0; border: 1px solid #334155;">
                        <span style="font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #38bdf8; font-family: monospace;">{otp_code}</span>
                    </div>
                    <p style="color: #94a3b8; font-size: 12px;">This code expires in 5 minutes. If you did not request this, secure your account immediately.</p>
                </div>
                """
                msg.attach(MIMEText(html_body, "html"))

                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
                    server.sendmail(self.smtp_user, [clean_email], msg.as_string())
                email_sent = True
                delivery_message = f"Real-time OTP successfully dispatched to {clean_email} via Gmail SMTP."
            except Exception as e:
                delivery_message = f"SMTP dispatch error: {str(e)}"
        else:
            delivery_message = f"Real-time OTP generated ({otp_code}). Configure SMTP_USER and SMTP_PASSWORD environment variables for direct inbox delivery."

        return {
            "success": True,
            "email": clean_email,
            "expires_in_seconds": 300,
            "delivery_status": "SENT" if email_sent else "GENERATED",
            "message": delivery_message
        }

    def verify_otp_and_register_device(self, email: str, entered_otp: str, device_telemetry: dict) -> dict:
        """Verifies the live OTP and binds verified physical device permissions (Geolocation, Notification)."""
        clean_email = email.strip().lower()
        record = self.pending_otps.get(clean_email)

        if not record:
            return {"success": False, "error": "No pending verification request found for this email."}

        if datetime.utcnow() > record["expires_at"]:
            del self.pending_otps[clean_email]
            return {"success": False, "error": "Verification code has expired. Please request a new one."}

        record["attempts"] += 1
        if record["attempts"] > 4:
            del self.pending_otps[clean_email]
            return {"success": False, "error": "Maximum verification attempts exceeded. Please restart."}

        if record["otp"] != entered_otp.strip():
            return {"success": False, "error": f"Invalid verification code. {4 - record['attempts']} attempts remaining."}

        # Verification successful, enforce device permissions check
        geo_permission = device_telemetry.get("geo_permission", False)
        coordinates = device_telemetry.get("coordinates", {})
        if not geo_permission or not coordinates.get("latitude"):
            return {
                "success": False,
                "error": "Real-time device Geolocation permission is mandatory for Sentinel zero-trust perimeter verification."
            }

        # Clear OTP
        del self.pending_otps[clean_email]

        # Generate session token
        session_token = secrets.token_hex(32)
        session_data = {
            "email": clean_email,
            "verified_at": datetime.utcnow().isoformat() + "Z",
            "device": {
                "geo_latitude": coordinates.get("latitude"),
                "geo_longitude": coordinates.get("longitude"),
                "geo_accuracy_meters": coordinates.get("accuracy"),
                "notification_granted": device_telemetry.get("notification_permission", False),
                "user_agent": device_telemetry.get("user_agent", "Unknown Device"),
                "platform": device_telemetry.get("platform", "Unknown OS")
            }
        }
        self.active_sessions[session_token] = session_data

        return {
            "success": True,
            "session_token": session_token,
            "user": clean_email,
            "device": session_data["device"],
            "message": "Real-time identity and device perimeter verified."
        }
