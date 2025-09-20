"""
Advanced Security Management
===========================
Multi-factor authentication and security features
"""

import os
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List
import hashlib
import hmac
import qrcode
import io
import base64

logger = logging.getLogger(__name__)

class SecurityManager:
    """Advanced security management system"""
    
    def __init__(self):
        self.failed_attempts = {}
        self.active_sessions = {}
        self.security_events = []
        
    def generate_otp_secret(self, username: str) -> str:
        """Generate OTP secret for 2FA"""
        secret = secrets.token_hex(20)
        return secret
    
    def generate_qr_code(self, username: str, secret: str) -> str:
        """Generate QR code for 2FA setup"""
        otpauth_url = f"otpauth://totp/ChainGuard:{username}?secret={secret}&issuer=ChainGuard"
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(otpauth_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    def verify_otp(self, secret: str, token: str) -> bool:
        """Verify OTP token"""
        # Simplified OTP verification - in production use proper TOTP library
        import time
        current_time = int(time.time() // 30)
        
        for i in range(-1, 2):  # Allow 30 second window
            test_token = self._generate_totp(secret, current_time + i)
            if test_token == token:
                return True
        return False
    
    def _generate_totp(self, secret: str, time_counter: int) -> str:
        """Generate TOTP token"""
        key = base64.b32decode(secret.upper())
        msg = time_counter.to_bytes(8, byteorder='big')
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        
        offset = digest[-1] & 0x0f
        code = ((digest[offset] & 0x7f) << 24 |
                (digest[offset + 1] & 0xff) << 16 |
                (digest[offset + 2] & 0xff) << 8 |
                (digest[offset + 3] & 0xff))
        
        return str(code % 1000000).zfill(6)
    
    def check_password_strength(self, password: str) -> Dict[str, any]:
        """Check password strength"""
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password must be at least 8 characters")
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
        strength = strength_levels[min(score, 4)]
        
        return {
            'score': score,
            'strength': strength,
            'feedback': feedback
        }
    
    def log_security_event(self, event_type: str, username: str, details: str, ip_address: str = None):
        """Log security events"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'username': username,
            'details': details,
            'ip_address': ip_address or '127.0.0.1',
            'severity': self._determine_severity(event_type)
        }
        
        self.security_events.append(event)
        logger.info(f"Security Event: {event_type} - {username} - {details}")
        
        # Keep only last 1000 events
        if len(self.security_events) > 1000:
            self.security_events.pop(0)
    
    def _determine_severity(self, event_type: str) -> str:
        """Determine event severity"""
        high_severity = ['failed_login_multiple', 'account_lockout', 'suspicious_activity']
        medium_severity = ['failed_login', 'password_change', 'privilege_escalation']
        
        if event_type in high_severity:
            return 'HIGH'
        elif event_type in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_security_dashboard(self) -> Dict[str, any]:
        """Get security dashboard data"""
        recent_events = self.security_events[-50:] if self.security_events else []
        
        # Count events by type
        event_counts = {}
        for event in recent_events:
            event_type = event['type']
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        # Active sessions
        active_sessions_count = len(self.active_sessions)
        
        # Failed attempts
        failed_attempts_count = sum(self.failed_attempts.values())
        
        return {
            'recent_events': recent_events,
            'event_counts': event_counts,
            'active_sessions': active_sessions_count,
            'failed_attempts': failed_attempts_count,
            'total_events': len(self.security_events)
        }

# Global security manager
security_manager = SecurityManager()
