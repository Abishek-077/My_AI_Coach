import logging
import re
import os
import time
from flask import request, jsonify

# =====================================================
# LOG FILE SETUP
# =====================================================

LOG_DIR = "security_logs"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "security.log"),
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

security_logger = logging.getLogger("SECURITY")


# =====================================================
# SUSPICIOUS PAYLOAD PATTERNS
# =====================================================

SUSPICIOUS_PATTERNS = [
    r"<script.*?>",
    r"</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"document\.cookie",
    r"window\.location",
    r"<img.*?src",
    r"<iframe",
    r"base64,",
    r"=cmd\|",
    r"powershell",
    r"/bin/bash",
    r"../",
    r"%3cscript",
]


def detect_suspicious_input(data: str) -> bool:
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            return True
    return False


# =====================================================
# CENTRAL SECURITY LOGGER
# =====================================================

def log_suspicious_activity(reason: str, payload: str = ""):
    ip = request.remote_addr
    path = request.path
    method = request.method

    security_logger.warning(
        f"Suspicious activity detected | "
        f"IP={ip} | METHOD={method} | PATH={path} | "
        f"REASON={reason} | PAYLOAD={payload[:200]}"
    )


# =====================================================
# RESPONSE PROTOCOL
# =====================================================

def secure_response(data=None, message="Success", status=200):
    return jsonify({
        "status": "success",
        "message": message,
        "data": data
    }), status


def secure_error(message="Request blocked", status=400):
    return jsonify({
        "status": "error",
        "message": message
    }), status


# =====================================================
# SECURITY HEADERS
# =====================================================

def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "media-src 'self' blob:; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )

    return response


# =====================================================
# REQUEST INSPECTION (AUTO-DETECT ATTACKS)
# =====================================================

def inspect_request():
    suspicious = False

    # Inspect query params
    for key, value in request.args.items():
        if detect_suspicious_input(value):
            log_suspicious_activity("Malicious query parameter", value)
            suspicious = True

    # Inspect form fields
    for key, value in request.form.items():
        if detect_suspicious_input(value):
            log_suspicious_activity("Malicious form input", value)
            suspicious = True

    # Inspect JSON body
    if request.is_json:
        for k, v in request.get_json(silent=True, default={}).items():
            if isinstance(v, str) and detect_suspicious_input(v):
                log_suspicious_activity("Malicious JSON payload", v)
                suspicious = True

    return suspicious
