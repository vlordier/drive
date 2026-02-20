"""Logging filters for security and PII sanitization."""

import hashlib
import logging
import re
import secrets
from typing import Any, Optional

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PASSWORD_PATTERN = re.compile(r"(password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE)
TOKEN_PATTERN = re.compile(r"(token|api_key|apikey|secret)\s*[:=]\s*\S+", re.IGNORECASE)
AWS_KEY_PATTERN = re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}")
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
)
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")
CREDIT_CARD_PATTERN = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
SSN_PATTERN = re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b")

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "token",
    "private_key",
    "privatekey",
    "aws_access_key",
    "aws_secret_key",
    "jwt",
    "bearer",
    "authorization",
    "auth_token",
    "session_id",
    "sessionid",
    "csrftoken",
    "csrf_token",
    "x-api-key",
    "client_secret",
    "encryption_key",
}


class SanitizePIIFilter(logging.Filter):
    """Filter that sanitizes PII from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.msg:
            record.msg = self._sanitize_string(str(record.msg))
        if record.args:
            record.args = tuple(self._sanitize_args(record.args))
        return True

    def _sanitize_string(self, text: str) -> str:
        text = EMAIL_PATTERN.sub("[EMAIL]", text)
        text = PASSWORD_PATTERN.sub(r"\1=[REDACTED]", text)
        text = TOKEN_PATTERN.sub(r"\1=[REDACTED]", text)
        text = AWS_KEY_PATTERN.sub("[AWS_KEY_REDACTED]", text)
        text = PRIVATE_KEY_PATTERN.sub("[PRIVATE_KEY_REDACTED]", text)
        text = JWT_PATTERN.sub("[JWT_REDACTED]", text)
        text = CREDIT_CARD_PATTERN.sub("[CREDIT_CARD_REDACTED]", text)
        text = SSN_PATTERN.sub("[SSN_REDACTED]", text)
        return text

    def _sanitize_args(self, args: tuple) -> tuple:
        sanitized = []
        for arg in args:
            if isinstance(arg, str):
                sanitized.append(self._sanitize_string(arg))
            elif isinstance(arg, dict):
                sanitized.append(self._sanitize_dict(arg))
            else:
                sanitized.append(arg)
        return tuple(sanitized)  # type: ignore[return-value]

    def _sanitize_dict(self, d: dict) -> dict:
        result = {}
        for key, value in d.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in SENSITIVE_KEYS):
                result[key] = "[REDACTED]"
            elif isinstance(value, str):
                result[key] = self._sanitize_string(value)
            elif isinstance(value, dict):
                result[key] = self._sanitize_dict(value)
            else:
                result[key] = value
        return result


class SecurityEventLogger:
    """Logger for security-related events."""

    def __init__(self, name: str = "security"):
        self.logger = logging.getLogger(name)

    def log_authentication_failure(self, user: str, ip_address: str, reason: str):
        """Log authentication failure."""
        self.logger.warning(
            f"Authentication failure: user={user} ip={ip_address} reason={reason}"
        )

    def log_authorization_failure(
        self, user: str, action: str, resource: str, ip_address: str
    ):
        """Log authorization failure."""
        self.logger.warning(
            f"Authorization denied: user={user} action={action} resource={resource} ip={ip_address}"
        )

    def log_suspicious_activity(self, description: str, details: dict):
        """Log suspicious activity."""
        self.logger.warning(f"Suspicious activity: {description} details={details}")

    def log_api_rate_limit_exceeded(self, user: str, ip_address: str, endpoint: str):
        """Log rate limit exceeded."""
        self.logger.warning(
            f"Rate limit exceeded: user={user} ip={ip_address} endpoint={endpoint}"
        )

    def log_credential_leak_detected(self, pattern: str, location: str):
        """Log potential credential leak detected."""
        self.logger.critical(
            f"Potential credential leak detected: pattern={pattern} location={location}"
        )


def detect_potential_credentials(text: str) -> dict[str, str | None]:
    """
    Scan text for potential leaked credentials.
    Returns dict of detected patterns.
    """
    detected = {}

    if AWS_KEY_PATTERN.search(text):
        detected["aws_key"] = "AWS access key detected"
    if PRIVATE_KEY_PATTERN.search(text):
        detected["private_key"] = "Private key detected"
    if JWT_PATTERN.search(text):
        detected["jwt_token"] = "JWT token detected"  # noqa: S105
    if CREDIT_CARD_PATTERN.search(text):
        detected["credit_card"] = "Credit card detected"
    if SSN_PATTERN.search(text):
        detected["ssn"] = "SSN detected"

    return detected


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


def hash_sensitive_data(data: str, salt: str | None = None) -> str:
    """Hash sensitive data using SHA-256 with optional salt."""
    if salt is None:
        salt = secrets.token_hex(16)
    return hashlib.pbkdf2_hmac("sha256", data.encode(), salt.encode(), 100000).hex()


security_logger = SecurityEventLogger()
