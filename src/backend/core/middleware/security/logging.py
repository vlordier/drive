"""Security middleware for preventing log leaks."""

import logging
import re
import uuid
from collections.abc import Callable
from typing import Any, Optional

from django.conf import settings
from django.http import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)

# Sensitive headers that should never be logged
SENSITIVE_HEADERS = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "sec-websocket-key",
    "upgrade",
    "connection",
}

# Sensitive query parameters
SENSITIVE_QUERY_PARAMS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "auth",
    "session_id",
    "csrftoken",
    "jwt",
    "private_key",
    "encryption_key",
    "key",
}

# Response headers that shouldn't leak
SENSITIVE_RESPONSE_HEADERS = {
    "set-cookie",
    "authorization",
    "x-api-key",
}


class RequestIDMiddleware:
    """Middleware that adds a unique request ID to each request for tracking."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request_id = request.META.get("HTTP_X_REQUEST_ID")
        if not request_id:
            request_id = str(uuid.uuid4())

        request.request_id = request_id  # type: ignore[attr-defined]
        response = self.get_response(request)
        response["X-Request-ID"] = request_id

        return response


class SanitizeHeadersMiddleware:
    """Middleware that sanitizes sensitive headers in logs."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self._sanitize_request_headers(request)
        response = self.get_response(request)
        self._sanitize_response_headers(response)
        return response

    def _sanitize_request_headers(self, request: HttpRequest) -> None:
        sanitized = {}
        for key, value in request.META.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].lower()
                if header_name in SENSITIVE_HEADERS:
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = value
            else:
                sanitized[key] = value

        for key, value in sanitized.items():
            if key.startswith("HTTP_"):
                request.META[key] = value

    def _sanitize_response_headers(self, response: HttpResponse) -> None:
        for header in SENSITIVE_RESPONSE_HEADERS:
            if header in response:
                response[header] = "[REDACTED]"


class SanitizeQueryParamsMiddleware:
    """Middleware that sanitizes sensitive query parameters in logs."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.GET:
            request.GET._mutable = True  # type: ignore[attr-defined]
            for key in list(request.GET.keys()):
                if self._is_sensitive_param(key):
                    request.GET[key] = "[REDACTED]"

        return self.get_response(request)

    def _is_sensitive_param(self, param: str) -> bool:
        param_lower = param.lower()
        return any(sensitive in param_lower for sensitive in SENSITIVE_QUERY_PARAMS)


class SecureResponseMiddleware:
    """
    Adds security headers that Django's SecurityMiddleware doesn't provide.

    Note: Django's SecurityMiddleware already provides:
    - X-Content-Type-Options (SECURE_CONTENT_TYPE_NOSNIFF)
    - Referrer-Policy (SECURE_REFERRER_POLICY)
    - X-Frame-Options (XFrameOptionsMiddleware)
    - HSTS headers (SECURE_HSTS_* settings)

    This middleware adds Permissions-Policy which Django doesn't support.
    See: https://docs.djangoproject.com/en/6.0/ref/middleware/
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)

        if not hasattr(response, "security_headers_added"):
            # Permissions-Policy - Django doesn't provide this
            # Disables browser features that could be abused
            response["Permissions-Policy"] = (
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
                "magnetometer=(), microphone=(), payment=(), usb=()"
            )
            response.security_headers_added = True  # type: ignore[attr-defined]

        return response


class LogSanitizer:
    """Utility class for sanitizing log messages."""

    EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    PASSWORD_PATTERN = re.compile(
        r'([\'"]?(?:password|passwd|pwd|secret|token|api_key|apikey)[\'"]?\s*[:=]\s*)[^\s\'"]+',
        re.IGNORECASE,
    )
    AWS_KEY_PATTERN = re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}")
    JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")

    @classmethod
    def sanitize_message(cls, message: str) -> str:
        if not message:
            return message
        message = cls.EMAIL_PATTERN.sub("[EMAIL]", message)
        message = cls.PASSWORD_PATTERN.sub(r"\1[REDACTED]", message)
        message = cls.AWS_KEY_PATTERN.sub("[AWS_KEY]", message)
        message = cls.JWT_PATTERN.sub("[JWT]", message)
        return message

    @classmethod
    def sanitize_dict(cls, data: dict, depth: int = 0) -> dict:
        if depth > 5:
            return {"[MAX_DEPTH]": True}

        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(s in key_lower for s in SENSITIVE_QUERY_PARAMS):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, str):
                sanitized[key] = cls.sanitize_message(value)
            elif isinstance(value, dict):
                sanitized[key] = cls.sanitize_dict(value, depth + 1)  # type: ignore[assignment]
            else:
                sanitized[key] = value
        return sanitized
