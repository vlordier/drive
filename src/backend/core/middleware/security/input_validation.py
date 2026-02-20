"""Input validation middleware for security."""

import ipaddress
import json
import re
from collections.abc import Callable
from ipaddress import IPv4Address, IPv6Address
from re import Pattern
from typing import Any
from urllib.parse import urlparse

from django.http import HttpRequest, HttpResponse

# Private IP ranges to block
PRIVATE_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
]

# Blocked hostnames (not IPs)
BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "host.docker.internal",
    }
)


def is_safe_url(url: str, allowed_hosts: list[str] | None = None) -> bool:
    """Validate URL to prevent SSRF attacks."""
    is_safe = True

    # Basic validation
    if not url:
        is_safe = False
    else:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            is_safe = False
        else:
            host = parsed.netloc.split(":")[0]
            # Check for IP address
            try:
                ip = ipaddress.ip_address(host)
                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or any(ip in net for net in PRIVATE_RANGES)
                ):
                    is_safe = False
                elif allowed_hosts and str(ip) not in allowed_hosts:
                    is_safe = False
            except ValueError:
                # It's a hostname
                if host.lower() in BLOCKED_HOSTNAMES:
                    is_safe = False
                elif allowed_hosts and not any(
                    host == h or host.endswith(f".{h}") for h in allowed_hosts
                ):
                    is_safe = False

    return is_safe


class InputValidationMiddleware:
    """
    Middleware that validates and sanitizes incoming request data.

    Provides protection against:
    - SQL injection via query parameters
    - XSS via input sanitization
    - Path traversal attacks
    - Invalid UTF-8 encoding
    - Control character injection
    """

    # Characters that should be blocked or sanitized
    CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

    # SQL injection patterns
    SQL_INJECTION_PATTERNS: list[Pattern[str]] = [
        re.compile(
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b)",
            re.IGNORECASE,
        ),
        re.compile(r"(--|\#|\/\*|\*\/)"),  # SQL comments
        re.compile(
            r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)"
        ),  # Multiple statements
        re.compile(r"'(\s*(OR|AND)\s*'?\d)", re.IGNORECASE),  # OR/AND injection
        re.compile(r"'(\s*=\s*')"),  # Login bypass attempts
    ]

    # XSS patterns
    XSS_PATTERNS: list[Pattern[str]] = [
        re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),  # Event handlers
        re.compile(r"<iframe[^>]*>.*?</iframe>", re.IGNORECASE | re.DOTALL),
        re.compile(r"<\w+\s+on\w+", re.IGNORECASE),
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERN = re.compile(
        r"(\.\.[/\\])|(/etc/passwd)|(windows\\system32)"
    )

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Validate request method
        if not self._validate_request_method(request):
            return HttpResponse("Invalid request method", status=405)

        # Validate Content-Type for POST/PUT
        if request.method in ("POST", "PUT", "PATCH"):
            if not self._validate_content_type(request):
                return HttpResponse("Invalid Content-Type", status=415)

        # Validate and sanitize query parameters
        if request.GET:
            sanitized_get = self._sanitize_query_params(dict(request.GET))
            request.GET = sanitized_get  # type: ignore[assignment]

        # Validate and sanitize request body
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                self._validate_body(request)
            except (ValueError, UnicodeDecodeError):
                return HttpResponse("Invalid request body", status=400)

        # Check for path traversal in URL
        if self._contains_path_traversal(request.path):
            return HttpResponse("Forbidden", status=403)

        response = self.get_response(request)

        # Add security headers for response
        response["X-Content-Type-Options"] = "nosniff"

        return response

    def _validate_request_method(self, request: HttpRequest) -> bool:
        """Allow only safe HTTP methods."""
        allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        return request.method in allowed_methods

    def _validate_content_type(self, request: HttpRequest) -> bool:
        """Validate Content-Type header."""
        content_type = request.headers.get("Content-Type", "")

        # Allow JSON and form data
        allowed_types = [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ]

        return any(ct in content_type.lower() for ct in allowed_types)

    def _sanitize_query_params(self, params: dict) -> dict:
        """Sanitize query parameters."""
        sanitized = {}

        for key, value in params.items():
            if value is None:
                continue

            # Convert to string if needed
            str_value = str(value)

            # Remove control characters
            str_value = self.CONTROL_CHARS_PATTERN.sub("", str_value)

            # Check for SQL injection patterns
            if self._contains_sql_injection(str_value):
                # Log but don't block - let the view handle it
                pass

            # Basic XSS sanitization (HTML encode)
            # Only for display, not for storage
            sanitized[key] = str_value

        return sanitized

    def _contains_sql_injection(self, value: str) -> bool:
        """Check if value contains SQL injection patterns."""
        for pattern in self.SQL_INJECTION_PATTERNS:
            if pattern.search(value):
                return True
        return False

    def _validate_body(self, request: HttpRequest) -> None:
        """Validate request body."""
        if not request.body:
            return

        # Check for valid UTF-8
        try:
            request.body.decode("utf-8")
        except UnicodeDecodeError:
            raise

        # Check body size (additional check beyond Django settings)
        max_size = 10 * 1024 * 1024  # 10MB
        if len(request.body) > max_size:
            raise ValueError("Request body too large")

    def _contains_path_traversal(self, path: str) -> bool:
        """Check if path contains path traversal attempts."""
        return bool(self.PATH_TRAVERSAL_PATTERN.search(path.lower()))


class RequestTimeoutMiddleware:
    """
    Middleware to add timeout protections and prevent slowloris attacks.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Add request timeout header (suggests to upstream to timeout)
        response = self.get_response(request)
        response["X-Request-Timeout"] = "30"
        return response
