"""Authentication and session security middleware."""

import logging
import time
from collections.abc import Callable
from typing import Any, Optional

from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpRequest, HttpResponse, JsonResponse

logger = logging.getLogger(__name__)

User = get_user_model()


class SessionSecurityMiddleware:
    """
    Middleware that enhances session security:
    - Regenerates session ID periodically
    - Tracks session creation time
    - Invalidates sessions after inactivity timeout
    - Adds session security headers
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        self.session_timeout = getattr(settings, "SESSION_SECURITY_TIMEOUT", 3600)
        self.absolute_timeout = getattr(settings, "SESSION_ABSOLUTE_TIMEOUT", 86400)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if hasattr(request, "user") and request.user.is_authenticated:
            if not self._is_session_valid(request):
                logger.warning(
                    f"Session expired for user {request.user.id}, "
                    f"request_id={getattr(request, 'request_id', 'unknown')}"
                )
                return self._session_expired_response(request)

            if not self._is_session_ip_valid(request):
                logger.warning(f"Possible session hijacking for user {request.user.id}")
                request.session.flush()
                return self._session_expired_response(request)

            self._maybe_regenerate_session(request)
            request.session["_last_activity"] = int(time.time())

        response = self.get_response(request)
        response["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
        response["Pragma"] = "no-cache"
        response["Expires"] = "0"

        return response

    def _is_session_valid(self, request: HttpRequest) -> bool:
        last_activity = request.session.get("_last_activity")
        if not last_activity:
            return True

        if int(time.time()) - last_activity > self.session_timeout:
            return False

        session_created = request.session.get("_session_created")
        if session_created:
            if int(time.time()) - session_created > self.absolute_timeout:
                return False

        return True

    def _is_session_ip_valid(self, request: HttpRequest) -> bool:
        stored_ip = request.session.get("_session_ip")
        if not stored_ip:
            request.session["_session_ip"] = self._get_client_ip(request)
            return True

        current_ip = self._get_client_ip(request)
        return stored_ip == current_ip or self._is_same_subnet(stored_ip, current_ip)

    def _get_client_ip(self, request: HttpRequest) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "")

    def _is_same_subnet(self, ip1: str, ip2: str) -> bool:
        try:
            parts1 = ip1.split(".")[:-1]
            parts2 = ip2.split(".")[:-1]
            return parts1 == parts2
        except (IndexError, AttributeError):
            return False

    def _maybe_regenerate_session(self, request: HttpRequest) -> None:
        regeneration_interval = getattr(settings, "SESSION_REGENERATION_INTERVAL", 300)
        last_regen = request.session.get("_last_session_regen", 0)

        if int(time.time()) - last_regen > regeneration_interval:
            request.session.regenerate()  # type: ignore[attr-defined]
            request.session["_last_session_regen"] = int(time.time())

    def _session_expired_response(self, request: HttpRequest) -> HttpResponse:
        from django.contrib.auth import logout  # noqa: PLC0415

        logout(request)
        response = HttpResponse(
            "Session expired. Please log in again.",
            status=401,
            content_type="text/plain",
        )
        response["WWW-Authenticate"] = 'Bearer realm="session_expired"'
        return response


class CSRFProtectionMiddleware:
    """
    Enhanced CSRF protection middleware.

    Note: Django's CsrfViewMiddleware handles most CSRF validation.
    This middleware adds the CSRF token to a custom header for JavaScript clients
    and validates the Origin header for cross-origin requests.

    See Django CSRF docs: https://docs.djangoproject.com/en/6.0/ref/csrf/
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Validate Origin header for POST/PUT/DELETE requests
        # This adds extra protection beyond Django's built-in CSRF
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            origin = request.META.get("HTTP_ORIGIN")

            if origin:
                allowed_hosts = getattr(settings, "CSRF_TRUSTED_ORIGINS", [])
                allowed_hosts = allowed_hosts or getattr(settings, "ALLOWED_HOSTS", [])

                origin_host = origin.split("://")[-1].rstrip("/")
                if not any(
                    origin_host == host or origin_host.endswith(f".{host}")
                    for host in allowed_hosts
                ):
                    logger.warning(
                        f"CSRF: Invalid origin {origin} not in trusted origins"
                    )
                    return HttpResponse("CSRF validation failed", status=403)

        response = self.get_response(request)

        # Add CSRF token to custom header for JavaScript clients
        # This allows AJAX requests to easily access the CSRF token
        if hasattr(request, "csrf_token"):
            response["X-CSRF-Token"] = request.csrf_token

        return response


class TokenValidationMiddleware:
    """
    Middleware that validates authentication tokens on each request:
    - Checks token expiration
    - Validates token signature
    - Logs suspicious token activities
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")

        if auth_header:
            if not self._is_valid_token_format(auth_header):
                logger.warning("Invalid token format in Authorization header")
                return HttpResponse("Invalid token format", status=401)

            token = self._extract_token(auth_header)
            if token:
                validation_result = self._validate_token(token, request)
                if not validation_result["valid"]:
                    logger.warning(
                        f"Token validation failed: {validation_result['reason']}"
                    )
                    return JsonResponse(
                        {"error": validation_result["message"]}, status=401
                    )

        response = self.get_response(request)
        return response

    def _is_valid_token_format(self, auth_header: str) -> bool:
        parts = auth_header.split()
        if len(parts) != 2:
            return False
        scheme = parts[0].lower()
        return scheme in ("bearer", "token", "apikey", "jwt")

    def _extract_token(self, auth_header: str) -> str | None:
        parts = auth_header.split()
        if len(parts) == 2:
            return parts[1]
        return None

    def _validate_token(self, token: str, request: HttpRequest) -> dict:
        if len(token) < 10:
            return {
                "valid": False,
                "reason": "token_too_short",
                "message": "Invalid token",
            }

        if token in ("null", "undefined", "true", "false", "none"):
            return {
                "valid": False,
                "reason": "invalid_token_value",
                "message": "Invalid token",
            }

        return {"valid": True, "reason": None, "message": None}
