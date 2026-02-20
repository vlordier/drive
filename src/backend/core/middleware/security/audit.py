"""Security audit middleware."""

import logging
import time
from collections.abc import Callable
from typing import Any

from django.http import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)


class SecurityAuditMiddleware:
    """
    Middleware that logs security-relevant events for audit purposes.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request._security_event_started = int(time.time())  # type: ignore[attr-defined]

        response = self.get_response(request)
        self._log_security_event(request, response)

        return response

    def _log_security_event(self, request: HttpRequest, response: HttpResponse) -> None:
        if response.status_code in (401, 403, 429):
            logger.warning(
                f"Security event: status={response.status_code}, "
                f"user={getattr(request.user, 'id', 'anonymous')}, "
                f"ip={self._get_client_ip(request)}, "
                f"path={request.path}, "
                f"method={request.method}"
            )

        if hasattr(request, "_was_authenticated") and not request.user.is_authenticated:
            logger.info(
                f"Authentication: user logged out, ip={self._get_client_ip(request)}"
            )

    def _get_client_ip(self, request: HttpRequest) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "")
