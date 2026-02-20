"""Rate limiting middleware."""

import logging
import time
from collections.abc import Callable
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)


class IPRateLimitMiddleware:
    """
    Simple IP-based rate limiting middleware.
    Uses in-memory storage - for production use Redis-backed storage.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        self.request_counts: dict = {}
        self.window_size = 60
        self.max_requests = 100

    def __call__(self, request: HttpRequest) -> HttpResponse:
        client_ip = self._get_client_ip(request)
        current_time = int(time.time())

        self._cleanup_old_entries(current_time)

        if not self._check_rate_limit(client_ip, current_time):
            logger.warning(f"Rate limit exceeded for IP {client_ip}")
            response = HttpResponse("Rate limit exceeded", status=429)
            response["Retry-After"] = str(self.window_size)
            response["X-RateLimit-Limit"] = str(self.max_requests)
            response["X-RateLimit-Remaining"] = "0"
            return response

        response = self.get_response(request)

        remaining = self.max_requests - self.request_counts.get(client_ip, 0)
        response["X-RateLimit-Limit"] = str(self.max_requests)
        response["X-RateLimit-Remaining"] = str(max(0, remaining))

        return response

    def _get_client_ip(self, request: HttpRequest) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "")

    def _cleanup_old_entries(self, current_time: int) -> None:
        cutoff = current_time - self.window_size
        self.request_counts = {
            ip: count
            for ip, (timestamp, count) in list(self.request_counts.items())
            if timestamp > cutoff
        }

    def _check_rate_limit(self, client_ip: str, current_time: int) -> bool:
        if client_ip not in self.request_counts:
            self.request_counts[client_ip] = [current_time, 1]
            return True

        timestamp, count = self.request_counts[client_ip]

        if current_time - timestamp > self.window_size:
            self.request_counts[client_ip] = [current_time, 1]
            return True

        if count >= self.max_requests:
            return False

        self.request_counts[client_ip][1] = count + 1
        return True
