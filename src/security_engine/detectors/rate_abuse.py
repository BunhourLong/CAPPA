from __future__ import annotations

import os
from collections import defaultdict, deque
from datetime import timedelta

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors.base import Detector, is_static_asset


def _positive_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError:
        return default
    return value if value > 0 else default


class RateAbuseDetector(Detector):
    def __init__(self, threshold: int | None = None, window_seconds: int | None = None) -> None:
        self.threshold = threshold or _positive_int_env("RATE_ABUSE_THRESHOLD", 30)
        self.window = timedelta(seconds=window_seconds or _positive_int_env("RATE_ABUSE_WINDOW_SECONDS", 60))
        self._events_by_ip: dict[str, deque] = defaultdict(deque)
        self._last_alert_at: dict[str, object] = {}

    def evaluate(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        if is_static_asset(event):
            return []

        history = self._events_by_ip[event.ip]
        history.append(event.timestamp)

        while history and event.timestamp - history[0] > self.window:
            history.popleft()

        if len(history) < self.threshold:
            return []

        last_alert_at = self._last_alert_at.get(event.ip)
        if last_alert_at and event.timestamp - last_alert_at <= self.window:
            return []

        self._last_alert_at[event.ip] = event.timestamp

        return [
            DetectionAlert(
                ip=event.ip,
                endpoint=event.endpoint,
                alert_type="rate_abuse",
                severity="medium",
                timestamp=event.timestamp,
                message=f"{len(history)} requests from {event.ip} within {int(self.window.total_seconds())} seconds",
                metadata={
                    "request_count": len(history),
                    "window_seconds": int(self.window.total_seconds()),
                },
            )
        ]
