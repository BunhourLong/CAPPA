from __future__ import annotations

import os
from collections import defaultdict, deque
from datetime import timedelta

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors.base import Detector, is_static_asset


def _positive_limit(name: str, override: int | None, default: int) -> int:
    raw_value = os.getenv(name, str(default)) if override is None else override
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


class RateAbuseDetector(Detector):
    def __init__(self, threshold: int | None = None, window_seconds: int | None = None) -> None:
        self.threshold = _positive_limit("RATE_ABUSE_THRESHOLD", threshold, 30)
        self.window = timedelta(seconds=_positive_limit("RATE_ABUSE_WINDOW_SECONDS", window_seconds, 60))
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
