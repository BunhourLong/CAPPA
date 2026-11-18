from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.core.http_models import HTTPLogEvent
from src.security_engine.detectors import build_detectors
from src.security_engine.detectors.rate_abuse import RateAbuseDetector

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _event(
    target: str,
    *,
    at: datetime = NOW,
    method: str = "GET",
    ip: str = "203.0.113.7",
    status: int = 200,
    ua: str = "Mozilla/5.0",
) -> HTTPLogEvent:
    head, sep, tail = target.partition("?")
    return HTTPLogEvent(
        timestamp=at,
        ip=ip,
        method=method,
        endpoint=head,
        status_code=status,
        user_agent=ua,
        request_target=target,
        raw_line="",
        query=tail if sep else "",
    )


def _replay(events):
    detectors = build_detectors()
    alerts = []
    for event in events:
        for detector in detectors:
            alerts.extend(detector.evaluate(event))
    return alerts


def _burst(target: str, count: int, *, seconds: int, **kwargs) -> list[HTTPLogEvent]:
    return [_event(target, at=NOW + timedelta(seconds=i * seconds / count), **kwargs) for i in range(count)]


def test_static_asset_burst_does_not_alert_rate_abuse():
    detector = RateAbuseDetector()

    alerts = [alert for event in _burst("/assets/chunk.js", 105, seconds=180) for alert in detector.evaluate(event)]

    assert alerts == []


def test_ordinary_page_loads_do_not_alert_any_detector():
    events: list[HTTPLogEvent] = []
    for page in range(2):
        start = NOW + timedelta(seconds=page * 40)
        events.append(_event(f"/products?page={page}", at=start))
        for index in range(55):
            events.append(_event(f"/assets/chunk-{index}.js", at=start + timedelta(seconds=index * 0.4)))
        events.append(_event(f"/products/{page}", at=start + timedelta(seconds=30)))

    assert _replay(events) == []


def test_single_dashboard_session_does_not_alert_any_detector():
    events = [_event(f"/siem/assets/main-{index}.js", at=NOW + timedelta(seconds=index * 0.1)) for index in range(20)]

    for second in range(0, 300):
        if second % 5 == 0:
            events.append(_event("/siem/api/ui/alerts", at=NOW + timedelta(seconds=second)))
        if second % 15 == 0:
            events.append(_event("/siem/api/ui/dashboard", at=NOW + timedelta(seconds=second)))
            events.append(_event("/siem/api/ui/map-points", at=NOW + timedelta(seconds=second)))

    assert _replay(events) == []


def test_dynamic_burst_at_300_per_minute_still_alerts():
    alerts = _replay(_burst("/api/v1/catalog", 300, seconds=60))

    assert [alert.alert_type for alert in alerts if alert.alert_type == "rate_abuse"]


@pytest.mark.parametrize(
    "target",
    [
        "/api/v1/items.js",
        "/page/1.js",
        "/static/../api/v1/items",
        "/assets/../api/v1/items",
    ],
)
def test_static_suffix_or_directory_does_not_exempt_a_dynamic_endpoint(target):
    detector = RateAbuseDetector()

    alerts = [alert for event in _burst(target, 30, seconds=30) for alert in detector.evaluate(event)]

    assert [alert.alert_type for alert in alerts] == ["rate_abuse"]


def test_post_to_a_static_asset_path_still_counts():
    detector = RateAbuseDetector()

    alerts = [
        alert
        for event in _burst("/assets/upload.js", 30, seconds=30, method="POST")
        for alert in detector.evaluate(event)
    ]

    assert [alert.alert_type for alert in alerts] == ["rate_abuse"]


def test_scraping_still_detects_dynamic_enumeration():
    events = [_event(f"/page/{index}", at=NOW + timedelta(seconds=index)) for index in range(50)]
    alerts = _replay(events)

    assert "scraping" in {alert.alert_type for alert in alerts}


def test_rate_limits_are_configurable_through_the_environment(monkeypatch):
    monkeypatch.setenv("RATE_ABUSE_THRESHOLD", "5")
    monkeypatch.setenv("RATE_ABUSE_WINDOW_SECONDS", "10")

    alerts = _replay(_burst("/api/v1/catalog", 5, seconds=10))

    assert [alert.alert_type for alert in alerts] == ["rate_abuse"]
