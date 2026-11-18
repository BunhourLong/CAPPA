from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.core.http_models import HTTPLogEvent
from src.security_engine.detectors import build_detectors
from src.security_engine.detectors.base import is_static_asset
from src.security_engine.detectors.rate_abuse import RateAbuseDetector

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

# Filenames from a production build (`ng build`), including URL-safe hash characters.
ANGULAR_BUNDLES = (
    "/main-J4EPU54G.js",
    "/styles-7YWBOZPV.css",
    "/chunk-Q-Ed_POJ.js",
    "/siem/main-J4EPU54G.js",
    "/siem/styles-7YWBOZPV.css",
    "/siem/chunk-hvRrl_o-.js",
)


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


def _rate_abuse_alerts(events) -> list[str]:
    detector = RateAbuseDetector()
    return [alert.alert_type for event in events for alert in detector.evaluate(event)]


@pytest.mark.parametrize(
    "target",
    [
        "/main-4F3A9C2D.js",
        "/styles-8B1E7A3C.css",
        "/polyfills-2D6C4E8A.js",
        "/chunk-7A5B3C1D.js",
        "/chunk-Q-Ed_POJ.js",
        "/siem/main-4F3A9C2D.js",
        "/siem/styles-8B1E7A3C.css",
        "/siem/chunk-7A5B3C1D.js",
        "/siem/chunk-hvRrl_o-.js",
        "/siem/assets/main-4F3A9C2D.js",
        "/siem/favicon.ico",
        "/assets/icons/logo-4F3A9C2D.svg",
    ],
)
def test_successful_asset_gets_are_static(target):
    assert is_static_asset(_event(target))


@pytest.mark.parametrize(
    "target",
    [
        # Arbitrary root names and unhashed bundles are dynamic, not "any .js at root".
        "/main.js",
        "/dashboard-4F3A9C2D.js",
        # A server-side extension anywhere in the compound name counts as dynamic,
        # even inside an asset directory.
        "/assets/upload.php.js",
        "/siem/assets/upload.php.js",
        "/assets/upload.js.php",
        "/assets/config.json",
        "/api/v1/items.js",
        "/page/1.js",
        "/siem/api/ui/dashboard",
    ],
)
def test_ambiguous_or_dynamic_names_are_not_static(target):
    assert not is_static_asset(_event(target))


@pytest.mark.parametrize("status", [401, 404, 500, 503])
def test_missing_or_error_assets_are_not_static(status):
    assert not is_static_asset(_event("/assets/chunk-7A5B3C1D.js", status=status))


def test_static_asset_burst_does_not_alert_rate_abuse():
    detector = RateAbuseDetector()

    alerts = [alert for event in _burst("/assets/chunk.js", 105, seconds=180) for alert in detector.evaluate(event)]

    assert alerts == []


def test_asset_traffic_at_35_per_minute_for_three_minutes_does_not_alert():
    events: list[HTTPLogEvent] = []
    for index in range(105):
        at = NOW + timedelta(seconds=index * 180 / 105)
        events.append(_event(ANGULAR_BUNDLES[index % len(ANGULAR_BUNDLES)], at=at))
    for second in range(0, 180):
        at = NOW + timedelta(seconds=second)
        if second % 5 == 0:
            events.append(_event("/siem/api/ui/alerts", at=at))
        if second % 15 == 0:
            events.append(_event("/siem/api/ui/dashboard", at=at))
            events.append(_event("/siem/api/ui/map-points", at=at))
        if second in (0, 60, 120):
            events.append(_event("/siem/dashboard", at=at))

    events.sort(key=lambda event: event.timestamp)

    assert _replay(events) == []


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
    events = [
        _event("/siem/main-J4EPU54G.js", at=NOW),
        _event("/siem/styles-7YWBOZPV.css", at=NOW + timedelta(milliseconds=200)),
        _event("/siem/chunk-Q-Ed_POJ.js", at=NOW + timedelta(milliseconds=400)),
    ]
    for index, hash_ in enumerate(("7Jjctb_5", "hvRrl_o-", "CpbL28yq", "CnDaF4xU", "OS0PYAiU", "DLfYRnLg")):
        events.append(_event(f"/siem/chunk-{hash_}.js", at=NOW + timedelta(milliseconds=600 + index * 80)))
    events += [
        _event("/siem/login", at=NOW + timedelta(milliseconds=900)),
        _event("/siem/dashboard", at=NOW + timedelta(milliseconds=950)),
        _event("/siem/alerts", at=NOW + timedelta(seconds=1)),
    ]

    for second in range(0, 300):
        at = NOW + timedelta(seconds=second)
        if second % 5 == 0:
            events.append(_event("/siem/api/ui/alerts", at=at))
        if second % 15 == 0:
            events.append(_event("/siem/api/ui/dashboard", at=at))
            events.append(_event("/siem/api/ui/map-points", at=at))

    events.sort(key=lambda event: event.timestamp)

    assert _replay(events) == []


def test_dynamic_burst_at_300_per_minute_still_alerts():
    alerts = _replay(_burst("/api/v1/catalog", 300, seconds=60))

    assert [alert.alert_type for alert in alerts if alert.alert_type == "rate_abuse"]


def test_missing_assets_still_count_for_path_probe_and_rate_abuse():
    events = [
        _event(f"/assets/chunk-{index:08X}.js", at=NOW + timedelta(seconds=index), status=404) for index in range(30)
    ]

    assert {"404_spray", "rate_abuse"} <= {alert.alert_type for alert in _replay(events)}


def test_error_assets_still_count_for_rate_abuse():
    assert _rate_abuse_alerts(_burst("/assets/chunk-7A5B3C1D.js", 30, seconds=30, status=503)) == ["rate_abuse"]


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
    assert _rate_abuse_alerts(_burst(target, 30, seconds=30)) == ["rate_abuse"]


@pytest.mark.parametrize(
    "target",
    [
        "/assets/upload.php.js",
        "/siem/assets/upload.php.js",
        "/assets/upload.js.php",
        "/assets/config.json",
    ],
)
def test_compound_server_side_asset_names_still_count(target):
    assert _rate_abuse_alerts(_burst(target, 30, seconds=30)) == ["rate_abuse"]


def test_post_to_a_static_asset_path_still_counts():
    assert _rate_abuse_alerts(_burst("/assets/upload.js", 30, seconds=30, method="POST")) == ["rate_abuse"]


def test_scraping_still_detects_dynamic_enumeration():
    events = [_event(f"/page/{index}", at=NOW + timedelta(seconds=index)) for index in range(50)]
    alerts = _replay(events)

    assert "scraping" in {alert.alert_type for alert in alerts}


def test_rate_limits_default_to_30_requests_in_60_seconds(monkeypatch):
    monkeypatch.delenv("RATE_ABUSE_THRESHOLD", raising=False)
    monkeypatch.delenv("RATE_ABUSE_WINDOW_SECONDS", raising=False)

    detector = RateAbuseDetector()

    assert detector.threshold == 30
    assert detector.window == timedelta(seconds=60)


def test_rate_limits_are_configurable_through_the_environment(monkeypatch):
    monkeypatch.setenv("RATE_ABUSE_THRESHOLD", "5")
    monkeypatch.setenv("RATE_ABUSE_WINDOW_SECONDS", "10")

    alerts = _replay(_burst("/api/v1/catalog", 5, seconds=10))

    assert [alert.alert_type for alert in alerts] == ["rate_abuse"]


@pytest.mark.parametrize("name", ["RATE_ABUSE_THRESHOLD", "RATE_ABUSE_WINDOW_SECONDS"])
@pytest.mark.parametrize("value", ["typo", "0", "-1", ""])
def test_invalid_rate_limits_fail_detector_startup(monkeypatch, name, value):
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match=name):
        build_detectors()
