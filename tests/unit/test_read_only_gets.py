"""Invariant 7: GET routes never write — no repository writes, no enforcement side effects.

Reputation decay/expiry belongs to the engine tick, not to page views.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from unittest.mock import create_autospec

from fastapi.routing import APIRoute

from src.api.auth import create_session_cookie
from src.security_engine.enforcement_service import EnforcementService

# Repository method-name prefixes that only read. Anything else a GET triggers is a write.
READ_ONLY_PREFIXES = ("get_", "list_", "count_", "fetch_")

# Mirrors ALERT_WITH_REPUTATION_SELECT so /alerts/{id} exercises its full serialize path.
FAKE_ALERT = {
    "id": 1,
    "event_id": 1,
    "ip": "203.0.113.7",
    "endpoint": "/",
    "type": "xss",
    "severity": "medium",
    "status": "unresolved",
    "message": "test alert",
    "metadata": {},
    "created_at": datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
    "updated_at": None,
    "confidence": 50,
    "reputation_status": "unknown",
    "current_state": "unknown",
    "current_score": 10.0,
    "lifetime_score": 10.0,
    "alert_count": 1,
    "malicious_count": 0,
    "block_count": 0,
    "offense_streak": 1,
    "last_seen": None,
    "last_alert_at": datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
    "blocked_until": None,
    "cooldown_until": None,
    "whitelist": False,
    "analyst_override": None,
    "blocked_reason": None,
    "manual_blocked": False,
    "threshold_reached": False,
    "total_alert_count": 1,
    "safe_alert_count": 0,
    "unresolved_alert_count": 1,
    "malicious_alert_count": 0,
    "alert_hold_active": False,
    "reputation_reasons": [],
}


def _get_paths():
    from src.api.main import app

    paths = sorted(
        route.path
        for route in app.routes
        if isinstance(route, APIRoute) and "GET" in route.methods - {"HEAD", "OPTIONS"}
    )
    assert paths, "no GET routes found"
    # Any path parameter becomes "1": /alerts/{alert_id} -> /alerts/1.
    return [re.sub(r"\{[^}]+\}", "1", path) for path in paths]


def test_get_routes_write_nothing(api_client, fake_repository, monkeypatch, tmp_path):
    from src.api import main

    # The UI build is a deployment concern, not part of this invariant: serve a stub shell
    # so the SPA routes return 200 instead of the "not built" 503.
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    monkeypatch.setattr(main, "FRONTEND_DIST_DIR", tmp_path)

    fake_repository.get_user_by_id.return_value = {"id": 1, "username": "u", "role": "admin", "is_active": True}
    fake_repository.get_alert.return_value = dict(FAKE_ALERT)
    fake_repository.count_ip_states.return_value = {}
    fake_repository.list_recent_reputation_transitions.return_value = []
    fake_repository.get_distinct_alert_types.return_value = []
    api_client.cookies.set("siem_session", create_session_cookie(1, os.environ["SESSION_SECRET"]))

    enforcement = create_autospec(EnforcementService, instance=True)
    monkeypatch.setattr(main, "enforcement_service", enforcement)

    problems = []
    for path in _get_paths():
        repo_calls_before = len(fake_repository.mock_calls)
        enforcement_calls_before = len(enforcement.mock_calls)
        response = api_client.get(path, headers={"accept": "*/*"})
        repo_names = {str(call[0]) for call in fake_repository.mock_calls[repo_calls_before:]}
        writes = sorted(name for name in repo_names if not name.startswith(READ_ONLY_PREFIXES))
        enforcement_calls = enforcement.mock_calls[enforcement_calls_before:]
        if writes or enforcement_calls or response.status_code >= 400:
            problems.append(
                f"GET {path} -> {response.status_code}: repository={writes} enforcement={enforcement_calls}"
            )

    assert not problems, "\n".join(problems)
