from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.core.http_models import DetectionAlert
from src.security_engine.enforcement import (
    IPReputationRecord,
    ReputationConfig,
    evaluate_ip_reputation,
    positive_float_env,
    positive_int_env,
)
from src.security_engine.enforcement_service import EnforcementService
from src.security_engine.engine import SecurityEngine
from src.security_engine.repository import SecurityRepository
from src.security_engine.service import LogMonitorService

IP = "203.0.113.7"
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _alert(alert_id: int | None, offset_s: int = 0, **kw) -> dict:
    base = {
        "id": alert_id,
        "type": "path_probe",
        "severity": "medium",
        "status": "unresolved",
        "created_at": NOW + timedelta(seconds=offset_s),
        "metadata": {},
    }
    base.update(kw)
    return base


# --- evaluate_ip_reputation: incremental lifetime_score, older holds, cooldown expiry ---


def test_lifetime_score_incremental_monotonic_across_ticks_safe_and_aging():
    # Spaced > repeat_window_seconds (900s) so each path_probe contributes its exact base weight (12.0).
    a1 = _alert(1, offset_s=-4000)
    a2 = _alert(2, offset_s=-2000)
    a3 = _alert(3, offset_s=0, status="safe")

    r1 = evaluate_ip_reputation(IP, [a1], now=NOW)
    assert r1.lifetime_score == pytest.approx(12.0)
    assert r1.last_scored_alert_id == 1

    r2 = evaluate_ip_reputation(IP, [a1, a2], r1, now=NOW)
    assert r2.lifetime_score == pytest.approx(24.0)
    assert r2.last_scored_alert_id == 2

    # Alert 1 ages out of window and alert 2 is marked safe: lifetime_score stays monotonic.
    r3 = evaluate_ip_reputation(IP, [{**a2, "status": "safe"}], r2, now=NOW)
    assert r3.lifetime_score == pytest.approx(24.0)
    assert r3.last_scored_alert_id == 2

    # All prior alerts aged out; a brand-new safe alert still advances watermark & lifetime_score.
    r4 = evaluate_ip_reputation(IP, [], r3, now=NOW)
    assert r4.lifetime_score == pytest.approx(24.0)
    assert r4.last_scored_alert_id == 2

    r5 = evaluate_ip_reputation(IP, [a3], r4, now=NOW)
    assert r5.lifetime_score == pytest.approx(36.0)
    assert r5.last_scored_alert_id == 3


@pytest.mark.parametrize(
    ("prev_watermark", "row_id", "expected_lifetime", "expected_watermark"),
    [
        (None, 5, 50.0, 5),
        (3, None, 50.0, 3),
    ],
)
def test_lifetime_score_fallback_without_watermark_or_alert_id(
    prev_watermark, row_id, expected_lifetime, expected_watermark
):
    prev = IPReputationRecord(ip=IP, lifetime_score=50.0, last_scored_alert_id=prev_watermark)
    ev = evaluate_ip_reputation(IP, [_alert(row_id)], prev, now=NOW)
    assert ev.lifetime_score == pytest.approx(expected_lifetime)
    assert ev.last_scored_alert_id == expected_watermark


def test_older_hold_alert_ids_holds_block_with_zero_score_and_no_expiry():
    prev = IPReputationRecord(ip=IP, current_state="blocked", blocked_until=NOW + timedelta(seconds=600))
    ev = evaluate_ip_reputation(IP, [], prev, now=NOW, older_hold_alert_ids=[42])

    assert ev.current_state == "blocked"
    assert ev.alert_hold_active is True
    assert ev.blocked_until is None
    assert ev.blocked_reason == "alert_hold"
    assert ev.current_score == pytest.approx(0.0)
    assert ev.source_alert_ids == [42]


@pytest.mark.parametrize(
    "prev_kwargs",
    [
        {"analyst_override": "trusted"},
        {"whitelist": True},
        {"analyst_override": "force_unblock", "cooldown_until": NOW + timedelta(seconds=600)},
    ],
)
def test_older_hold_alert_ids_omitted_when_hold_inactive(prev_kwargs):
    prev = IPReputationRecord(ip=IP, **prev_kwargs)
    ev = evaluate_ip_reputation(IP, [], prev, now=NOW, older_hold_alert_ids=[42])

    assert ev.current_state != "blocked"
    assert ev.alert_hold_active is False
    assert 42 not in ev.source_alert_ids


def test_older_hold_alert_ids_on_manual_block_keeps_manual_reason():
    prev = IPReputationRecord(ip=IP, analyst_override="manual_block")
    ev_with_hold = evaluate_ip_reputation(IP, [], prev, now=NOW, older_hold_alert_ids=[42])
    assert ev_with_hold.current_state == "blocked"
    assert ev_with_hold.blocked_reason == "manual_block"
    assert ev_with_hold.reputation_reasons == ["manual_block_override"]
    assert ev_with_hold.alert_hold_active is True
    assert 42 in ev_with_hold.source_alert_ids

    ev_no_hold = evaluate_ip_reputation(IP, [], prev, now=NOW, older_hold_alert_ids=[])
    assert ev_no_hold.alert_hold_active is False
    assert ev_no_hold.source_alert_ids == []


@pytest.mark.parametrize(
    ("override", "expected_override"),
    [
        (None, None),
        ("suppress_auto_block", None),
        ("force_unblock", None),
        ("trusted", "trusted"),
        ("manual_block", "manual_block"),
    ],
)
def test_expired_cooldown_clears_to_none(override, expected_override):
    prev = IPReputationRecord(
        ip=IP,
        analyst_override=override,
        cooldown_until=NOW - timedelta(seconds=1),
    )
    ev = evaluate_ip_reputation(IP, [], prev, now=NOW)
    assert ev.cooldown_until is None
    assert ev.analyst_override == expected_override


# --- Config validation & fail-fast init ---


@pytest.mark.parametrize("bad", ["0", "-5", "abc", "1.5"])
def test_scoring_window_env_rejects_invalid(monkeypatch, bad):
    monkeypatch.setenv("REPUTATION_SCORING_WINDOW_SECONDS", bad)
    with pytest.raises(ValueError, match="REPUTATION_SCORING_WINDOW_SECONDS"):
        ReputationConfig()


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "nan", "inf", "-inf"])
def test_refresh_interval_env_rejects_invalid_before_engine_init(monkeypatch, bad):
    monkeypatch.setenv("REPUTATION_REFRESH_INTERVAL_SECONDS", bad)
    engine = MagicMock()
    with pytest.raises(ValueError, match="REPUTATION_REFRESH_INTERVAL_SECONDS"):
        LogMonitorService(engine=engine)
    engine.enforcement_service.initialize.assert_not_called()


def test_positive_env_helpers_accept_valid(monkeypatch):
    monkeypatch.setenv("TEST_POS_INT", "42")
    monkeypatch.setenv("TEST_POS_FLOAT", "2.5")
    assert positive_int_env("TEST_POS_INT", 1) == 42
    assert positive_float_env("TEST_POS_FLOAT", 1.0) == pytest.approx(2.5)


@pytest.mark.parametrize(
    "env",
    [
        {"DB_POOL_MIN_SIZE": "0"},
        {"DB_POOL_MIN_SIZE": "-1"},
        {"DB_POOL_MIN_SIZE": "abc"},
        {"DB_POOL_MAX_SIZE": "0"},
        {"DB_POOL_MAX_SIZE": "-2"},
        {"DB_POOL_MAX_SIZE": "abc"},
        {"DB_POOL_MIN_SIZE": "5", "DB_POOL_MAX_SIZE": "2"},
        {"DB_POOL_TIMEOUT_SECONDS": "0"},
        {"DB_POOL_TIMEOUT_SECONDS": "-0.5"},
        {"DB_POOL_TIMEOUT_SECONDS": "abc"},
        {"DB_POOL_TIMEOUT_SECONDS": "nan"},
        {"DB_POOL_TIMEOUT_SECONDS": "inf"},
        {"DB_POOL_TIMEOUT_SECONDS": "-inf"},
    ],
)
def test_repository_init_fails_fast_without_connecting(monkeypatch, env):
    for key in ("DB_POOL_MIN_SIZE", "DB_POOL_MAX_SIZE", "DB_POOL_TIMEOUT_SECONDS"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    with patch("src.security_engine.repository.ConnectionPool") as pool_cls:
        with pytest.raises(ValueError):
            SecurityRepository("postgresql://unused/db")
        pool_cls.assert_not_called()


# --- LogMonitorService: tick gating, guarded failure counters, run_forever ---


def test_maybe_refresh_reputations_gating():
    engine = MagicMock()
    svc = LogMonitorService(engine=engine)
    svc.refresh_interval_seconds = 30.0

    # monotonic_now=0.0 still runs on first tick (None vs 0.0 distinction).
    assert svc.maybe_refresh_reputations(monotonic_now=0.0, now=NOW) is True
    engine.enforcement_service.refresh_known_ip_states.assert_called_once_with(trigger_reason="engine_tick", now=NOW)

    assert svc.maybe_refresh_reputations(monotonic_now=29.9, now=NOW) is False
    assert engine.enforcement_service.refresh_known_ip_states.call_count == 1

    assert svc.maybe_refresh_reputations(monotonic_now=30.0, now=NOW) is True
    assert engine.enforcement_service.refresh_known_ip_states.call_count == 2


def test_refresh_reputations_guarded_tracks_tick_failures_separately():
    engine = MagicMock()
    svc = LogMonitorService(engine=engine)
    svc.refresh_interval_seconds = 0.0
    svc._consecutive_failures = svc.MAX_CONSECUTIVE_FAILURES - 1

    engine.enforcement_service.refresh_known_ip_states.side_effect = RuntimeError("db blip")
    for i in range(1, svc.MAX_CONSECUTIVE_FAILURES):
        svc._refresh_reputations_guarded()
        assert svc._consecutive_tick_failures == i
        assert svc._consecutive_failures == svc.MAX_CONSECUTIVE_FAILURES - 1

    # Skipped tick (ran=False) does not clear the streak.
    svc.maybe_refresh_reputations = lambda: False
    svc._refresh_reputations_guarded()
    assert svc._consecutive_tick_failures == svc.MAX_CONSECUTIVE_FAILURES - 1

    # A successful tick clears only _consecutive_tick_failures.
    svc.maybe_refresh_reputations = lambda: True
    svc._refresh_reputations_guarded()
    assert svc._consecutive_tick_failures == 0
    assert svc._consecutive_failures == svc.MAX_CONSECUTIVE_FAILURES - 1

    # Reaching MAX_CONSECUTIVE_FAILURES re-raises.
    svc.maybe_refresh_reputations = MagicMock(side_effect=RuntimeError("down"))
    for _ in range(svc.MAX_CONSECUTIVE_FAILURES - 1):
        svc._refresh_reputations_guarded()
    with pytest.raises(RuntimeError, match="down"):
        svc._refresh_reputations_guarded()


def test_run_forever_ticks_under_continuous_lines_and_closes_repo(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("line1\nline2\nline3\n", encoding="utf-8")

    engine = MagicMock()
    svc = LogMonitorService(engine=engine)
    svc.refresh_interval_seconds = 10.0
    svc._seek_to_end = lambda _stream: None  # read existing lines without hitting sleep

    processed = 0
    now_t = [0.0]

    def fake_process(_line):
        nonlocal processed
        processed += 1
        now_t[0] += 6.0
        if processed == 3:
            raise KeyboardInterrupt
        return MagicMock(), []

    svc.process_line = fake_process

    with (
        patch("src.security_engine.service.time.monotonic", side_effect=lambda: now_t[0]),
        patch("src.security_engine.service.time.sleep") as mock_sleep,
        pytest.raises(KeyboardInterrupt),
    ):
        svc.run_forever(str(log))

    # Ticked at t=0.0 and t=12.0 while processing continuous lines (never hit idle sleep).
    mock_sleep.assert_not_called()
    assert engine.enforcement_service.refresh_known_ip_states.call_count == 2
    engine.repository.close.assert_called_once()


# --- EnforcementService & SecurityEngine ---


def test_refresh_known_ip_states_continues_after_error_syncs_and_reraises_first():
    repo = MagicMock()
    repo.list_ips_needing_refresh.return_value = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    svc = EnforcementService(repository=repo, blocklist_manager=MagicMock())

    err1, err2 = RuntimeError("first"), ValueError("second")
    seen: list[str] = []

    def fake_recalc(ip, **_kw):
        seen.append(ip)
        if ip == "198.51.100.1":
            raise err1
        if ip == "198.51.100.3":
            raise err2
        return {"ip": ip}

    svc.recalculate_ip_reputation = fake_recalc
    svc.sync_blocklist = MagicMock()

    with pytest.raises(RuntimeError, match="first"):
        svc.refresh_known_ip_states(now=NOW)

    assert seen == ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    svc.sync_blocklist.assert_called_once()


def test_refresh_known_ip_states_syncs_blocklist_when_candidates_empty():
    repo = MagicMock()
    repo.list_ips_needing_refresh.return_value = []
    svc = EnforcementService(repository=repo, blocklist_manager=MagicMock())
    svc.sync_blocklist = MagicMock()

    assert svc.refresh_known_ip_states(now=NOW) == []
    svc.sync_blocklist.assert_called_once()


@pytest.mark.parametrize(
    ("unresolved", "malicious", "expected_snippet"),
    [
        (2, 1, "3 unresolved/malicious alert(s)"),
        (0, 0, "an older unresolved/malicious alert"),
    ],
)
def test_manual_unblock_ip_distinguishes_in_window_vs_older_hold(unresolved, malicious, expected_snippet):
    repo = MagicMock()

    @contextmanager
    def fake_tx(_ip):
        yield MagicMock()

    repo.ip_transaction = fake_tx
    repo.get_ip_reputation.return_value = {
        "ip": IP,
        "alert_hold_active": True,
        "unresolved_alert_count": unresolved,
        "malicious_alert_count": malicious,
    }
    svc = EnforcementService(repository=repo, blocklist_manager=MagicMock())

    with pytest.raises(ValueError, match=expected_snippet.replace("(", r"\(").replace(")", r"\)")):
        svc.manual_unblock_ip(IP)
    repo.set_ip_override_fields.assert_not_called()


def test_process_event_syncs_blocklist_in_finally_after_partial_ip_commit(make_http_event):
    repo = MagicMock()
    repo.insert_event.return_value = 10
    repo.insert_alert.side_effect = [101, 102]

    @contextmanager
    def fake_tx(_ip):
        yield MagicMock()

    repo.ip_transaction = fake_tx
    enforcement = MagicMock()

    def fail_on_second(ip, **_kw):
        if ip == "198.51.100.2":
            raise RuntimeError("boom")

    enforcement.recalculate_ip_reputation.side_effect = fail_on_second

    detector = MagicMock()
    detector.evaluate.return_value = [
        DetectionAlert(
            ip="198.51.100.1", endpoint="/", alert_type="payload_sqli", severity="high", timestamp=NOW, message="a"
        ),
        DetectionAlert(
            ip="198.51.100.2", endpoint="/", alert_type="payload_sqli", severity="high", timestamp=NOW, message="b"
        ),
    ]
    engine = SecurityEngine(repository=repo, enforcement_service=enforcement)
    engine.detectors = [detector]

    with pytest.raises(RuntimeError, match="boom"):
        engine.process_event(make_http_event())

    enforcement.sync_blocklist.assert_called_once()


def test_negative_alert_weight_never_decreases_lifetime_score():
    cfg = ReputationConfig(alert_weights={"neg_type": -25.0})
    prev_tracked = IPReputationRecord(ip=IP, lifetime_score=40.0, last_scored_alert_id=1)
    ev_tracked = evaluate_ip_reputation(
        IP,
        [_alert(2, type="neg_type")],
        prev_tracked,
        now=NOW,
        config=cfg,
    )
    assert ev_tracked.lifetime_score == pytest.approx(40.0)
    assert ev_tracked.last_scored_alert_id == 2

    ev_fresh = evaluate_ip_reputation(
        IP,
        [_alert(1, type="neg_type")],
        now=NOW,
        config=cfg,
    )
    assert ev_fresh.lifetime_score == pytest.approx(0.0)


def test_refresh_known_ip_states_forwards_none_now_for_in_lock_timestamp():
    repo = MagicMock()
    repo.list_ips_needing_refresh.return_value = ["198.51.100.9"]
    svc = EnforcementService(repository=repo, blocklist_manager=MagicMock())
    svc.recalculate_ip_reputation = MagicMock(return_value={"ip": "198.51.100.9"})
    svc.sync_blocklist = MagicMock()

    svc.refresh_known_ip_states(trigger_reason="engine_tick", now=None)

    svc.recalculate_ip_reputation.assert_called_once_with(
        "198.51.100.9",
        trigger_reason="engine_tick",
        manual_or_auto="auto",
        now=None,
    )


def test_serialize_blocked_ip_older_hold_not_unblock_eligible():
    from src.api.main import _serialize_blocked_ip

    base = {
        "ip": IP,
        "reputation_status": "blocked",
        "current_state": "blocked",
        "current_score": 0.0,
        "lifetime_score": 35.0,
        "alert_count": 1,
        "malicious_count": 0,
        "block_count": 1,
        "offense_streak": 0,
        "manual_blocked": False,
        "whitelist": False,
        "unresolved_alert_count": 0,
        "malicious_alert_count": 0,
        "safe_alert_count": 0,
        "total_alert_count": 0,
        "threshold_reached": False,
        "reputation_reasons": ["alert_hold"],
        "updated_at": NOW,
    }
    held = _serialize_blocked_ip({**base, "alert_hold_active": True})
    assert held.alert_hold_active is True
    assert held.unblock_eligible is False

    clear = _serialize_blocked_ip({**base, "alert_hold_active": False})
    assert clear.alert_hold_active is False
    assert clear.unblock_eligible is True


def test_assert_safe_test_db_requires_test_token(monkeypatch):
    from tests.integration import conftest as pg_conftest

    monkeypatch.delenv("ALLOW_TEST_DB_TRUNCATE", raising=False)
    current_db = {"name": "cybersiem_test"}

    @contextmanager
    def fake_connect(_url, **_kw):
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = (current_db["name"],)
        yield conn

    monkeypatch.setattr(pg_conftest.psycopg, "connect", fake_connect)

    for allowed in ("cybersiem_test", "test_cybersiem", "my-test-db", "TEST"):
        current_db["name"] = allowed
        pg_conftest._assert_safe_test_db("postgresql://unused")

    for rejected in ("cybersiem_latest", "cybersiem", "attestation", ""):
        current_db["name"] = rejected
        with pytest.raises(RuntimeError, match="Refusing to truncate database"):
            pg_conftest._assert_safe_test_db("postgresql://unused")

    current_db["name"] = "cybersiem_latest"
    monkeypatch.setenv("ALLOW_TEST_DB_TRUNCATE", "1")
    pg_conftest._assert_safe_test_db("postgresql://unused")
