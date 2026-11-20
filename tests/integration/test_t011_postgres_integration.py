from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from functools import partial

import psycopg
import pytest
from psycopg import sql
from psycopg_pool import PoolTimeout

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors.payload import PayloadDetector
from src.security_engine.enforcement import (
    NginxBlocklistManager,
    ReputationConfig,
    evaluate_ip_reputation,
    utc_now,
)
from src.security_engine.enforcement_service import EnforcementService
from src.security_engine.engine import SecurityEngine
from src.security_engine.repository import SecurityRepository
from src.security_engine.service import LogMonitorService
from tests.integration.conftest import TRUNCATE_SQL


def _sqli_event(ip: str, ts: datetime) -> HTTPLogEvent:
    return HTTPLogEvent(
        timestamp=ts,
        ip=ip,
        method="GET",
        endpoint="/search",
        status_code=200,
        user_agent="pytest",
        request_target="/search?q=1+or+1=1",
        raw_line=f'{ip} - - "GET /search?q=1+or+1=1 HTTP/1.1" 200 0',
    )


def _plan_stats(node: dict) -> tuple[int, list[str]]:
    loops = int(node.get("Actual Loops", 1))
    rows = (
        int(node.get("Actual Rows", 0))
        + int(node.get("Rows Removed by Filter", 0))
        + int(node.get("Rows Removed by Index Recheck", 0))
    ) * loops
    types = [str(node.get("Node Type", ""))]
    for child in node.get("Plans", ()):
        child_rows, child_types = _plan_stats(child)
        rows += child_rows
        types.extend(child_types)
    return rows, types


def _run_gated(pg_url: str, tasks: list) -> list:
    """Block all workers on an ACCESS EXCLUSIVE table lock, verify >=N wait in pg_stat_activity, then release."""
    n = len(tasks)
    gate = psycopg.connect(pg_url, autocommit=False)
    observer = psycopg.connect(pg_url, autocommit=True)
    gate_pid = gate.info.backend_pid
    obs_pid = observer.info.backend_pid
    start_barrier = threading.Barrier(n + 1)

    def _wrapped(fn):
        start_barrier.wait(timeout=10.0)
        return fn()

    try:
        gate.execute("BEGIN")
        gate.execute("LOCK TABLE events, alerts, ip_reputations IN ACCESS EXCLUSIVE MODE")

        with ThreadPoolExecutor(max_workers=n) as pool:
            gate_released = False
            try:
                futures = [pool.submit(_wrapped, task) for task in tasks]
                start_barrier.wait(timeout=10.0)

                deadline = time.monotonic() + 10.0
                waiting = 0
                while time.monotonic() < deadline:
                    row = observer.execute(
                        """
                        SELECT COUNT(*)
                        FROM pg_stat_activity
                        WHERE datname = current_database()
                          AND pid NOT IN (%s, %s)
                          AND wait_event_type = 'Lock'
                        """,
                        (gate_pid, obs_pid),
                    ).fetchone()
                    waiting = int(row[0]) if row else 0
                    if waiting >= n:
                        break
                    time.sleep(0.02)

                if waiting < n:
                    dump = observer.execute(
                        """
                        SELECT pid, state, wait_event_type, wait_event, left(query, 80)
                        FROM pg_stat_activity
                        WHERE datname = current_database() AND pid NOT IN (%s, %s)
                        """,
                        (gate_pid, obs_pid),
                    ).fetchall()
                    pytest.fail(f"Expected >= {n} workers waiting on Lock, saw {waiting}: {dump}")

                gate.commit()
                gate_released = True
                return [f.result(timeout=30.0) for f in futures]
            finally:
                start_barrier.abort()
                if not gate_released and not gate.closed:
                    gate.rollback()
    finally:
        if not gate.closed:
            gate.rollback()
            gate.close()
        if not observer.closed:
            observer.close()


# --- 1. Bounded pool & idempotent close ---


def test_bounded_pool_enforces_max_size_timeout_and_idempotent_close(pg_url, monkeypatch):
    monkeypatch.setenv("DB_POOL_MIN_SIZE", "1")
    monkeypatch.setenv("DB_POOL_MAX_SIZE", "2")
    monkeypatch.setenv("DB_POOL_TIMEOUT_SECONDS", "0.4")

    repo = SecurityRepository(pg_url)
    try:
        with repo.connection() as c1, repo.connection() as c2:
            assert c1.execute("SELECT 1 AS n").fetchone()["n"] == 1
            assert c2.execute("SELECT 1 AS n").fetchone()["n"] == 1
            with pytest.raises(PoolTimeout):
                with repo.connection():
                    pass

        # Released connection allows checkout again.
        with repo.connection() as c3:
            assert c3.execute("SELECT 2 AS n").fetchone()["n"] == 2
    finally:
        repo.close()
        repo.close()  # idempotent


# --- 2. 10k old alerts, monotonic lifetime_score, older hold lifecycle, SQL/Python parity, backfill ---


def test_bounded_window_10k_old_alerts_monotonic_lifetime_and_older_hold(pg_repo, blocklist_manager):
    now = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    cfg = ReputationConfig(scoring_window_seconds=86400)
    svc = EnforcementService(repository=pg_repo, blocklist_manager=blocklist_manager, config=cfg)

    ip = "198.51.100.10"
    old_ts = now - timedelta(days=3)
    with pg_repo.connection() as conn:
        with conn.cursor() as cur:
            with cur.copy("COPY alerts (ip, endpoint, type, severity, status, message, created_at) FROM STDIN") as copy:
                for _ in range(10_000):
                    copy.write_row((ip, "/", "path_probe", "medium", "unresolved", "old", old_ts))
            cur.execute("ANALYZE alerts")
        conn.commit()

    cutoff = now - timedelta(seconds=cfg.scoring_window_seconds)

    # Generic-plan regression: 10k old alerts, 0 in-window -> forced generic plan & repeated
    # prepared calls must scan 0 rows and never Seq Scan.
    with pg_repo.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SET LOCAL plan_cache_mode = force_generic_plan")
            for _ in range(7):
                assert pg_repo.list_alert_rows_for_ip(ip, since=cutoff, conn=conn) == []
            alert_query, alert_params = pg_repo._alert_rows_query(ip, cutoff)
            prepared_sql = alert_query.as_string(conn)
            for idx in range(1, len(alert_params) + 1):
                prepared_sql = prepared_sql.replace("%s", f"${idx}", 1)
            cur.execute(f"PREPARE t011_alert_rows_plan AS {prepared_sql}")
            cur.execute(
                sql.SQL("EXPLAIN (ANALYZE, FORMAT JSON) EXECUTE t011_alert_rows_plan({}, {})").format(
                    sql.Literal(ip), sql.Literal(cutoff)
                )
            )
            alert_plan_doc = cur.fetchone()["QUERY PLAN"]
            cur.execute("DEALLOCATE t011_alert_rows_plan")
        conn.rollback()
    alert_scanned, alert_nodes = _plan_stats(alert_plan_doc[0]["Plan"])
    assert "Seq Scan" not in alert_nodes
    assert alert_scanned == 0

    in_window_id = pg_repo.insert_alert(
        DetectionAlert(
            ip=ip,
            endpoint="/admin",
            alert_type="path_probe",
            severity="medium",
            timestamp=now - timedelta(minutes=5),
            message="in window",
        )
    )

    rows = pg_repo.list_alert_rows_for_ip(ip, since=cutoff)
    assert len(rows) == 1
    assert rows[0]["id"] == in_window_id

    # Older-hold lookup must return [] with bounded skip-scan rows (no Seq Scan) under BOTH
    # default config and custom severity weights where medium >= ALERT_HOLD_MIN_WEIGHT.
    for hold_cfg in (
        cfg,
        ReputationConfig(
            scoring_window_seconds=86400,
            severity_weights={"high": 18.0, "medium": 20.0, "low": 6.0},
        ),
    ):
        hold_svc = EnforcementService(repository=pg_repo, blocklist_manager=blocklist_manager, config=hold_cfg)
        hold_types, hold_sevs, non_hold_types, known_sevs, default_holds = hold_svc._hold_query_params()
        assert (
            pg_repo.list_older_hold_alert_ids(
                ip,
                before=cutoff,
                hold_types=hold_types,
                hold_severities=hold_sevs,
                non_hold_types=non_hold_types,
                known_severities=known_sevs,
                default_severity_holds=default_holds,
            )
            == []
        )
        query, params = pg_repo._older_hold_query(
            ip,
            before=cutoff,
            hold_types=hold_types,
            hold_severities=hold_sevs,
            non_hold_types=non_hold_types,
            known_severities=known_sevs,
            default_severity_holds=default_holds,
        )
        with pg_repo.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql.SQL("EXPLAIN (ANALYZE, FORMAT JSON) ") + query, params)
                plan_doc = cur.fetchone()["QUERY PLAN"]
        scanned_rows, node_types = _plan_stats(plan_doc[0]["Plan"])
        assert "Seq Scan" not in node_types
        assert scanned_rows <= 20

    rec1 = svc.recalculate_ip_reputation(ip, now=now)
    assert rec1["lifetime_score"] == pytest.approx(12.0)
    assert rec1["last_scored_alert_id"] == in_window_id
    assert rec1["alert_hold_active"] is False

    # After the in-window alert ages out, current_score drops to 0 while lifetime_score stays monotonic.
    later = now + timedelta(days=2)
    rec2 = svc.recalculate_ip_reputation(ip, now=later)
    assert rec2["current_score"] == pytest.approx(0.0)
    assert rec2["lifetime_score"] == pytest.approx(12.0)
    assert rec2["last_scored_alert_id"] == in_window_id

    # A new alert strictly advances lifetime_score without re-scoring the 10k old rows.
    newer_id = pg_repo.insert_alert(
        DetectionAlert(
            ip=ip,
            endpoint="/admin",
            alert_type="path_probe",
            severity="medium",
            timestamp=later,
            message="newer",
        )
    )
    rec3 = svc.recalculate_ip_reputation(ip, now=later)
    assert rec3["lifetime_score"] == pytest.approx(24.0)
    assert rec3["last_scored_alert_id"] == newer_id

    # Old unresolved high alert holds block with zero current_score, blocks manual_unblock_ip, releases on safe.
    hold_ip = "198.51.100.11"
    old_high_id = pg_repo.insert_alert(
        DetectionAlert(
            ip=hold_ip,
            endpoint="/login",
            alert_type="payload_sqli",
            severity="high",
            timestamp=now - timedelta(days=3),
            message="old high",
        )
    )
    held = svc.sync_ip_and_blocklist(hold_ip, now=now)
    assert held["current_state"] == "blocked"
    assert held["alert_hold_active"] is True
    assert held["blocked_until"] is None
    assert held["current_score"] == pytest.approx(0.0)
    transitions = pg_repo.list_recent_reputation_transitions(limit=5, ip=hold_ip)
    assert transitions and old_high_id in transitions[0]["source_alert_ids"]

    with pytest.raises(ValueError, match="an older unresolved/malicious alert"):
        svc.manual_unblock_ip(hold_ip)

    svc.update_alert_status(old_high_id, "safe")
    released = pg_repo.get_ip_reputation(hold_ip)
    assert released["current_state"] == "trusted"
    assert released["alert_hold_active"] is False
    assert hold_ip not in blocklist_manager.blocklist_path.read_text(encoding="utf-8")


def test_list_older_hold_alert_ids_sql_python_parity(pg_repo, blocklist_manager):
    now = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    cutoff = now - timedelta(hours=24)
    old_ts = cutoff - timedelta(hours=1)

    configs = [
        ReputationConfig(),  # default: medium=10 (<20)
        ReputationConfig(severity_weights={"high": 18.0, "medium": 20.0, "low": 6.0}),  # custom medium>=20
    ]
    cases = [
        ("payload_sqli", "low", "unresolved"),  # explicit hold type
        ("rate_abuse", "high", "unresolved"),  # explicit non-hold type, severity=high
        ("rate_abuse", "medium", "unresolved"),  # explicit non-hold type overrides custom medium>=20
        ("untyped_alert", "high", "malicious"),
        ("untyped_alert", "medium", "unresolved"),
        ("untyped_alert", "low", "unresolved"),
        ("untyped_alert", "weird", "unresolved"),  # unknown severity falls back to medium
        ("untyped_alert", "weird", "safe"),  # safe never holds
    ]

    for cfg_idx, cfg in enumerate(configs):
        svc = EnforcementService(repository=pg_repo, blocklist_manager=blocklist_manager, config=cfg)
        hold_types, hold_sevs, non_hold_types, known_sevs, default_holds = svc._hold_query_params()

        for case_idx, (alert_type, severity, status) in enumerate(cases):
            ip = f"198.51.{cfg_idx + 20}.{case_idx + 1}"
            aid = pg_repo.insert_alert(
                DetectionAlert(
                    ip=ip,
                    endpoint="/",
                    alert_type=alert_type,
                    severity=severity,
                    status=status,
                    timestamp=old_ts,
                    message="parity",
                )
            )
            sql_holds = bool(
                pg_repo.list_older_hold_alert_ids(
                    ip,
                    before=cutoff,
                    hold_types=hold_types,
                    hold_severities=hold_sevs,
                    non_hold_types=non_hold_types,
                    known_severities=known_sevs,
                    default_severity_holds=default_holds,
                )
            )
            py_holds = evaluate_ip_reputation(
                ip,
                [{"id": aid, "type": alert_type, "severity": severity, "status": status, "created_at": old_ts}],
                config=cfg,
                now=now,
            ).alert_hold_active
            assert sql_holds is py_holds, f"Mismatch for cfg={cfg_idx} case={(alert_type, severity, status)}"


def test_ensure_schema_backfills_null_watermarks_once_without_overwriting_live(pg_repo, pg_url, blocklist_manager):
    now = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    ip_null = "198.51.100.30"
    ip_live = "198.51.100.31"
    ip_empty = "198.51.100.32"
    ip_no_last = "198.51.100.33"
    ip_out_of_order = "198.51.100.34"
    ip_bulk_deleted = "198.51.100.35"

    a1 = pg_repo.insert_alert(
        DetectionAlert(
            ip=ip_null,
            endpoint="/",
            alert_type="path_probe",
            severity="medium",
            timestamp=now - timedelta(minutes=5),
            message="1",
        )
    )
    a2 = pg_repo.insert_alert(
        DetectionAlert(ip=ip_null, endpoint="/", alert_type="path_probe", severity="medium", timestamp=now, message="2")
    )
    # Unscored alert arriving after last_alert_at must stay above the backfilled watermark.
    pg_repo.insert_alert(
        DetectionAlert(
            ip=ip_null,
            endpoint="/",
            alert_type="path_probe",
            severity="medium",
            timestamp=now + timedelta(minutes=1),
            message="unscored",
        )
    )
    b1 = pg_repo.insert_alert(
        DetectionAlert(ip=ip_live, endpoint="/", alert_type="path_probe", severity="medium", timestamp=now, message="3")
    )
    pg_repo.insert_alert(
        DetectionAlert(ip=ip_live, endpoint="/", alert_type="path_probe", severity="medium", timestamp=now, message="4")
    )
    pg_repo.insert_alert(
        DetectionAlert(
            ip=ip_no_last, endpoint="/", alert_type="path_probe", severity="medium", timestamp=now, message="unscored-2"
        )
    )
    o1 = pg_repo.insert_alert(
        DetectionAlert(
            ip=ip_out_of_order,
            endpoint="/",
            alert_type="path_probe",
            severity="medium",
            timestamp=now - timedelta(minutes=5),
            message="o1",
        )
    )
    o2 = pg_repo.insert_alert(
        DetectionAlert(
            ip=ip_out_of_order,
            endpoint="/",
            alert_type="path_probe",
            severity="medium",
            timestamp=now,
            message="o2",
        )
    )
    # Higher-ID unscored alert with an EARLIER created_at than last_alert_at must not be swallowed.
    o_earlier_unscored = pg_repo.insert_alert(
        DetectionAlert(
            ip=ip_out_of_order,
            endpoint="/",
            alert_type="path_probe",
            severity="medium",
            timestamp=now - timedelta(minutes=2),
            message="o-earlier-unscored",
        )
    )
    # Legacy bulk-delete left fewer alerts <= last_alert_at than total_alert_count; backdated unscored alert must not be skipped.
    bd_unscored = pg_repo.insert_alert(
        DetectionAlert(
            ip=ip_bulk_deleted,
            endpoint="/",
            alert_type="path_probe",
            severity="medium",
            timestamp=now - timedelta(minutes=2),
            message="bd-unscored",
        )
    )

    with pg_repo.connection() as conn:
        conn.execute(
            """
            INSERT INTO ip_reputations (
                ip, last_alert_at, last_scored_alert_id, total_alert_count, alert_count, lifetime_score
            )
            VALUES
                (%s, %s, NULL, 2, 2, 24.0),
                (%s, %s, %s, 2, 2, 24.0),
                (%s, NULL, NULL, 0, 0, 0.0),
                (%s, NULL, NULL, 0, 0, 0.0),
                (%s, %s, NULL, 2, 2, 24.0),
                (%s, %s, NULL, 2, 2, 24.0)
            """,
            (ip_null, now, ip_live, now, b1, ip_empty, ip_no_last, ip_out_of_order, now, ip_bulk_deleted, now),
        )
        conn.commit()

    # Warm ensure_schema() must take zero ALTER TABLE / CREATE INDEX locks.
    with psycopg.connect(pg_url, autocommit=False) as blocker:
        blocker.execute("BEGIN")
        blocker.execute("LOCK TABLE ip_reputations, alerts IN ROW EXCLUSIVE MODE")
        pg_repo.ensure_schema()
        blocker.rollback()

    assert pg_repo.get_ip_reputation(ip_null)["last_scored_alert_id"] == max(a1, a2)
    assert pg_repo.get_ip_reputation(ip_live)["last_scored_alert_id"] == b1
    assert pg_repo.get_ip_reputation(ip_empty)["last_scored_alert_id"] == 0
    assert pg_repo.get_ip_reputation(ip_no_last)["last_scored_alert_id"] == 0
    assert pg_repo.get_ip_reputation(ip_out_of_order)["last_scored_alert_id"] == max(o1, o2)
    assert pg_repo.get_ip_reputation(ip_bulk_deleted)["last_scored_alert_id"] == 0
    assert o_earlier_unscored > max(o1, o2)

    # Next recalculation must score the unscored higher-ID alert with the earlier timestamp
    # and the backdated alert on the post-bulk-delete IP.
    svc = EnforcementService(repository=pg_repo, blocklist_manager=blocklist_manager, config=ReputationConfig())
    rec = svc.recalculate_ip_reputation(ip_out_of_order, now=now + timedelta(minutes=1))
    assert rec["last_scored_alert_id"] == o_earlier_unscored
    assert rec["lifetime_score"] > 24.0

    rec_bd = svc.recalculate_ip_reputation(ip_bulk_deleted, now=now + timedelta(minutes=1))
    assert rec_bd["last_scored_alert_id"] == bd_unscored
    assert rec_bd["lifetime_score"] > 24.0

    # New alert + second ensure_schema() must not overwrite the now-populated watermark.
    pg_repo.insert_alert(
        DetectionAlert(ip=ip_null, endpoint="/", alert_type="path_probe", severity="medium", timestamp=now, message="5")
    )
    pg_repo.ensure_schema()
    assert pg_repo.get_ip_reputation(ip_null)["last_scored_alert_id"] == max(a1, a2)


def test_ensure_schema_serializes_with_advisory_lock_and_commits_per_ddl(pg_repo, pg_url):
    # Drop one index on ip_reputations and one on alerts so ensure_schema() must run DDL on both.
    with pg_repo.connection() as conn:
        conn.execute("DROP INDEX idx_ip_reputations_blocked_until")
        conn.execute("DROP INDEX idx_alerts_hold_lookup")
        conn.commit()

    # Hold ROW EXCLUSIVE on alerts while ensure_schema() runs: ip_reputations DDL must commit
    # before alerts DDL starts, so the alerts holder can lock ip_reputations NOWAIT without deadlock.
    with (
        psycopg.connect(pg_url, autocommit=False) as blocker,
        psycopg.connect(pg_url, autocommit=True) as observer,
    ):
        blocker.execute("BEGIN")
        blocker.execute("LOCK TABLE alerts IN ROW EXCLUSIVE MODE")
        blocker_pid = blocker.info.backend_pid
        obs_pid = observer.info.backend_pid

        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(pg_repo.ensure_schema)
            try:
                deadline = time.monotonic() + 10.0
                waiting_on_alerts = False
                while time.monotonic() < deadline:
                    row = observer.execute(
                        """
                        SELECT COUNT(*)
                        FROM pg_stat_activity
                        WHERE datname = current_database()
                          AND pid NOT IN (%s, %s)
                          AND wait_event_type = 'Lock'
                          AND query LIKE '%%idx_alerts_hold_lookup%%'
                        """,
                        (blocker_pid, obs_pid),
                    ).fetchone()
                    if row and int(row[0]) >= 1:
                        waiting_on_alerts = True
                        break
                    time.sleep(0.02)

                assert waiting_on_alerts, "ensure_schema() did not block on alerts index DDL as expected"
                # Proves ip_reputations DDL already committed and released its lock before alerts DDL ran.
                blocker.execute("LOCK TABLE ip_reputations IN ROW EXCLUSIVE MODE NOWAIT")
                idx_row = blocker.execute(
                    "SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'idx_ip_reputations_blocked_until'"
                ).fetchone()
                assert idx_row is not None
                blocker.rollback()
                fut.result(timeout=10.0)
            finally:
                blocker.rollback()

        # Advisory lock must serialize concurrent ensure_schema() and always be released afterwards.
        blocker.execute("SELECT pg_advisory_lock(hashtextextended('cybersiem:ensure_schema', 0))")
        blocker.commit()
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(pg_repo.ensure_schema)
            try:
                deadline = time.monotonic() + 10.0
                waiting_on_advisory = False
                while time.monotonic() < deadline:
                    row = observer.execute(
                        """
                        SELECT COUNT(*)
                        FROM pg_stat_activity
                        WHERE datname = current_database()
                          AND pid NOT IN (%s, %s)
                          AND wait_event_type = 'Lock'
                          AND wait_event = 'advisory'
                        """,
                        (blocker_pid, obs_pid),
                    ).fetchone()
                    if row and int(row[0]) >= 1:
                        waiting_on_advisory = True
                        break
                    time.sleep(0.02)
                assert waiting_on_advisory, "ensure_schema() did not wait on schema advisory lock"
                blocker.execute("SELECT pg_advisory_unlock(hashtextextended('cybersiem:ensure_schema', 0))")
                blocker.commit()
                fut.result(timeout=10.0)
            finally:
                blocker.execute("SELECT pg_advisory_unlock_all()")
                blocker.commit()

        lingering = observer.execute(
            "SELECT COUNT(*) FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database())"
        ).fetchone()
        assert int(lingering[0]) == 0


# --- 3. Tick expiry, cooldown clearing, idle/benign exclusion ---


def test_tick_releases_expired_block_clears_cooldown_and_skips_idle_ips(pg_repo, blocklist_manager):
    t0 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    cfg = ReputationConfig(scoring_window_seconds=86400, block_duration_seconds=1800, cooldown_duration_seconds=1800)
    enforcement = EnforcementService(repository=pg_repo, blocklist_manager=blocklist_manager, config=cfg)
    engine = SecurityEngine(repository=pg_repo, enforcement_service=enforcement)
    monitor = LogMonitorService(engine=engine)
    monitor.refresh_interval_seconds = 30.0

    ip = "198.51.100.40"
    for offset in (0, 60, 120):
        pg_repo.insert_alert(
            DetectionAlert(
                ip=ip,
                endpoint="/login",
                alert_type="brute_force",
                severity="medium",
                timestamp=t0 + timedelta(seconds=offset),
                message="bf",
            )
        )
    blocked = enforcement.sync_ip_and_blocklist(ip, now=t0 + timedelta(seconds=120))
    assert blocked["current_state"] == "blocked"
    assert f"deny {ip};" in blocklist_manager.blocklist_path.read_text(encoding="utf-8")

    # Benign-only IP (events only) and idle trusted IP should never appear as refresh candidates.
    benign_ip = "198.51.100.41"
    idle_ip = "198.51.100.42"
    pg_repo.insert_event(
        HTTPLogEvent(
            timestamp=t0,
            ip=benign_ip,
            method="GET",
            endpoint="/",
            status_code=200,
            user_agent="pytest",
            request_target="/",
            raw_line="ok",
        )
    )
    with pg_repo.connection() as conn:
        conn.execute(
            "INSERT INTO ip_reputations (ip, current_state, reputation_status, current_score, last_scored_alert_id) "
            "VALUES (%s, 'trusted', 'trusted', 0, 0)",
            (idle_ip,),
        )
        conn.commit()

    # One tick past block_until releases the block and removes it from blocklist.conf.
    t_unblock = t0 + timedelta(seconds=120 + cfg.block_duration_seconds + 10)
    assert monitor.maybe_refresh_reputations(monotonic_now=0.0, now=t_unblock) is True
    after_block = pg_repo.get_ip_reputation(ip)
    assert after_block["current_state"] != "blocked"
    assert after_block["blocked_until"] is None
    assert after_block["cooldown_until"] is not None
    assert ip not in blocklist_manager.blocklist_path.read_text(encoding="utf-8")

    # After cooldown expires and alerts age out, tick clears cooldown to trusted and drops IP from candidates.
    t_clear = t_unblock + timedelta(days=2)
    assert monitor.maybe_refresh_reputations(monotonic_now=60.0, now=t_clear) is True
    cleared = pg_repo.get_ip_reputation(ip)
    assert cleared["current_state"] == "trusted"
    assert cleared["cooldown_until"] is None
    assert cleared["current_score"] == pytest.approx(0.0)

    candidates = pg_repo.list_ips_needing_refresh(t_clear - timedelta(seconds=cfg.scoring_window_seconds))
    assert ip not in candidates
    assert benign_ip not in candidates
    assert idle_ip not in candidates

    # A single path_probe that decays to trusted (score=0, unresolved_alert_count=1) must still be
    # refreshed once after its scoring window closes to reset counts to 0, then stop matching.
    decayed_ip = "198.51.100.43"
    pg_repo.insert_alert(
        DetectionAlert(
            ip=decayed_ip,
            endpoint="/admin",
            alert_type="path_probe",
            severity="medium",
            timestamp=t_clear,
            message="probe",
        )
    )
    decayed = enforcement.recalculate_ip_reputation(decayed_ip, now=t_clear + timedelta(hours=3))
    assert decayed["current_state"] == "trusted"
    assert decayed["current_score"] == pytest.approx(0.0)
    assert decayed["blocked_until"] is None
    assert decayed["cooldown_until"] is None
    assert decayed["unresolved_alert_count"] == 1

    t_aged = t_clear + timedelta(days=2)
    aged_cutoff = t_aged - timedelta(seconds=cfg.scoring_window_seconds)
    assert decayed_ip in pg_repo.list_ips_needing_refresh(aged_cutoff)
    assert monitor.maybe_refresh_reputations(monotonic_now=120.0, now=t_aged) is True

    after_age = pg_repo.get_ip_reputation(decayed_ip)
    assert after_age["alert_count"] == 0
    assert after_age["total_alert_count"] == 0
    assert after_age["unresolved_alert_count"] == 0
    assert after_age["malicious_alert_count"] == 0
    assert after_age["safe_alert_count"] == 0
    assert decayed_ip not in pg_repo.list_ips_needing_refresh(aged_cutoff)


# --- 4. Postgres concurrency tests (lock-gated via pg_stat_activity) ---


def test_concurrent_expiry_tick_vs_new_high_alert(pg_url, tmp_path, monkeypatch):
    n = 2
    monkeypatch.setenv("DB_POOL_MIN_SIZE", str(n + 1))
    monkeypatch.setenv("DB_POOL_MAX_SIZE", str(n + 2))
    monkeypatch.setenv("DB_POOL_TIMEOUT_SECONDS", "10.0")

    repo = SecurityRepository(pg_url)
    try:
        repo.ensure_schema()
        repo._get_pool().wait()
        blocklist_path = tmp_path / "blocklist.conf"
        cfg = ReputationConfig(block_duration_seconds=1800, cooldown_duration_seconds=1800)
        enforcement = EnforcementService(
            repository=repo,
            blocklist_manager=NginxBlocklistManager(str(blocklist_path)),
            config=cfg,
        )
        engine = SecurityEngine(repository=repo, enforcement_service=enforcement)
        engine.detectors = [PayloadDetector()]

        for round_idx in range(5):
            with repo.connection() as conn:
                conn.execute(TRUNCATE_SQL)
                conn.commit()

            ip = f"198.51.200.{round_idx + 1}"
            now = utc_now()
            t_seed = now - timedelta(seconds=2200)
            for offset in (0, 60, 120):
                repo.insert_alert(
                    DetectionAlert(
                        ip=ip,
                        endpoint="/login",
                        alert_type="brute_force",
                        severity="medium",
                        timestamp=t_seed + timedelta(seconds=offset),
                        message="bf",
                    )
                )
            seeded = enforcement.sync_ip_and_blocklist(ip, now=t_seed + timedelta(seconds=120))
            assert seeded["current_state"] == "blocked"
            assert seeded["blocked_until"] < now
            prior_lifetime = seeded["lifetime_score"]

            event = _sqli_event(ip, now)
            _run_gated(
                pg_url,
                [
                    partial(enforcement.refresh_known_ip_states, trigger_reason="engine_tick", now=now),
                    partial(engine.process_event, event),
                ],
            )

            final = repo.get_ip_reputation(ip)
            assert final["current_state"] == "blocked"
            assert final["alert_hold_active"] is True
            assert final["blocked_until"] is None
            assert final["lifetime_score"] == pytest.approx(prior_lifetime + 35.0)
            assert f"deny {ip};" in blocklist_path.read_text(encoding="utf-8")
    finally:
        repo.close()


def test_concurrent_six_alert_writes_and_ticks_exact_lifetime_and_watermark(pg_url, tmp_path, monkeypatch):
    writers = 6
    ticks = 2
    n = writers + ticks
    monkeypatch.setenv("DB_POOL_MIN_SIZE", str(n + 1))
    monkeypatch.setenv("DB_POOL_MAX_SIZE", str(n + 2))
    monkeypatch.setenv("DB_POOL_TIMEOUT_SECONDS", "10.0")

    repo = SecurityRepository(pg_url)
    try:
        repo.ensure_schema()
        repo._get_pool().wait()
        cfg = ReputationConfig()
        enforcement = EnforcementService(
            repository=repo,
            blocklist_manager=NginxBlocklistManager(str(tmp_path / "blocklist.conf")),
            config=cfg,
        )
        engine = SecurityEngine(repository=repo, enforcement_service=enforcement)
        engine.detectors = [PayloadDetector()]

        for round_idx in range(5):
            with repo.connection() as conn:
                conn.execute(TRUNCATE_SQL)
                conn.commit()

            ip = f"198.51.201.{round_idx + 1}"
            now = utc_now()
            # Seed 1 alert > repeat_window_seconds away so ticks always contend on this IP.
            repo.insert_alert(
                DetectionAlert(
                    ip=ip,
                    endpoint="/admin",
                    alert_type="path_probe",
                    severity="medium",
                    timestamp=now - timedelta(seconds=8000),
                    message="seed",
                )
            )
            enforcement.recalculate_ip_reputation(ip, now=now)

            # 6 alerts spaced >=1000s apart (> repeat_window_seconds=900s) -> deterministic 1.0x weight (35.0 each).
            events = [_sqli_event(ip, now - timedelta(seconds=1000 * (i + 1))) for i in range(writers)]
            tasks = [
                *(partial(engine.process_event, ev) for ev in events),
                *(
                    partial(enforcement.refresh_known_ip_states, trigger_reason="engine_tick", now=now)
                    for _ in range(ticks)
                ),
            ]
            _run_gated(pg_url, tasks)

            rows = repo.list_alert_rows_for_ip(ip)
            assert len(rows) == 1 + writers
            final = repo.get_ip_reputation(ip)
            assert final["lifetime_score"] == pytest.approx(12.0 + writers * 35.0)
            assert final["last_scored_alert_id"] == max(r["id"] for r in rows)
    finally:
        repo.close()


def test_concurrent_tick_vs_manual_block_and_alert_status_update(pg_url, tmp_path, monkeypatch):
    n = 3
    monkeypatch.setenv("DB_POOL_MIN_SIZE", str(n + 1))
    monkeypatch.setenv("DB_POOL_MAX_SIZE", str(n + 2))
    monkeypatch.setenv("DB_POOL_TIMEOUT_SECONDS", "10.0")

    repo = SecurityRepository(pg_url)
    try:
        repo.ensure_schema()
        repo._get_pool().wait()
        blocklist_path = tmp_path / "blocklist.conf"
        cfg = ReputationConfig(block_duration_seconds=1800, cooldown_duration_seconds=1800)
        enforcement = EnforcementService(
            repository=repo,
            blocklist_manager=NginxBlocklistManager(str(blocklist_path)),
            config=cfg,
        )

        for round_idx in range(5):
            with repo.connection() as conn:
                conn.execute(TRUNCATE_SQL)
                conn.commit()

            ip = f"198.51.202.{round_idx + 1}"
            now = utc_now()
            alert_id = repo.insert_alert(
                DetectionAlert(
                    ip=ip,
                    endpoint="/login",
                    alert_type="payload_sqli",
                    severity="high",
                    timestamp=now - timedelta(minutes=10),
                    message="sqli",
                )
            )
            seeded = enforcement.sync_ip_and_blocklist(ip, now=now - timedelta(minutes=10))
            assert seeded["current_state"] == "blocked"
            assert seeded["alert_hold_active"] is True

            _run_gated(
                pg_url,
                [
                    partial(enforcement.refresh_known_ip_states, trigger_reason="engine_tick", now=now),
                    partial(enforcement.manual_block_ip, ip, "analyst_block"),
                    partial(enforcement.update_alert_status, alert_id, "safe"),
                ],
            )

            alert = repo.get_alert(alert_id)
            assert alert is not None
            assert alert["status"] == "safe"

            final = repo.get_ip_reputation(ip)
            assert final["current_state"] == "blocked"
            assert final["manual_blocked"] is True
            assert final["analyst_override"] == "manual_block"
            assert final["alert_hold_active"] is False
            assert final["unresolved_alert_count"] == 0
            assert final["safe_alert_count"] == 1
            assert f"deny {ip};" in blocklist_path.read_text(encoding="utf-8")
    finally:
        repo.close()
