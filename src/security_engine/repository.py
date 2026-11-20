from __future__ import annotations

import json
import math
import os
import threading
from collections.abc import Sequence
from contextlib import contextmanager
from datetime import datetime
from typing import Iterator

from psycopg import Connection, sql
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.enforcement import IPReputationEvaluation, ReputationTransition

DEFAULT_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cybersiem:cybersiem@localhost:5432/cybersiem",
)

ALERT_WITH_REPUTATION_SELECT = """
    SELECT
        alerts.id,
        alerts.event_id,
        host(alerts.ip) AS ip,
        alerts.endpoint,
        alerts.type,
        alerts.severity,
        alerts.status,
        alerts.message,
        alerts.metadata,
        alerts.created_at,
        alerts.updated_at,
        alerts.confidence,
        ip_reputations.reputation_status,
        ip_reputations.current_state,
        ip_reputations.current_score,
        ip_reputations.lifetime_score,
        ip_reputations.alert_count,
        ip_reputations.malicious_count,
        ip_reputations.block_count,
        ip_reputations.offense_streak,
        ip_reputations.last_seen,
        ip_reputations.last_alert_at,
        ip_reputations.blocked_until,
        ip_reputations.cooldown_until,
        ip_reputations.whitelist,
        ip_reputations.analyst_override,
        ip_reputations.blocked_reason,
        ip_reputations.manual_blocked,
        ip_reputations.threshold_reached,
        ip_reputations.total_alert_count,
        ip_reputations.safe_alert_count,
        ip_reputations.unresolved_alert_count,
        ip_reputations.malicious_alert_count,
        ip_reputations.alert_hold_active,
        ip_reputations.reputation_reasons
    FROM alerts
    LEFT JOIN ip_reputations ON ip_reputations.ip = alerts.ip
"""

IP_REPUTATION_SELECT = """
    SELECT
        host(ip) AS ip,
        reputation_status,
        current_state,
        current_score,
        lifetime_score,
        alert_count,
        malicious_count,
        block_count,
        offense_streak,
        last_seen,
        last_alert_at,
        blocked_until,
        cooldown_until,
        whitelist,
        analyst_override,
        blocked_reason,
        manual_blocked,
        threshold_reached,
        total_alert_count,
        safe_alert_count,
        unresolved_alert_count,
        malicious_alert_count,
        alert_hold_active,
        last_scored_alert_id,
        reputation_reasons,
        updated_at
    FROM ip_reputations
"""


class SecurityRepository:
    def __init__(self, database_url: str = DEFAULT_DATABASE_URL) -> None:
        self.database_url = database_url
        self._pool: ConnectionPool | None = None
        self._pool_lock = threading.Lock()
        # Fail fast on bad pool config instead of at the first connection attempt.
        self._pool_min_size, self._pool_max_size, self._pool_timeout = self._pool_settings()

    @staticmethod
    def _pool_settings() -> tuple[int, int, float]:
        def _int_env(name: str, default: int) -> int:
            try:
                return int(os.getenv(name, str(default)))
            except ValueError as exc:
                raise ValueError(f"{name} must be an integer, got {os.getenv(name)!r}") from exc

        min_size = _int_env("DB_POOL_MIN_SIZE", 1)
        max_size = _int_env("DB_POOL_MAX_SIZE", 10)
        try:
            timeout = float(os.getenv("DB_POOL_TIMEOUT_SECONDS", "10.0"))
        except ValueError as exc:
            raw = os.getenv("DB_POOL_TIMEOUT_SECONDS")
            raise ValueError(f"DB_POOL_TIMEOUT_SECONDS must be a number, got {raw!r}") from exc
        if min_size < 1:
            raise ValueError(f"DB_POOL_MIN_SIZE must be >= 1, got {min_size}")
        if max_size < min_size:
            raise ValueError(f"DB_POOL_MAX_SIZE ({max_size}) must be >= DB_POOL_MIN_SIZE ({min_size})")
        if timeout <= 0:
            raise ValueError(f"DB_POOL_TIMEOUT_SECONDS must be > 0, got {timeout}")
        if not math.isfinite(timeout):
            raise ValueError(f"DB_POOL_TIMEOUT_SECONDS must be a finite number, got {timeout}")
        return min_size, max_size, timeout

    def _get_pool(self) -> ConnectionPool:
        if self._pool is None:
            with self._pool_lock:
                if self._pool is None:
                    self._pool = ConnectionPool(
                        self.database_url,
                        min_size=self._pool_min_size,
                        max_size=self._pool_max_size,
                        timeout=self._pool_timeout,
                        open=True,
                        kwargs={"row_factory": dict_row},
                    )
        return self._pool

    def close(self) -> None:
        """Shut the pool down; safe to call more than once."""
        with self._pool_lock:
            pool, self._pool = self._pool, None
        if pool is not None:
            pool.close()

    @contextmanager
    def connection(self) -> Iterator:
        with self._get_pool().connection() as conn:
            yield conn

    @contextmanager
    def _transact(self, conn: Connection | None = None) -> Iterator:
        """Reuse the caller's connection and transaction, or open and commit our own.

        A borrowed connection is never committed here: the caller (e.g. ``ip_transaction``)
        owns the transaction, which keeps its advisory lock until it commits.
        """
        if conn is not None:
            yield conn
            return
        with self.connection() as owned:
            yield owned
            owned.commit()

    @contextmanager
    def ip_transaction(self, ip: str) -> Iterator:
        """Serialize per-IP reputation reads/writes with a transaction-scoped advisory lock."""
        with self._transact() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(host(%s::inet), 0))", (ip,))
            yield conn

    @contextmanager
    def blocklist_sync_transaction(self) -> Iterator:
        """Serialize blocklist snapshot reads and file writes across processes."""
        with self._transact() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(hashtextextended('cybersiem:blocklist_sync', 0))")
            yield conn

    def ensure_schema(self) -> None:
        tables_ddl = (
            (
                "events",
                """
                CREATE TABLE IF NOT EXISTS events (
                    id BIGSERIAL PRIMARY KEY,
                    occurred_at TIMESTAMPTZ NOT NULL,
                    ip INET NOT NULL,
                    method VARCHAR(16) NOT NULL,
                    endpoint TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    user_agent TEXT NOT NULL,
                    request_target TEXT NOT NULL,
                    query_string TEXT NOT NULL DEFAULT '',
                    referer TEXT NOT NULL DEFAULT '-',
                    raw_line TEXT NOT NULL
                )
                """,
            ),
            (
                "ip_reputations",
                """
                CREATE TABLE IF NOT EXISTS ip_reputations (
                    ip INET PRIMARY KEY,
                    reputation_status VARCHAR(32) NOT NULL DEFAULT 'trusted',
                    current_state VARCHAR(32) NOT NULL DEFAULT 'trusted',
                    current_score DOUBLE PRECISION NOT NULL DEFAULT 0,
                    lifetime_score DOUBLE PRECISION NOT NULL DEFAULT 0,
                    alert_count INTEGER NOT NULL DEFAULT 0,
                    malicious_count INTEGER NOT NULL DEFAULT 0,
                    block_count INTEGER NOT NULL DEFAULT 0,
                    offense_streak INTEGER NOT NULL DEFAULT 0,
                    blocked_reason TEXT,
                    manual_blocked BOOLEAN NOT NULL DEFAULT FALSE,
                    total_alert_count INTEGER NOT NULL DEFAULT 0,
                    safe_alert_count INTEGER NOT NULL DEFAULT 0,
                    unresolved_alert_count INTEGER NOT NULL DEFAULT 0,
                    malicious_alert_count INTEGER NOT NULL DEFAULT 0,
                    alert_hold_active BOOLEAN NOT NULL DEFAULT FALSE,
                    last_scored_alert_id BIGINT,
                    threshold_reached BOOLEAN NOT NULL DEFAULT FALSE,
                    last_seen TIMESTAMPTZ,
                    last_alert_at TIMESTAMPTZ,
                    blocked_until TIMESTAMPTZ,
                    cooldown_until TIMESTAMPTZ,
                    whitelist BOOLEAN NOT NULL DEFAULT FALSE,
                    analyst_override VARCHAR(32),
                    reputation_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
            ),
            (
                "alerts",
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id BIGSERIAL PRIMARY KEY,
                    event_id BIGINT REFERENCES events(id) ON DELETE SET NULL,
                    ip INET NOT NULL,
                    endpoint TEXT NOT NULL,
                    type VARCHAR(64) NOT NULL,
                    severity VARCHAR(16) NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'unresolved',
                    message TEXT NOT NULL,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ,
                    confidence INTEGER NOT NULL DEFAULT 50
                )
                """,
            ),
            (
                "ip_reputation_transitions",
                """
                CREATE TABLE IF NOT EXISTS ip_reputation_transitions (
                    id BIGSERIAL PRIMARY KEY,
                    ip INET NOT NULL,
                    old_state VARCHAR(32) NOT NULL,
                    new_state VARCHAR(32) NOT NULL,
                    score_before DOUBLE PRECISION NOT NULL DEFAULT 0,
                    score_after DOUBLE PRECISION NOT NULL DEFAULT 0,
                    trigger_reason TEXT NOT NULL,
                    source_alert_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    manual_or_auto VARCHAR(16) NOT NULL DEFAULT 'auto',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
            ),
            (
                "users",
                """
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username VARCHAR(64) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role VARCHAR(16) NOT NULL DEFAULT 'readonly',
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
            ),
            (
                "audit_logs",
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id BIGSERIAL PRIMARY KEY,
                    actor VARCHAR(64),
                    action VARCHAR(64) NOT NULL,
                    target TEXT,
                    source_ip TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
            ),
        )
        # Keep ip_reputations DDL before alerts DDL to avoid lock-order deadlocks.
        columns_ddl = (
            (
                "ip_reputations",
                "current_state",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS current_state VARCHAR(32) NOT NULL DEFAULT 'trusted'",
            ),
            (
                "ip_reputations",
                "current_score",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS current_score DOUBLE PRECISION NOT NULL DEFAULT 0",
            ),
            (
                "ip_reputations",
                "lifetime_score",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS lifetime_score DOUBLE PRECISION NOT NULL DEFAULT 0",
            ),
            (
                "ip_reputations",
                "alert_count",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS alert_count INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "ip_reputations",
                "malicious_count",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS malicious_count INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "ip_reputations",
                "block_count",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS block_count INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "ip_reputations",
                "offense_streak",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS offense_streak INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "ip_reputations",
                "last_seen",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ",
            ),
            (
                "ip_reputations",
                "last_alert_at",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS last_alert_at TIMESTAMPTZ",
            ),
            (
                "ip_reputations",
                "blocked_until",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS blocked_until TIMESTAMPTZ",
            ),
            (
                "ip_reputations",
                "cooldown_until",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS cooldown_until TIMESTAMPTZ",
            ),
            (
                "ip_reputations",
                "whitelist",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS whitelist BOOLEAN NOT NULL DEFAULT FALSE",
            ),
            (
                "ip_reputations",
                "analyst_override",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS analyst_override VARCHAR(32)",
            ),
            (
                "ip_reputations",
                "reputation_reasons",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS reputation_reasons JSONB NOT NULL DEFAULT '[]'::jsonb",
            ),
            (
                "ip_reputations",
                "alert_hold_active",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS alert_hold_active BOOLEAN NOT NULL DEFAULT FALSE",
            ),
            (
                "ip_reputations",
                "last_scored_alert_id",
                "ALTER TABLE ip_reputations ADD COLUMN IF NOT EXISTS last_scored_alert_id BIGINT",
            ),
            (
                "alerts",
                "confidence",
                "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS confidence INTEGER NOT NULL DEFAULT 50",
            ),
            (
                "users",
                "role",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(16) NOT NULL DEFAULT 'readonly'",
            ),
        )
        indexes_ddl = (
            (
                "idx_ip_reputations_state",
                "CREATE INDEX IF NOT EXISTS idx_ip_reputations_state ON ip_reputations (current_state, current_score DESC)",
            ),
            (
                "idx_ip_reputations_blocked_until",
                "CREATE INDEX IF NOT EXISTS idx_ip_reputations_blocked_until ON ip_reputations (blocked_until)",
            ),
            (
                "idx_alerts_created_at",
                "CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC)",
            ),
            ("idx_alerts_status", "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status)"),
            ("idx_alerts_type", "CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts (type)"),
            (
                "idx_alerts_ip_created_at",
                "CREATE INDEX IF NOT EXISTS idx_alerts_ip_created_at ON alerts (ip, created_at DESC)",
            ),
            (
                "idx_alerts_hold_lookup",
                """
                CREATE INDEX IF NOT EXISTS idx_alerts_hold_lookup
                ON alerts (ip, severity, type, created_at)
                WHERE status IN ('unresolved', 'malicious')
                """,
            ),
            (
                "idx_events_occurred_at",
                "CREATE INDEX IF NOT EXISTS idx_events_occurred_at ON events (occurred_at DESC)",
            ),
            (
                "idx_events_ip_occurred_at",
                "CREATE INDEX IF NOT EXISTS idx_events_ip_occurred_at ON events (ip, occurred_at DESC)",
            ),
            (
                "idx_events_endpoint_occurred_at",
                "CREATE INDEX IF NOT EXISTS idx_events_endpoint_occurred_at ON events (endpoint, occurred_at DESC)",
            ),
            (
                "idx_ip_reputation_transitions_created_at",
                "CREATE INDEX IF NOT EXISTS idx_ip_reputation_transitions_created_at ON ip_reputation_transitions (created_at DESC)",
            ),
            (
                "idx_ip_reputation_transitions_ip_created_at",
                "CREATE INDEX IF NOT EXISTS idx_ip_reputation_transitions_ip_created_at ON ip_reputation_transitions (ip, created_at DESC)",
            ),
            (
                "idx_audit_logs_created_at",
                "CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC)",
            ),
            (
                "idx_audit_logs_actor",
                "CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs (actor)",
            ),
        )

        schema_lock_sql = "SELECT pg_advisory_lock(hashtextextended('cybersiem:ensure_schema', 0))"
        schema_unlock_sql = "SELECT pg_advisory_unlock(hashtextextended('cybersiem:ensure_schema', 0))"

        with self.connection() as conn:
            locked = False
            try:
                with conn.cursor() as cur:
                    cur.execute(schema_lock_sql)
                conn.commit()
                locked = True

                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = current_schema()
                        """
                    )
                    existing_tables = {row["table_name"] for row in cur.fetchall()}

                    cur.execute(
                        """
                        SELECT table_name, column_name, column_default
                        FROM information_schema.columns
                        WHERE table_schema = current_schema()
                        """
                    )
                    existing_columns = {
                        (row["table_name"], row["column_name"]): row["column_default"] for row in cur.fetchall()
                    }

                    cur.execute(
                        """
                        SELECT indexname
                        FROM pg_indexes
                        WHERE schemaname = current_schema()
                        """
                    )
                    existing_indexes = {row["indexname"] for row in cur.fetchall()}
                conn.commit()

                # Commit after each DDL statement so no DDL lock is held across tables.
                with conn.cursor() as cur:
                    for table_name, ddl in tables_ddl:
                        if table_name not in existing_tables:
                            cur.execute(ddl)
                            conn.commit()

                    ddl_order = (
                        "ip_reputations",
                        "alerts",
                        "events",
                        "ip_reputation_transitions",
                        "users",
                        "audit_logs",
                    )
                    for target_table in ddl_order:
                        if target_table in existing_tables:
                            for table_name, col_name, ddl in columns_ddl:
                                if table_name == target_table and (table_name, col_name) not in existing_columns:
                                    cur.execute(ddl)
                                    conn.commit()
                            if target_table == "alerts" and "'unresolved'" not in (
                                existing_columns.get(("alerts", "status")) or ""
                            ):
                                cur.execute("ALTER TABLE alerts ALTER COLUMN status SET DEFAULT 'unresolved'")
                                conn.commit()
                        for index_name, ddl in indexes_ddl:
                            if index_name not in existing_indexes and f"ON {target_table} " in ddl:
                                cur.execute(ddl)
                                conn.commit()

                    # Scope backfilled watermarks by scored count + last_alert_at so later-ID
                    # unscored alerts with earlier timestamps stay above last_scored_alert_id,
                    # and fall back to 0 if legacy alerts were bulk-deleted (COUNT(*) < K).
                    cur.execute(
                        """
                        UPDATE ip_reputations
                        SET last_scored_alert_id = COALESCE(
                            (
                                SELECT CASE
                                    WHEN COUNT(*) = GREATEST(
                                        COALESCE(ip_reputations.total_alert_count, 0),
                                        COALESCE(ip_reputations.alert_count, 0),
                                        0
                                    ) THEN MAX(scored.id)
                                    ELSE 0
                                END
                                FROM (
                                    SELECT a.id
                                    FROM alerts a
                                    WHERE a.ip = ip_reputations.ip
                                      AND ip_reputations.last_alert_at IS NOT NULL
                                      AND a.created_at <= ip_reputations.last_alert_at
                                    ORDER BY a.id ASC
                                    LIMIT GREATEST(
                                        COALESCE(ip_reputations.total_alert_count, 0),
                                        COALESCE(ip_reputations.alert_count, 0),
                                        0
                                    )
                                ) AS scored
                            ),
                            0
                        )
                        WHERE last_scored_alert_id IS NULL
                        """
                    )
                    cur.execute(
                        """
                        UPDATE ip_reputations
                        SET current_state = CASE
                            WHEN reputation_status = 'blocked' THEN 'blocked'
                            WHEN reputation_status IS NULL OR reputation_status = 'allowed' THEN 'trusted'
                            ELSE reputation_status
                        END
                        WHERE current_state IS NULL OR current_state = 'trusted'
                        """
                    )
                    cur.execute(
                        """
                        UPDATE ip_reputations
                        SET reputation_status = current_state
                        WHERE reputation_status IS DISTINCT FROM current_state
                        """
                    )
                    cur.execute(
                        """
                        UPDATE ip_reputations
                        SET
                            alert_count = GREATEST(COALESCE(alert_count, 0), COALESCE(total_alert_count, 0)),
                            malicious_count = GREATEST(COALESCE(malicious_count, 0), COALESCE(malicious_alert_count, 0))
                        WHERE
                            COALESCE(alert_count, 0) = 0
                            OR COALESCE(malicious_count, 0) = 0
                        """
                    )
                    cur.execute(
                        """
                        UPDATE alerts
                        SET status = CASE
                            WHEN status IN ('open', 'investigating') THEN 'unresolved'
                            WHEN status = 'resolved' THEN 'safe'
                            ELSE status
                        END
                        WHERE status IN ('open', 'investigating', 'resolved')
                        """
                    )
                conn.commit()
            finally:
                if locked and not conn.closed:
                    conn.rollback()
                    with conn.cursor() as cur:
                        cur.execute(schema_unlock_sql)
                    conn.commit()

    def insert_event(self, event: HTTPLogEvent) -> int:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO events (
                        occurred_at,
                        ip,
                        method,
                        endpoint,
                        status_code,
                        user_agent,
                        request_target,
                        query_string,
                        referer,
                        raw_line
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        event.timestamp,
                        event.ip,
                        event.method,
                        event.endpoint,
                        event.status_code,
                        event.user_agent,
                        event.request_target,
                        event.query,
                        event.referer,
                        event.raw_line,
                    ),
                )
                event_id = cur.fetchone()["id"]
            conn.commit()
        return event_id

    def insert_alert(self, alert: DetectionAlert, conn: Connection | None = None) -> int:
        with self._transact(conn) as db:
            if conn is None:
                # We own the transaction: hold the per-IP lock so a concurrent reputation
                # tick cannot commit a stale view that outlives this insert.
                with db.cursor() as cur:
                    cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(host(%s::inet), 0))", (alert.ip,))
            with db.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO alerts (
                        event_id,
                        ip,
                        endpoint,
                        type,
                        severity,
                        status,
                        message,
                        metadata,
                        created_at,
                        confidence
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    RETURNING id
                    """,
                    (
                        alert.event_id,
                        alert.ip,
                        alert.endpoint,
                        alert.alert_type,
                        alert.severity,
                        alert.status,
                        alert.message,
                        json.dumps(alert.metadata),
                        alert.timestamp,
                        alert.confidence,
                    ),
                )
                alert_id = cur.fetchone()["id"]
        return alert_id

    def list_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        filter_type: str | None = None,
        filter_severity: str | None = None,
        filter_status: str | None = None,
        filter_ip: str | None = None,
        blocked_only: bool = False,
    ) -> list[dict]:
        where_clauses: list[str] = []
        params: list = []

        if filter_type:
            where_clauses.append("alerts.type = %s")
            params.append(filter_type)
        if filter_severity:
            where_clauses.append("alerts.severity = %s")
            params.append(filter_severity)
        if filter_status:
            where_clauses.append("alerts.status = %s")
            params.append(filter_status)
        if filter_ip:
            where_clauses.append("host(alerts.ip) ILIKE %s")
            params.append(f"%{filter_ip}%")
        if blocked_only:
            where_clauses.append("ip_reputations.current_state = 'blocked'")

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        params.extend([limit, offset])

        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    {ALERT_WITH_REPUTATION_SELECT}
                    {where_sql}
                    ORDER BY alerts.created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    params,
                )
                return list(cur.fetchall())

    @staticmethod
    def _alert_rows_query(ip: str, since: datetime | None) -> tuple[sql.SQL, tuple]:
        if since is None:
            return (
                sql.SQL(
                    """
                    SELECT
                        id,
                        type,
                        severity,
                        status,
                        metadata,
                        created_at
                    FROM alerts
                    WHERE ip = %s
                    ORDER BY created_at ASC
                    """
                ),
                (ip,),
            )
        return (
            sql.SQL(
                """
                SELECT
                    id,
                    type,
                    severity,
                    status,
                    metadata,
                    created_at
                FROM alerts
                WHERE ip = %s
                  AND created_at >= %s
                ORDER BY created_at ASC
                """
            ),
            (ip, since),
        )

    def list_alert_rows_for_ip(
        self,
        ip: str,
        since: datetime | None = None,
        conn: Connection | None = None,
    ) -> list[dict]:
        query, params = self._alert_rows_query(ip, since)
        with self._transact(conn) as db:
            with db.cursor() as cur:
                cur.execute(query, params)
                return list(cur.fetchall())

    @staticmethod
    def _older_hold_query(
        ip: str,
        *,
        before: datetime,
        hold_types: Sequence[str],
        hold_severities: Sequence[str],
        non_hold_types: Sequence[str],
        known_severities: Sequence[str],
        default_severity_holds: bool,
    ) -> tuple[sql.SQL, list]:
        query = sql.SQL(
            """
            WITH RECURSIVE distinct_pairs AS (
                (
                    SELECT a.severity, a.type
                    FROM alerts a
                    WHERE a.ip = %s
                      AND a.status IN ('unresolved', 'malicious')
                    ORDER BY a.severity, a.type
                    LIMIT 1
                )
                UNION ALL
                SELECT next_pair.severity, next_pair.type
                FROM distinct_pairs dp
                CROSS JOIN LATERAL (
                    SELECT a.severity, a.type
                    FROM alerts a
                    WHERE a.ip = %s
                      AND a.status IN ('unresolved', 'malicious')
                      AND (a.severity, a.type) > (dp.severity, dp.type)
                    ORDER BY a.severity, a.type
                    LIMIT 1
                ) AS next_pair
            )
            SELECT older.id
            FROM (
                SELECT severity, type
                FROM distinct_pairs
                WHERE severity = 'high'
                   OR type = ANY(%s::varchar[])
                   OR (
                       type <> ALL(%s::varchar[])
                       AND (
                           severity = ANY(%s::varchar[])
                           OR (%s::boolean AND severity <> ALL(%s::varchar[]))
                       )
                   )
            ) AS eligible
            CROSS JOIN LATERAL (
                SELECT a.id
                FROM alerts a
                WHERE a.ip = %s
                  AND a.status IN ('unresolved', 'malicious')
                  AND a.severity = eligible.severity
                  AND a.type = eligible.type
                  AND a.created_at < %s
                ORDER BY a.created_at ASC
                LIMIT 1
            ) AS older
            LIMIT 1
            """
        )
        params = [
            ip,
            ip,
            list(hold_types),
            list(non_hold_types),
            list(hold_severities),
            bool(default_severity_holds),
            list(known_severities),
            ip,
            before,
        ]
        return query, params

    def list_older_hold_alert_ids(
        self,
        ip: str,
        *,
        before: datetime,
        hold_types: Sequence[str],
        hold_severities: Sequence[str],
        non_hold_types: Sequence[str],
        known_severities: Sequence[str],
        default_severity_holds: bool,
        conn: Connection | None = None,
    ) -> list[int]:
        """One unresolved/malicious alert older than the scoring window that still justifies an alert hold.

        Uses a loose index scan over distinct (severity, type) pairs in idx_alerts_hold_lookup so
        only eligible pairs touch created_at < before, keeping scans bounded under any weight config.
        """
        query, params = self._older_hold_query(
            ip,
            before=before,
            hold_types=hold_types,
            hold_severities=hold_severities,
            non_hold_types=non_hold_types,
            known_severities=known_severities,
            default_severity_holds=default_severity_holds,
        )
        with self._transact(conn) as db:
            with db.cursor() as cur:
                cur.execute(query, params)
                row = cur.fetchone()
                return [row["id"]] if row else []

    def list_ips_needing_refresh(self, since: datetime) -> list[str]:
        """IPs with reputation work to do: non-idle rows plus IPs alerted since *since*."""
        with self._transact() as db:
            with db.cursor() as cur:
                cur.execute(
                    """
                    SELECT host(ip) AS ip FROM ip_reputations
                    WHERE current_state <> 'trusted'
                       OR current_score > 0
                       OR blocked_until IS NOT NULL
                       OR cooldown_until IS NOT NULL
                       OR alert_count > 0
                       OR total_alert_count > 0
                       OR unresolved_alert_count > 0
                       OR malicious_alert_count > 0
                       OR safe_alert_count > 0
                    UNION
                    SELECT DISTINCT host(ip) FROM alerts
                    WHERE created_at >= %s
                    ORDER BY ip
                    """,
                    (since,),
                )
                return [row["ip"] for row in cur.fetchall()]

    def list_alert_map_rows(self, limit: int = 200) -> list[dict]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT host(ip) AS ip, type, severity
                    FROM alerts
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return list(cur.fetchall())

    def get_alert(self, alert_id: int, conn: Connection | None = None) -> dict | None:
        with self._transact(conn) as db:
            with db.cursor() as cur:
                cur.execute(
                    f"""
                    {ALERT_WITH_REPUTATION_SELECT}
                    WHERE alerts.id = %s
                    """,
                    (alert_id,),
                )
                return cur.fetchone()

    def update_alert_status(self, alert_id: int, status: str, conn: Connection | None = None) -> dict | None:
        with self._transact(conn) as db:
            with db.cursor() as cur:
                cur.execute(
                    """
                    UPDATE alerts
                    SET status = %s, updated_at = NOW()
                    WHERE id = %s
                    RETURNING id, event_id, host(ip) AS ip, endpoint, type, severity, status, message, metadata, created_at, updated_at, confidence
                    """,
                    (status, alert_id),
                )
                return cur.fetchone()

    def delete_all_alerts(self) -> int:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("LOCK TABLE alerts IN ACCESS EXCLUSIVE MODE")
                cur.execute("DELETE FROM alerts")
                deleted = cur.rowcount
            conn.commit()
        return deleted

    def summarize_alerts_for_ip(self, ip: str) -> dict:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        host(ip) AS ip,
                        COUNT(*)::INTEGER AS total_alert_count,
                        COUNT(*) FILTER (WHERE status = 'safe')::INTEGER AS safe_alert_count,
                        COUNT(*) FILTER (WHERE status = 'unresolved')::INTEGER AS unresolved_alert_count,
                        COUNT(*) FILTER (WHERE status = 'malicious')::INTEGER AS malicious_alert_count
                    FROM alerts
                    WHERE ip = %s
                    GROUP BY ip
                    """,
                    (ip,),
                )
                row = cur.fetchone()
                if row:
                    return row
                return {
                    "ip": ip,
                    "total_alert_count": 0,
                    "safe_alert_count": 0,
                    "unresolved_alert_count": 0,
                    "malicious_alert_count": 0,
                }

    def get_ip_activity(self, ip: str, conn: Connection | None = None) -> dict[str, datetime | None]:
        with self._transact(conn) as db:
            with db.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        (SELECT MAX(occurred_at) FROM events WHERE ip = %s) AS last_seen,
                        (SELECT MAX(created_at) FROM alerts WHERE ip = %s) AS last_alert_at
                    """,
                    (ip, ip),
                )
                row = cur.fetchone() or {}
                return {
                    "last_seen": row.get("last_seen"),
                    "last_alert_at": row.get("last_alert_at"),
                }

    def get_ip_reputation(self, ip: str, conn: Connection | None = None) -> dict | None:
        with self._transact(conn) as db:
            with db.cursor() as cur:
                cur.execute(
                    f"""
                    {IP_REPUTATION_SELECT}
                    WHERE ip = %s
                    """,
                    (ip,),
                )
                return cur.fetchone()

    def list_known_ips(self) -> list[str]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT host(ip) AS ip
                    FROM (
                        SELECT ip FROM alerts
                        UNION
                        SELECT ip FROM ip_reputations
                        UNION
                        SELECT ip FROM events
                    ) known_ips
                    ORDER BY ip
                    """
                )
                return [row["ip"] for row in cur.fetchall()]

    def upsert_ip_reputation(self, evaluation: IPReputationEvaluation, conn: Connection | None = None) -> dict:
        with self._transact(conn) as db:
            with db.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO ip_reputations (
                        ip,
                        reputation_status,
                        current_state,
                        current_score,
                        lifetime_score,
                        alert_count,
                        malicious_count,
                        block_count,
                        offense_streak,
                        blocked_reason,
                        manual_blocked,
                        total_alert_count,
                        safe_alert_count,
                        unresolved_alert_count,
                        malicious_alert_count,
                        alert_hold_active,
                        last_scored_alert_id,
                        threshold_reached,
                        last_seen,
                        last_alert_at,
                        blocked_until,
                        cooldown_until,
                        whitelist,
                        analyst_override,
                        reputation_reasons,
                        updated_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s::jsonb, NOW()
                    )
                    ON CONFLICT (ip) DO UPDATE
                    SET
                        reputation_status = EXCLUDED.reputation_status,
                        current_state = EXCLUDED.current_state,
                        current_score = EXCLUDED.current_score,
                        lifetime_score = EXCLUDED.lifetime_score,
                        alert_count = EXCLUDED.alert_count,
                        malicious_count = EXCLUDED.malicious_count,
                        block_count = EXCLUDED.block_count,
                        offense_streak = EXCLUDED.offense_streak,
                        blocked_reason = EXCLUDED.blocked_reason,
                        manual_blocked = EXCLUDED.manual_blocked,
                        total_alert_count = EXCLUDED.total_alert_count,
                        safe_alert_count = EXCLUDED.safe_alert_count,
                        unresolved_alert_count = EXCLUDED.unresolved_alert_count,
                        malicious_alert_count = EXCLUDED.malicious_alert_count,
                        alert_hold_active = EXCLUDED.alert_hold_active,
                        last_scored_alert_id = EXCLUDED.last_scored_alert_id,
                        threshold_reached = EXCLUDED.threshold_reached,
                        last_seen = EXCLUDED.last_seen,
                        last_alert_at = EXCLUDED.last_alert_at,
                        blocked_until = EXCLUDED.blocked_until,
                        cooldown_until = EXCLUDED.cooldown_until,
                        whitelist = EXCLUDED.whitelist,
                        analyst_override = EXCLUDED.analyst_override,
                        reputation_reasons = EXCLUDED.reputation_reasons,
                        updated_at = NOW()
                    RETURNING
                        host(ip) AS ip,
                        reputation_status,
                        current_state,
                        current_score,
                        lifetime_score,
                        alert_count,
                        malicious_count,
                        block_count,
                        offense_streak,
                        blocked_reason,
                        manual_blocked,
                        total_alert_count,
                        safe_alert_count,
                        unresolved_alert_count,
                        malicious_alert_count,
                        alert_hold_active,
                        last_scored_alert_id,
                        threshold_reached,
                        last_seen,
                        last_alert_at,
                        blocked_until,
                        cooldown_until,
                        whitelist,
                        analyst_override,
                        reputation_reasons,
                        updated_at
                    """,
                    (
                        evaluation.ip,
                        evaluation.current_state,
                        evaluation.current_state,
                        evaluation.current_score,
                        evaluation.lifetime_score,
                        evaluation.alert_count,
                        evaluation.malicious_count,
                        evaluation.block_count,
                        evaluation.offense_streak,
                        evaluation.blocked_reason,
                        evaluation.manual_blocked,
                        evaluation.total_alert_count,
                        evaluation.safe_alert_count,
                        evaluation.unresolved_alert_count,
                        evaluation.malicious_alert_count,
                        evaluation.alert_hold_active,
                        # Never store a NULL watermark: NULL re-triggers the startup backfill
                        # and untracks every alert on the next scoring pass. 0 == nothing scored yet.
                        evaluation.last_scored_alert_id if evaluation.last_scored_alert_id is not None else 0,
                        evaluation.threshold_reached,
                        evaluation.last_seen,
                        evaluation.last_alert_at,
                        evaluation.blocked_until,
                        evaluation.cooldown_until,
                        evaluation.whitelist,
                        evaluation.analyst_override,
                        json.dumps(evaluation.reputation_reasons),
                    ),
                )
                row = cur.fetchone()
        return row

    def set_ip_override_fields(
        self,
        ip: str,
        *,
        whitelist: bool,
        analyst_override: str | None,
        blocked_until: datetime | None,
        cooldown_until: datetime | None,
        blocked_reason: str | None,
        manual_blocked: bool,
        conn: Connection | None = None,
    ) -> dict:
        with self._transact(conn) as db:
            with db.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO ip_reputations (
                        ip,
                        reputation_status,
                        current_state,
                        current_score,
                        lifetime_score,
                        alert_count,
                        malicious_count,
                        block_count,
                        offense_streak,
                        blocked_reason,
                        manual_blocked,
                        total_alert_count,
                        safe_alert_count,
                        unresolved_alert_count,
                        malicious_alert_count,
                        threshold_reached,
                        last_scored_alert_id,
                        blocked_until,
                        cooldown_until,
                        whitelist,
                        analyst_override,
                        reputation_reasons,
                        updated_at
                    )
                    VALUES (
                        %s, 'trusted', 'trusted', 0, 0, 0, 0, 0, 0, %s, %s, 0, 0, 0, 0, FALSE,
                        0, %s, %s, %s, %s, '[]'::jsonb, NOW()
                    )
                    ON CONFLICT (ip) DO UPDATE
                    SET
                        blocked_reason = EXCLUDED.blocked_reason,
                        manual_blocked = EXCLUDED.manual_blocked,
                        blocked_until = EXCLUDED.blocked_until,
                        cooldown_until = EXCLUDED.cooldown_until,
                        whitelist = EXCLUDED.whitelist,
                        analyst_override = EXCLUDED.analyst_override,
                        updated_at = NOW()
                    RETURNING
                        host(ip) AS ip,
                        reputation_status,
                        current_state,
                        current_score,
                        lifetime_score,
                        alert_count,
                        malicious_count,
                        block_count,
                        offense_streak,
                        blocked_reason,
                        manual_blocked,
                        total_alert_count,
                        safe_alert_count,
                        unresolved_alert_count,
                        malicious_alert_count,
                        alert_hold_active,
                        threshold_reached,
                        last_seen,
                        last_alert_at,
                        blocked_until,
                        cooldown_until,
                        whitelist,
                        analyst_override,
                        reputation_reasons,
                        updated_at
                    """,
                    (
                        ip,
                        blocked_reason,
                        manual_blocked,
                        blocked_until,
                        cooldown_until,
                        whitelist,
                        analyst_override,
                    ),
                )
                row = cur.fetchone()
        return row

    def insert_reputation_transition(self, transition: ReputationTransition, conn: Connection | None = None) -> dict:
        with self._transact(conn) as db:
            with db.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO ip_reputation_transitions (
                        ip,
                        old_state,
                        new_state,
                        score_before,
                        score_after,
                        trigger_reason,
                        source_alert_ids,
                        manual_or_auto,
                        created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    RETURNING
                        id,
                        host(ip) AS ip,
                        old_state,
                        new_state,
                        score_before,
                        score_after,
                        trigger_reason,
                        source_alert_ids,
                        manual_or_auto,
                        created_at
                    """,
                    (
                        transition.ip,
                        transition.old_state,
                        transition.new_state,
                        transition.score_before,
                        transition.score_after,
                        transition.trigger_reason,
                        json.dumps(transition.source_alert_ids),
                        transition.manual_or_auto,
                        transition.created_at,
                    ),
                )
                row = cur.fetchone()
        return row

    def list_recent_reputation_transitions(self, limit: int = 25, ip: str | None = None) -> list[dict]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                if ip:
                    cur.execute(
                        """
                        SELECT
                            id,
                            host(ip) AS ip,
                            old_state,
                            new_state,
                            score_before,
                            score_after,
                            trigger_reason,
                            source_alert_ids,
                            manual_or_auto,
                            created_at
                        FROM ip_reputation_transitions
                        WHERE ip = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                        """,
                        (ip, limit),
                    )
                else:
                    cur.execute(
                        """
                        SELECT
                            id,
                            host(ip) AS ip,
                            old_state,
                            new_state,
                            score_before,
                            score_after,
                            trigger_reason,
                            source_alert_ids,
                            manual_or_auto,
                            created_at
                        FROM ip_reputation_transitions
                        ORDER BY created_at DESC
                        LIMIT %s
                        """,
                        (limit,),
                    )
                return list(cur.fetchall())

    def list_top_ip_reputations(self, limit: int = 10) -> list[dict]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    {IP_REPUTATION_SELECT}
                    WHERE current_score > 0 OR whitelist = TRUE OR analyst_override IS NOT NULL
                    ORDER BY current_score DESC, updated_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return list(cur.fetchall())

    def list_blocked_ips(self, conn: Connection | None = None) -> list[dict]:
        with self._transact(conn) as db:
            with db.cursor() as cur:
                cur.execute(
                    f"""
                    {IP_REPUTATION_SELECT}
                    WHERE current_state = 'blocked'
                    ORDER BY updated_at DESC, ip
                    """
                )
                return list(cur.fetchall())

    def count_ip_states(self) -> dict[str, int]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT current_state, COUNT(*)::INTEGER AS count
                    FROM ip_reputations
                    GROUP BY current_state
                    """
                )
                rows = cur.fetchall()

        counts = {state: 0 for state in ("trusted", "unknown", "suspicious", "throttled", "blocked")}
        for row in rows:
            counts[row["current_state"]] = row["count"]
        return counts

    def get_alert_type_counts(self, hours: int = 24) -> list[dict]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT type, COUNT(*)::INTEGER AS count
                    FROM alerts
                    WHERE created_at > NOW() - make_interval(hours => %s)
                    GROUP BY type
                    ORDER BY count DESC
                    LIMIT 10
                    """,
                    (hours,),
                )
                return list(cur.fetchall())

    def get_severity_counts(self, hours: int = 24) -> list[dict]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT severity, COUNT(*)::INTEGER AS count
                    FROM alerts
                    WHERE created_at > NOW() - make_interval(hours => %s)
                    GROUP BY severity
                    ORDER BY count DESC
                    """,
                    (hours,),
                )
                return list(cur.fetchall())

    def get_top_ips_by_alert_count(self, limit: int = 10, hours: int = 24) -> list[dict]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        host(a.ip) AS ip,
                        COUNT(*)::INTEGER AS alert_count,
                        COALESCE(r.current_state, 'trusted') AS current_state,
                        COALESCE(r.current_score, 0)::DOUBLE PRECISION AS current_score
                    FROM alerts a
                    LEFT JOIN ip_reputations r ON r.ip = a.ip
                    WHERE a.created_at > NOW() - make_interval(hours => %s)
                    GROUP BY a.ip, r.current_state, r.current_score
                    ORDER BY alert_count DESC
                    LIMIT %s
                    """,
                    (hours, limit),
                )
                return list(cur.fetchall())

    def get_alerts_per_hour(self, hours: int = 24) -> list[dict]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        date_trunc('hour', created_at) AS hour,
                        COUNT(*)::INTEGER AS count
                    FROM alerts
                    WHERE created_at > NOW() - make_interval(hours => %s)
                    GROUP BY hour
                    ORDER BY hour ASC
                    """,
                    (hours,),
                )
                return list(cur.fetchall())

    def get_distinct_alert_types(self) -> list[str]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT DISTINCT type FROM alerts ORDER BY type")
                return [row["type"] for row in cur.fetchall()]

    def get_user_by_username(self, username: str) -> dict | None:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, username, password_hash, role, is_active FROM users WHERE username = %s",
                    (username,),
                )
                return cur.fetchone()

    def get_user_by_id(self, user_id: int) -> dict | None:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, username, role, is_active FROM users WHERE id = %s",
                    (user_id,),
                )
                return cur.fetchone()

    def create_user(self, username: str, password_hash: str, role: str = "readonly") -> dict | None:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users (username, password_hash, role)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (username) DO NOTHING
                    RETURNING id, username, role, is_active
                    """,
                    (username, password_hash, role),
                )
                row = cur.fetchone()
            conn.commit()
        return row

    def update_user_role(self, username: str, new_role: str) -> dict | None:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE users SET role = %s WHERE username = %s
                    RETURNING id, username, role, is_active
                    """,
                    (new_role, username),
                )
                row = cur.fetchone()
            conn.commit()
        return row

    def log_audit_event(
        self,
        actor: str | None,
        action: str,
        target: str | None,
        source_ip: str | None,
    ) -> None:
        try:
            with self.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO audit_logs (actor, action, target, source_ip)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (actor, action, target, source_ip),
                    )
                conn.commit()
        except Exception:  # noqa: BLE001, S110 — audit failures must never break the caller
            pass

    def list_audit_events(self, limit: int = 100) -> list[dict]:
        with self.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, actor, action, target, source_ip, created_at
                    FROM audit_logs
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return list(cur.fetchall())
