from __future__ import annotations

import os
import time
from datetime import datetime, timedelta

from psycopg import Connection

from src.security_engine.enforcement import (
    ALERT_HOLD_MIN_WEIGHT,
    IPReputationRecord,
    NginxBlocklistManager,
    ReputationConfig,
    ReputationTransition,
    build_record_from_row,
    ensure_utc,
    evaluate_ip_reputation,
    utc_now,
)
from src.security_engine.repository import SecurityRepository


def _log(message: str) -> None:
    print(f"[security_engine] {message}", flush=True)


class EnforcementService:
    def __init__(
        self,
        repository: SecurityRepository | None = None,
        blocklist_manager: NginxBlocklistManager | None = None,
        config: ReputationConfig | None = None,
    ) -> None:
        self.repository = repository or SecurityRepository()
        self.blocklist_manager = blocklist_manager or NginxBlocklistManager()
        self.config = config or ReputationConfig()

    def initialize(self) -> None:
        retry_count = int(os.getenv("ENFORCEMENT_INIT_RETRIES", "30"))
        retry_delay_seconds = float(os.getenv("ENFORCEMENT_INIT_RETRY_DELAY_SECONDS", "1"))

        last_error: Exception | None = None
        for attempt in range(1, retry_count + 1):
            try:
                self.repository.ensure_schema()
                self.refresh_known_ip_states(trigger_reason="startup_refresh")
                self.sync_blocklist()
                return
            except Exception as exc:  # pragma: no cover - defensive startup retry
                last_error = exc
                if attempt == retry_count:
                    break
                time.sleep(retry_delay_seconds)

        if last_error is not None:
            raise last_error

    def refresh_known_ip_states(
        self,
        *,
        trigger_reason: str = "scheduled_refresh",
        manual_or_auto: str = "auto",
        now: datetime | None = None,
    ) -> list[dict]:
        """Periodic tick: re-score only IPs that still have work to do.

        IPs inside the scoring window with new alerts, or with lingering state (score, block,
        cooldown), are recalculated. Everything else is left alone so decay/expiry are the only
        reasons a stored row changes.
        """
        effective_now = ensure_utc(now) or utc_now()
        since = effective_now - timedelta(seconds=self.config.scoring_window_seconds)
        candidates = self.repository.list_ips_needing_refresh(since)
        first_error: Exception | None = None
        records: list[dict] = []
        try:
            for ip in candidates:
                try:
                    records.append(
                        self.recalculate_ip_reputation(
                            ip,
                            trigger_reason=trigger_reason,
                            manual_or_auto=manual_or_auto,
                            now=now,
                        )
                    )
                except Exception as exc:
                    # One failing IP must not starve the rest; re-raise the first after the sync.
                    if first_error is None:
                        first_error = exc
                    _log(f"Failed to recalculate reputation for {ip}: {type(exc).__name__}")
        finally:
            # Unconditional: write_blocklist skips the disk when nothing changed, and syncing
            # even with no candidates heals a stale or raced blocklist.conf.
            self.sync_blocklist()
        if first_error is not None:
            raise first_error
        return records

    def recalculate_ip_reputation(
        self,
        ip: str,
        *,
        trigger_reason: str = "recalculated",
        source_alert_ids: list[int] | None = None,
        manual_or_auto: str = "auto",
        now: datetime | None = None,
        conn: Connection | None = None,
    ) -> dict:
        if conn is not None:
            return self._recalculate_locked(
                ip,
                conn,
                trigger_reason=trigger_reason,
                source_alert_ids=source_alert_ids,
                manual_or_auto=manual_or_auto,
                now=now,
            )
        with self.repository.ip_transaction(ip) as locked_conn:
            return self._recalculate_locked(
                ip,
                locked_conn,
                trigger_reason=trigger_reason,
                source_alert_ids=source_alert_ids,
                manual_or_auto=manual_or_auto,
                now=now,
            )

    def _recalculate_locked(
        self,
        ip: str,
        conn: Connection,
        *,
        trigger_reason: str,
        source_alert_ids: list[int] | None,
        manual_or_auto: str,
        now: datetime | None,
    ) -> dict:
        """Score one IP inside a transaction that already holds the per-IP advisory lock."""
        effective_now = ensure_utc(now) or utc_now()
        previous_record = self._get_existing_record(ip, conn=conn)
        cutoff = effective_now - timedelta(seconds=self.config.scoring_window_seconds)
        alert_rows = self.repository.list_alert_rows_for_ip(ip, since=cutoff, conn=conn)
        hold_types, hold_severities, non_hold_types, known_severities, default_severity_holds = (
            self._hold_query_params()
        )
        older_hold_ids = self.repository.list_older_hold_alert_ids(
            ip,
            before=cutoff,
            hold_types=hold_types,
            hold_severities=hold_severities,
            non_hold_types=non_hold_types,
            known_severities=known_severities,
            default_severity_holds=default_severity_holds,
            conn=conn,
        )
        ip_activity = self.repository.get_ip_activity(ip, conn=conn)

        evaluation = evaluate_ip_reputation(
            ip=ip,
            alert_rows=alert_rows,
            previous_record=previous_record,
            last_seen=ip_activity.get("last_seen"),
            now=effective_now,
            config=self.config,
            trigger_reason=trigger_reason,
            source_alert_ids=source_alert_ids,
            older_hold_alert_ids=older_hold_ids,
        )
        stored_record = self.repository.upsert_ip_reputation(evaluation, conn=conn)

        if self._should_record_transition(previous_record, evaluation, manual_or_auto):
            self.repository.insert_reputation_transition(
                ReputationTransition(
                    ip=evaluation.ip,
                    old_state=previous_record.current_state,
                    new_state=evaluation.current_state,
                    score_before=previous_record.current_score,
                    score_after=evaluation.current_score,
                    trigger_reason=trigger_reason,
                    source_alert_ids=evaluation.source_alert_ids,
                    manual_or_auto=manual_or_auto,
                    created_at=effective_now,
                ),
                conn=conn,
            )

        return stored_record

    def _hold_query_params(self) -> tuple[list[str], list[str], list[str], list[str], bool]:
        """SQL decomposition of the alert-hold rule: severity='high' or base weight >= threshold."""
        hold_types = [
            alert_type for alert_type, weight in self.config.alert_weights.items() if weight >= ALERT_HOLD_MIN_WEIGHT
        ]
        # Types with an explicit weight take it regardless of severity; untyped ones fall back to
        # their severity weight, and unknown severities default to the medium weight — the SQL
        # mirrors weight_for_alert exactly so both sides agree on what keeps a hold alive.
        non_hold_types = list(self.config.alert_weights)
        hold_severities = [
            severity for severity, weight in self.config.severity_weights.items() if weight >= ALERT_HOLD_MIN_WEIGHT
        ]
        known_severities = list(self.config.severity_weights)
        default_severity_holds = self.config.severity_weights.get("medium", 10.0) >= ALERT_HOLD_MIN_WEIGHT
        return hold_types, hold_severities, non_hold_types, known_severities, default_severity_holds

    def sync_ip_and_blocklist(
        self,
        ip: str,
        *,
        trigger_reason: str = "recalculated",
        source_alert_ids: list[int] | None = None,
        manual_or_auto: str = "auto",
        now: datetime | None = None,
    ) -> dict:
        record = self.recalculate_ip_reputation(
            ip,
            trigger_reason=trigger_reason,
            source_alert_ids=source_alert_ids,
            manual_or_auto=manual_or_auto,
            now=now,
        )
        self.sync_blocklist()
        return record

    def sync_blocklist(self) -> None:
        with self.repository.blocklist_sync_transaction() as conn:
            blocked_ips = [record["ip"] for record in self.repository.list_blocked_ips(conn=conn)]
            self.blocklist_manager.write_blocklist(blocked_ips)

    def update_alert_status(self, alert_id: int, status: str) -> dict | None:
        current = self.repository.get_alert(alert_id)
        if not current:
            return None
        with self.repository.ip_transaction(current["ip"]) as conn:
            alert = self.repository.update_alert_status(alert_id, status, conn=conn)
            if not alert:
                return None
            self.recalculate_ip_reputation(
                alert["ip"],
                trigger_reason=f"alert_status_changed:{status}",
                source_alert_ids=[alert_id],
                manual_or_auto="manual",
                conn=conn,
            )
        self.sync_blocklist()
        return self.repository.get_alert(alert_id)

    def _apply_override(self, ip: str, *, trigger_reason: str, now: datetime | None = None, **override_fields) -> dict:
        """Apply an analyst override and re-score the IP under the per-IP advisory lock."""
        with self.repository.ip_transaction(ip) as conn:
            self.repository.set_ip_override_fields(ip, conn=conn, **override_fields)
            record = self.recalculate_ip_reputation(
                ip,
                trigger_reason=trigger_reason,
                manual_or_auto="manual",
                now=now,
                conn=conn,
            )
        self.sync_blocklist()
        return record

    def manual_block_ip(self, ip: str, reason: str | None = None) -> dict:
        return self._apply_override(
            ip,
            trigger_reason="manual_block_requested",
            whitelist=False,
            analyst_override="manual_block",
            blocked_until=None,
            cooldown_until=None,
            blocked_reason=reason or "manual_block",
            manual_blocked=True,
        )

    def manual_unblock_ip(self, ip: str) -> dict:
        now = utc_now()
        with self.repository.ip_transaction(ip) as conn:
            existing = self._get_existing_record(ip, conn=conn)
            if existing.alert_hold_active:
                pending = existing.unresolved_alert_count + existing.malicious_alert_count
                detail = (
                    f"{pending} unresolved/malicious alert(s) still require analyst review"
                    if pending > 0
                    else "an older unresolved/malicious alert still requires analyst review"
                )
                raise ValueError(
                    f"Cannot unblock {ip}: alert hold is active ({detail}). "
                    "Mark all alerts safe first, or use force_unblock (admin only)."
                )
            self.repository.set_ip_override_fields(
                ip,
                conn=conn,
                whitelist=False,
                analyst_override="suppress_auto_block",
                blocked_until=None,
                cooldown_until=now + timedelta(seconds=self.config.cooldown_duration_seconds),
                blocked_reason=None,
                manual_blocked=False,
            )
            record = self.recalculate_ip_reputation(
                ip,
                trigger_reason="manual_unblock_requested",
                manual_or_auto="manual",
                now=now,
                conn=conn,
            )
        self.sync_blocklist()
        return record

    def force_unblock_ip(self, ip: str, duration_seconds: int | None = None) -> dict:
        """Admin-only: release an alert-hold block for a cooldown window, bypassing alert review."""
        now = utc_now()
        window = duration_seconds or self.config.suppress_duration_seconds
        return self._apply_override(
            ip,
            trigger_reason="force_unblock_requested",
            now=now,
            whitelist=False,
            analyst_override="force_unblock",
            blocked_until=None,
            cooldown_until=now + timedelta(seconds=max(1, window)),
            blocked_reason=None,
            manual_blocked=False,
        )

    def trust_ip(self, ip: str, *, whitelist: bool = True) -> dict:
        return self._apply_override(
            ip,
            trigger_reason="analyst_trusted_ip",
            whitelist=whitelist,
            analyst_override="trusted",
            blocked_until=None,
            cooldown_until=None,
            blocked_reason=None,
            manual_blocked=False,
        )

    def remove_trust_ip(self, ip: str) -> dict:
        return self._apply_override(
            ip,
            trigger_reason="analyst_removed_trust",
            whitelist=False,
            analyst_override=None,
            blocked_until=None,
            cooldown_until=None,
            blocked_reason=None,
            manual_blocked=False,
        )

    def suppress_auto_block(
        self,
        ip: str,
        *,
        duration_seconds: int | None = None,
        whitelist: bool | None = None,
    ) -> dict:
        now = utc_now()
        suppression_window = duration_seconds or self.config.suppress_duration_seconds
        with self.repository.ip_transaction(ip) as conn:
            existing = self._get_existing_record(ip, conn=conn)
            self.repository.set_ip_override_fields(
                ip,
                conn=conn,
                whitelist=existing.whitelist if whitelist is None else whitelist,
                analyst_override="suppress_auto_block",
                blocked_until=None,
                cooldown_until=now + timedelta(seconds=max(1, suppression_window)),
                blocked_reason=None,
                manual_blocked=False,
            )
            record = self.recalculate_ip_reputation(
                ip,
                trigger_reason="temporary_auto_block_suppression",
                manual_or_auto="manual",
                now=now,
                conn=conn,
            )
        self.sync_blocklist()
        return record

    def clear_override(self, ip: str) -> dict:
        with self.repository.ip_transaction(ip) as conn:
            existing = self._get_existing_record(ip, conn=conn)
            self.repository.set_ip_override_fields(
                ip,
                conn=conn,
                whitelist=existing.whitelist,
                analyst_override=None,
                blocked_until=None,
                cooldown_until=None,
                blocked_reason=None,
                manual_blocked=False,
            )
            record = self.recalculate_ip_reputation(
                ip,
                trigger_reason="analyst_cleared_override",
                manual_or_auto="manual",
                conn=conn,
            )
        self.sync_blocklist()
        return record

    def apply_ip_control(
        self,
        ip: str,
        action: str,
        *,
        reason: str | None = None,
        duration_seconds: int | None = None,
    ) -> dict:
        if action == "manual_block":
            return self.manual_block_ip(ip, reason)
        if action == "manual_unblock":
            return self.manual_unblock_ip(ip)
        if action == "force_unblock":
            return self.force_unblock_ip(ip, duration_seconds=duration_seconds)
        if action in {"trust", "whitelist"}:
            return self.trust_ip(ip, whitelist=action == "whitelist")
        if action in {"clear_trust", "unwhitelist"}:
            return self.remove_trust_ip(ip)
        if action == "suppress_auto_block":
            return self.suppress_auto_block(ip, duration_seconds=duration_seconds)
        if action == "clear_override":
            return self.clear_override(ip)

        raise ValueError(f"Unsupported IP control action: {action}")

    def _get_existing_record(self, ip: str, conn: Connection | None = None) -> IPReputationRecord:
        existing_row = (
            self.repository.get_ip_reputation(ip, conn=conn)
            if conn is not None
            else self.repository.get_ip_reputation(ip)
        )
        return build_record_from_row(existing_row) or IPReputationRecord(ip=ip)

    @staticmethod
    def _should_record_transition(
        previous_record: IPReputationRecord,
        evaluation,
        manual_or_auto: str,
    ) -> bool:
        if previous_record.current_state != evaluation.current_state:
            return True
        if previous_record.analyst_override != evaluation.analyst_override:
            return True
        if previous_record.whitelist != evaluation.whitelist:
            return True
        if previous_record.blocked_until != evaluation.blocked_until:
            return True
        if previous_record.cooldown_until != evaluation.cooldown_until:
            return True
        if previous_record.blocked_reason != evaluation.blocked_reason:
            return True
        if manual_or_auto == "manual":
            return True
        return abs(previous_record.current_score - evaluation.current_score) >= 15
