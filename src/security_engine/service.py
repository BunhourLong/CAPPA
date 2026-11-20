from __future__ import annotations

import io
import os
import signal
import time
from datetime import datetime
from pathlib import Path

from src.security_engine.enforcement import positive_float_env
from src.security_engine.engine import SecurityEngine
from src.security_engine.parser import LogParseError, parse_nginx_log_line


class LogMonitorService:
    IDLE_LOG_INTERVAL_SECONDS = 10.0
    MAX_LOG_LINE_PREVIEW_LENGTH = 200
    MAX_CONSECUTIVE_FAILURES = 20

    def __init__(self, engine: SecurityEngine | None = None) -> None:
        # Fail fast on bad config, before any DB work.
        self.refresh_interval_seconds = positive_float_env("REPUTATION_REFRESH_INTERVAL_SECONDS", 30.0)
        self.engine = engine or SecurityEngine()
        self.engine.enforcement_service.initialize()
        self._last_idle_log_at = 0.0
        self._last_reputation_refresh_at: float | None = None
        self.rejected_line_count = 0
        self._consecutive_failures = 0
        self._consecutive_tick_failures = 0

    def process_line(self, line: str):
        event = parse_nginx_log_line(line)
        alerts = self.engine.process_event(event)
        return event, alerts

    def maybe_refresh_reputations(self, monotonic_now: float | None = None, now: datetime | None = None) -> bool:
        """Periodic engine tick: refresh reputation for IPs with decay/expiry or new alerts due."""
        if monotonic_now is None:
            monotonic_now = time.monotonic()
        if (
            self._last_reputation_refresh_at is not None
            and monotonic_now - self._last_reputation_refresh_at < self.refresh_interval_seconds
        ):
            return False
        self._last_reputation_refresh_at = monotonic_now
        self.engine.enforcement_service.refresh_known_ip_states(trigger_reason="engine_tick", now=now)
        return True

    def _refresh_reputations_guarded(self) -> None:
        """Tail-loop wrapper: one tick failure must not kill the log tail."""
        try:
            ran = self.maybe_refresh_reputations()
        except Exception as exc:
            self._consecutive_tick_failures += 1
            self._log(
                f"Failed to refresh reputations: {type(exc).__name__} "
                f"(consecutive_tick_failures={self._consecutive_tick_failures})"
            )
            if self._consecutive_tick_failures >= self.MAX_CONSECUTIVE_FAILURES:
                self._log("Too many consecutive refresh failures, exiting")
                raise
            return
        if ran:
            self._consecutive_tick_failures = 0

    def run_forever(self, log_path: str) -> None:
        log_file = Path(log_path)
        self._log(f"Security engine started. Watching {log_file}")

        try:
            while True:
                if not log_file.exists():
                    self._refresh_reputations_guarded()
                    self._log_idle(log_file)
                    time.sleep(1.0)
                    continue

                try:
                    with log_file.open("r", encoding="utf-8", errors="replace") as stream:
                        self._log(f"Opened log file: {log_file}")
                        self._seek_to_end(stream)
                        self._reset_idle_log_timer()

                        while True:
                            self._refresh_reputations_guarded()
                            line = stream.readline()
                            if line:
                                self._reset_idle_log_timer()
                                self._log(f"Reading log line: {self._preview_line(line)}")
                                try:
                                    event, alerts = self.process_line(line)
                                except LogParseError:
                                    self.rejected_line_count += 1
                                    self._log(f"Rejected unparseable log line (total={self.rejected_line_count})")
                                    continue
                                except Exception as exc:  # one bad line must not stop the tail
                                    self.rejected_line_count += 1
                                    self._log(
                                        f"Failed to process log line: {type(exc).__name__} "
                                        f"(total={self.rejected_line_count})"
                                    )
                                    self._consecutive_failures += 1
                                    if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
                                        self._log("Too many consecutive processing failures, exiting")
                                        raise
                                    continue
                                self._consecutive_failures = 0

                                self._log(
                                    "Parsed event: "
                                    f"ip={event.ip} source={event.ip_source} "
                                    f"peer_ip={event.peer_ip} "
                                    f"x_forwarded_for={event.x_forwarded_for} "
                                    f"x_real_ip={event.x_real_ip} "
                                    f"endpoint={event.endpoint}"
                                )

                                for alert in alerts:
                                    self._log(
                                        "Alert triggered: "
                                        f"type={alert.alert_type} severity={alert.severity} "
                                        f"ip={alert.ip} endpoint={alert.endpoint}"
                                    )
                                continue

                            if not log_file.exists():
                                self._log(f"NGINX access log disappeared, waiting for {log_file}...")
                                self._reset_idle_log_timer()
                                break

                            self._log_idle(log_file)
                            time.sleep(0.5)
                except FileNotFoundError:
                    self._log_idle(log_file)
                    time.sleep(1.0)
        finally:
            self.engine.repository.close()

    @staticmethod
    def _seek_to_end(stream) -> None:
        try:
            if stream.seekable():
                stream.seek(0, os.SEEK_END)
        except (io.UnsupportedOperation, OSError):
            return

    @staticmethod
    def _log(message: str) -> None:
        print(f"[security_engine] {message}", flush=True)

    @classmethod
    def _preview_line(cls, line: str) -> str:
        preview = line.strip()
        if len(preview) <= cls.MAX_LOG_LINE_PREVIEW_LENGTH:
            return preview
        return f"{preview[: cls.MAX_LOG_LINE_PREVIEW_LENGTH - 3]}..."

    def _log_idle(self, log_file: Path) -> None:
        now = time.monotonic()
        if now - self._last_idle_log_at < self.IDLE_LOG_INTERVAL_SECONDS:
            return

        self._last_idle_log_at = now
        self._log(f"Waiting for logs... path={log_file}")

    def _reset_idle_log_timer(self) -> None:
        self._last_idle_log_at = time.monotonic()


def main() -> None:
    log_path = os.getenv("NGINX_ACCESS_LOG", "/var/log/nginx/access.log")

    def _on_sigterm(signum, frame) -> None:  # noqa: ARG001 - signal handler signature
        # Raise instead of exit so run_forever's finally closes the repository cleanly.
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _on_sigterm)
    LogMonitorService().run_forever(log_path)


if __name__ == "__main__":
    main()
