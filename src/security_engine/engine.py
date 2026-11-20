from __future__ import annotations

from src.core.http_models import DetectionAlert, HTTPLogEvent
from src.security_engine.detectors import build_detectors
from src.security_engine.enforcement_service import EnforcementService
from src.security_engine.repository import SecurityRepository


class SecurityEngine:
    def __init__(
        self,
        repository: SecurityRepository | None = None,
        enforcement_service: EnforcementService | None = None,
    ) -> None:
        self.repository = repository or SecurityRepository()
        self.enforcement_service = enforcement_service or EnforcementService(repository=self.repository)
        self.detectors = build_detectors()

    def process_event(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        event_id = self.repository.insert_event(event)
        alerts: list[DetectionAlert] = []

        for detector in self.detectors:
            alerts.extend(detector.evaluate(event))

        alerts_by_ip: dict[str, list[DetectionAlert]] = {}
        for alert in alerts:
            alert.event_id = event_id
            alerts_by_ip.setdefault(alert.ip, []).append(alert)

        synced_any = False
        try:
            for ip, ip_alerts in alerts_by_ip.items():
                # Insert and re-score under one per-IP advisory lock: the stored record is
                # computed from exactly the alerts this transaction commits.
                with self.repository.ip_transaction(ip) as conn:
                    alert_ids: list[int] = []
                    for alert in ip_alerts:
                        alert.id = self.repository.insert_alert(alert, conn=conn)
                        alert_ids.append(alert.id)
                    self.enforcement_service.recalculate_ip_reputation(
                        ip,
                        trigger_reason="new_alerts_detected",
                        source_alert_ids=alert_ids,
                        manual_or_auto="auto",
                        conn=conn,
                    )
                synced_any = True
        finally:
            if synced_any:
                self.enforcement_service.sync_blocklist()

        return alerts
