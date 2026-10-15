from datetime import timedelta

from backend.models.siem_models import Alert, Correlation, Event


class SSHMultiHostAttack:
    CORRELATION_ID = "SSH_MULTI_HOST_ATTACK"

    TIME_WINDOW = timedelta(minutes=2)

    def __init__(self):
        self.alerts: list[Alert] = []
        self.correlated_combinations: set[frozenset[int]] = set()
        self.correlated_alert_ids: set[int] = set()

    def correlate(self, event: Event, alert: Alert) -> Correlation | None:
        if alert is None:
            return None

        if alert.source_ip is None:
            return None

        if alert.affected_host is None:
            return None

        if alert.id is None:
            return None

        self.alerts.append(alert)

        cutoff = alert.timestamp - self.TIME_WINDOW

        self.alerts = [
            existing
            for existing in self.alerts
            if existing.timestamp >= cutoff
        ]

        related_alerts = [
            existing
            for existing in self.alerts
            if existing.source_ip == alert.source_ip
            and existing.affected_host is not None
            and existing.id not in self.correlated_alert_ids
        ]

        hosts = {
            existing.affected_host
            for existing in related_alerts
        }

        if len(hosts) < 2:
            return None

        correlation_alerts = []

        for host in hosts:
            host_alerts = [
                existing
                for existing in related_alerts
                if existing.affected_host == host
            ]

            latest_alert = max(
                host_alerts,
                key=lambda existing: existing.timestamp,
            )

            correlation_alerts.append(latest_alert)

        correlation_alert_ids = frozenset(
            existing.id
            for existing in correlation_alerts
            if existing.id is not None
        )

        if correlation_alert_ids in self.correlated_combinations:
            return None

        self.correlated_combinations.add(correlation_alert_ids)
        self.correlated_alert_ids.update(correlation_alert_ids)

        return Correlation(
            timestamp=alert.timestamp,
            correlation_rule_id=self.CORRELATION_ID,
            alerts=list(correlation_alert_ids),
            source_ip=alert.source_ip,
            affected_host=None,
        )
