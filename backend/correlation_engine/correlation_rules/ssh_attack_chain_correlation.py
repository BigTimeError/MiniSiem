from datetime import timedelta

from backend.models.siem_models import Alert, Correlation, Event


class SSHAttackChainCorrelation:
    CORRELATION_ID = "SSH_ATTACK_CHAIN"

    TIME_WINDOW = timedelta(minutes=2)

    REQUIRED_RULES = {
        "SSH_BRUTE_FORCE",
        "SSH_USER_ENUMERATION",
    }

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
            and existing.affected_host == alert.affected_host
            and existing.id not in self.correlated_alert_ids
        ]

        alerts_by_rule: dict[str, Alert] = {}

        for existing in related_alerts:
            if existing.rule_id not in self.REQUIRED_RULES:
                continue

            current = alerts_by_rule.get(existing.rule_id)

            if current is None or existing.timestamp > current.timestamp:
                alerts_by_rule[existing.rule_id] = existing

        if set(alerts_by_rule.keys()) != self.REQUIRED_RULES:
            return None

        correlation_alerts = list(alerts_by_rule.values())

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
            affected_host=alert.affected_host,
        )
