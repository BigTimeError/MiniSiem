from datetime import timedelta

from backend.models.siem_models import Alert, Correlation, Event, EventType


class SSHCompromiseChain:
    CORRELATION_ID = "SSH_COMPROMISE_CHAIN"
    TIME_WINDOW = timedelta(minutes=2)
    REQUIRED_ALERT_RULE = "SSH_BRUTE_FORCE"

    def __init__(self):
        self.alerts: list[Alert] = []
        self.events: list[Event] = []

        self.correlated_combinations: set[frozenset[int]] = set()
        self.correlated_alert_ids: set[int] = set()
        self.correlated_event_ids: set[int] = set()

    def correlate(self, event: Event, alert: Alert| None = None) -> Correlation | None:

        if alert is not None:
            if alert.source_ip is None:
                return None

            if alert.affected_host is None:
                return None

            if alert.id is None:
                return None

            self.alerts.append(alert)

        if event.source_ip is None:
            return None

        if event.id is None:
            return None

        self.events.append(event)

        cutoff = event.timestamp - self.TIME_WINDOW

        self.alerts = [
            existing
            for existing in self.alerts
            if existing.timestamp >= cutoff
        ]

        self.events = [
            existing
            for existing in self.events
            if existing.timestamp >= cutoff
        ]

        if event.event_type != EventType.AUTHENTICATION_SUCCESS:
            return None

        related_alerts = [
            existing
            for existing in self.alerts
            if existing.rule_id == self.REQUIRED_ALERT_RULE
            and existing.source_ip == event.source_ip
            and existing.affected_host == event.source
            and existing.id is not None
            and existing.id not in self.correlated_alert_ids
        ]

        if not related_alerts:
            return None

        if event.event_type != EventType.AUTHENTICATION_SUCCESS:
            return None

        if event.id in self.correlated_event_ids:
            return None

        latest_alert = max(
            related_alerts,
            key=lambda existing: existing.timestamp,
        )

        correlation_alert_ids = frozenset(
            {latest_alert.id}
        )

        correlation_event_ids = {
            event.id
        }

        combination = frozenset(
            list(correlation_alert_ids)
            + list(correlation_event_ids)
        )

        if combination in self.correlated_combinations:
            return None

        self.correlated_combinations.add(combination)

        self.correlated_alert_ids.update(
            correlation_alert_ids
        )

        self.correlated_event_ids.update(
            correlation_event_ids
        )

        return Correlation(
            timestamp=event.timestamp,
            correlation_rule_id=self.CORRELATION_ID,
            alerts=list(correlation_alert_ids),
            source_ip=event.source_ip,
            affected_host=event.source,
        )
