from datetime import timedelta

from backend.models.siem_models import Alert, Correlation, Event, EventType

# Still under construction!!! Not working the intended way, as any normal login into root would cause this correlation to fire!
class SSHPrivilegeEscalationChain:
    CORRELATION_ID = "SSH_PRIVILEGE_ESCALATION_CHAIN"
    TIME_WINDOW = timedelta(minutes=2)
    REQUIRED_ALERT_RULE = "SSH_ROOT_LOGIN"

    def __init__(self):
        self.alerts: list[Alert] = []
        self.events: list[Event] = []

        self.correlated_combinations: set[frozenset[int]] = set()
        self.correlated_alert_ids: set[int] = set()
        self.correlated_event_ids: set[int] = set()

    def correlate(self, event: Event, alert: Alert | None = None) -> Correlation | None:

        if alert is not None:
            if alert.source_ip is None:
                return None

            if alert.affected_host is None:
                return None

            if alert.id is None:
                return None

            self.alerts.append(alert)

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
            and existing.timestamp <= event.timestamp
        ]

        if alert is None:
            return None

        if alert.rule_id != self.REQUIRED_ALERT_RULE:
            return None

        related_events = [
            existing
            for existing in self.events
            if existing.event_type == EventType.AUTHENTICATION_SUCCESS
            and existing.source_ip == alert.source_ip
            and existing.source == alert.affected_host
            and existing.timestamp <= alert.timestamp
            and existing.id is not None
            and existing.id not in self.correlated_event_ids
        ]

        if not related_events:
            return None

        latest_event = max(
            related_events,
            key=lambda existing: existing.timestamp,
        )

        combination = frozenset({
            alert.id,
            latest_event.id,
        })

        if combination in self.correlated_combinations:
            return None

        self.correlated_combinations.add(combination)
        self.correlated_alert_ids.add(alert.id)
        self.correlated_event_ids.add(latest_event.id)

        return Correlation(
            timestamp=alert.timestamp,
            correlation_rule_id=self.CORRELATION_ID,
            alerts=[alert.id],
            source_ip=alert.source_ip,
            affected_host=alert.affected_host,
        )