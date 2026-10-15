from datetime import timedelta

from backend.models.siem_models import Alert, AlertStatus, Event, EventType, Severity


class SSHInvalidUserLogin:
    RULE_ID = "SSH_INVALID_USER_LOGIN_ATTEMPT"

    def __init__(self):
        pass

    def detect(self, event):
        if event.event_type is not EventType.INVALID_USER_LOGIN:
            return

        if event.source_ip is None:
            return

        return Alert(
            timestamp=event.timestamp,
            rule_id=self.RULE_ID,
            title="Attempted login with invalid user",
            description=(
                f"Attempted login with invalid user {event.username} "
                f"from {event.source_ip}."
            ),
            severity=Severity.LOW,
            status=AlertStatus.OPEN,
            source_ip=event.source_ip,
            affected_host=event.source,
            mitre_technique="T1087 - Account Discovery",
            related_events=[event.id],
        )


class SSHInvalidUserLoginEnumerationRule:

    RULE_ID = "SSH_USER_ENUMERATION"

    ATTEMPTS_LIMIT = 5
    TIME_WINDOW = timedelta(seconds=60)
    ALERT_RESET_TIME = timedelta(minutes=5)

    def __init__(self):
        self.failed_attempts = {}
        self.alerted_ips = set()
        self.last_attempt = {}

    def detect(self, event: Event) -> Alert | None:

        if event.event_type is not EventType.INVALID_USER_LOGIN:
            return None

        if event.source_ip is None:
            return None

        if event.username is None:
            return None

        if event.source_ip in self.alerted_ips:

            last_attempt = self.last_attempt[event.source_ip]

            if event.timestamp - last_attempt > self.ALERT_RESET_TIME:
                self.alerted_ips.remove(event.source_ip)

        self.last_attempt[event.source_ip] = event.timestamp

        attempts = self.failed_attempts.setdefault(
            event.source_ip,
            []
        )

        for attempt in attempts:
            if attempt[1] == event.username:
                return None

        attempts.append([
            event.timestamp,
            event.username
        ])

        cutoff = event.timestamp - self.TIME_WINDOW

        self.failed_attempts[event.source_ip] = [
            attempt
            for attempt in attempts
            if attempt[0] >= cutoff
        ]

        attempts = self.failed_attempts[event.source_ip]

        if len(attempts) < self.ATTEMPTS_LIMIT:
            return None

        if event.source_ip in self.alerted_ips:
            return None

        self.alerted_ips.add(event.source_ip)

        return Alert(
            timestamp=event.timestamp,
            rule_id=self.RULE_ID,
            title="Possible SSH user enumeration",
            description=(
                f"{len(attempts)} unique invalid user SSH login "
                f"attempts from {event.source_ip} " 
                f"within 60 seconds."
            ),
            severity=Severity.MEDIUM,
            status=AlertStatus.OPEN,
            source_ip=event.source_ip,
            affected_host=event.source,
            mitre_technique="T1087 - Account Discovery",
            related_events=[event.id],
        )