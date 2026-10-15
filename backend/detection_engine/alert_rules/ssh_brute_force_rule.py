from backend.models.siem_models import Alert, AlertStatus, EventType, Severity
from datetime import timedelta

import logging

logger = logging.getLogger(__name__)

class SSHBruteForceRule:
    RULE_ID = "SSH_BRUTE_FORCE"
    ATTEMPTS_LIMIT = 5
    TIME_WINDOW = timedelta(seconds=60)
    ALERT_RESET_TIME = timedelta(minutes=5)

    def __init__(self):
        self.failed_attempts = {}
        self.alerted_ips = set()
        self.last_attempt = {}

    def detect(self, event):
        if event.event_type not in (EventType.AUTHENTICATION_FAILURE, EventType.INVALID_USER_LOGIN):
            return None

        if event.source_ip is None:
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

        attempts.append(event.timestamp)

        cutoff = event.timestamp - self.TIME_WINDOW

        self.failed_attempts[event.source_ip] = [
            timestamp
            for timestamp in attempts
            if timestamp >= cutoff
        ]

        attempts = self.failed_attempts[event.source_ip]

        logger.info(
            "Brute-force check: IP=%s, attempts=%d",
            event.source_ip,
            len(attempts),
        )

        if len(attempts) >= self.ATTEMPTS_LIMIT:

            if event.source_ip in self.alerted_ips:
                return None

            self.alerted_ips.add(event.source_ip)

            return Alert(
                timestamp=event.timestamp,
                rule_id=self.RULE_ID,
                title="Possible SSH Brute Force Attack",
                description=(
                    f"{len(attempts)} failed SSH authentication "
                    f"attempts from {event.source_ip} "
                    f"within 60 seconds."
                ),
                severity=Severity.HIGH,
                status=AlertStatus.OPEN,
                source_ip=event.source_ip,
                affected_host=event.source,
                mitre_technique="T1110 - Brute Force",
                related_events=[event.id],
            )

        return None