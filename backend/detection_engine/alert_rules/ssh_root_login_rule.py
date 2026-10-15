from backend.models.siem_models import Alert, AlertStatus, Event, EventType, Severity


class SSHRootLoginRule:
    RULE_ID = "SSH_ROOT_LOGIN"

    def __init__(self):
        pass

    def detect(self, event: Event) -> Alert | None:
        if event.event_type is not EventType.AUTHENTICATION_SUCCESS:
            return

        if event.source_ip is None:
            return

        if event.username == "root":

            return Alert(
                timestamp=event.timestamp,
                rule_id=self.RULE_ID,
                title="Root login detected",
                description=(
                    f"Login with root access "
                    f"from {event.source_ip}."
                ),
                severity=Severity.HIGH,
                status=AlertStatus.OPEN,
                source_ip=event.source_ip,
                affected_host=event.source,
                mitre_technique="T1087 - Account Discovery",
                related_events=[event.id],
            )

        return None