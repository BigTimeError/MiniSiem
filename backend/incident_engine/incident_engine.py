from backend.models.siem_models import (
    Alert,
    Correlation,
    Incident,
    IncidentStatus,
    Severity,
)
from backend.storage.alert_repository import AlertRepository
from backend.storage.incident_repository import IncidentRepository


class IncidentEngine:

    def __init__(
        self,
        incident_repository: IncidentRepository,
        alert_repository: AlertRepository,
    ):
        self.incident_repository = incident_repository
        self.alert_repository = alert_repository

    def process(
        self,
        correlation: Correlation,
        alerts: list[Alert],
    ) -> Incident:

        related_alerts = self._get_related_alerts(
            correlation,
            alerts,
        )

        existing_incident = self.incident_repository.find_open_incident(
            source_ip=correlation.source_ip,
            affected_host=correlation.affected_host,
        )

        if existing_incident is not None:
            incident = existing_incident

            for alert in related_alerts:
                if alert.id is not None:
                    incident = self.incident_repository.add_alert(
                        incident.id,
                        alert.id,
                    )

            if correlation.id is not None:
                incident = self.incident_repository.add_correlation(
                    incident.id,
                    correlation.id,
                )

            return incident

        related_alert_ids = [
            alert.id
            for alert in related_alerts
            if alert.id is not None
        ]

        related_correlation_ids = []

        if correlation.id is not None:
            related_correlation_ids.append(correlation.id)

        incident = Incident(
            timestamp=correlation.timestamp,
            title=self._build_title(correlation),
            description=self._build_description(
                correlation,
                related_alerts,
            ),
            severity=self._calculate_severity(
                related_alerts,
            ),
            status=IncidentStatus.OPEN,
            source_ip=correlation.source_ip,
            affected_host=correlation.affected_host,
            related_alerts=related_alert_ids,
            related_correlations=related_correlation_ids,
        )

        return self.incident_repository.save(incident)

    def _get_related_alerts(
        self,
        correlation: Correlation,
        alerts: list[Alert],
    ) -> list[Alert]:

        alerts_by_id = {
            alert.id: alert
            for alert in alerts
            if alert.id is not None
        }

        related_alerts = []

        for alert_id in correlation.alerts:
            if alert_id in alerts_by_id:
                related_alerts.append(alerts_by_id[alert_id])
                continue

            alert = self.alert_repository.get_by_id(alert_id)

            if alert is not None:
                related_alerts.append(alert)

        return related_alerts

    def _build_title(self, correlation: Correlation) -> str:
        if correlation.correlation_rule_id == "SSH_COMPROMISE_CHAIN":
            return "Possible SSH Server Compromise"

        if correlation.correlation_rule_id == "SSH_ATTACK_CHAIN":
            return "SSH Attack Chain Detected"

        if correlation.correlation_rule_id == "SSH_MULTI_HOST_ATTACK":
            return "SSH Multi-Host Attack Detected"

        return "Security Incident Detected"

    def _build_description(
        self,
        correlation: Correlation,
        alerts: list[Alert],
    ) -> str:
        return (
            f"Correlation {correlation.correlation_rule_id} "
            f"indicates a possible security incident. "
            f"The incident is associated with "
            f"{len(alerts)} alert(s)."
        )

    def _calculate_severity(
        self,
        alerts: list[Alert],
    ) -> Severity:

        if any(alert.severity == Severity.CRITICAL for alert in alerts):
            return Severity.CRITICAL

        if any(alert.severity == Severity.HIGH for alert in alerts):
            return Severity.HIGH

        if any(alert.severity == Severity.MEDIUM for alert in alerts):
            return Severity.MEDIUM

        return Severity.LOW