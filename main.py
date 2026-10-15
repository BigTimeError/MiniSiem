from pathlib import Path
import logging
import time

from sqlalchemy.orm import Session

from backend.api.event_stream import event_broker
from backend.correlation_engine.correlation_engine import CorrelationEngine
from backend.correlation_engine.correlation_rules.ssh_attack_chain_correlation import SSHAttackChainCorrelation
from backend.correlation_engine.correlation_rules.ssh_compromise_chain import SSHCompromiseChain
from backend.correlation_engine.correlation_rules.ssh_multi_host_attack import SSHMultiHostAttack
from backend.correlation_engine.correlation_rules.ssh_privilege_escalation_chain import SSHPrivilegeEscalationChain
from backend.detection_engine.alert_rules.ssh_invalid_user_login import (
    SSHInvalidUserLogin,
    SSHInvalidUserLoginEnumerationRule,
)
from backend.detection_engine.detection_engine import DetectionEngine
from backend.detection_engine.alert_rules.ssh_brute_force_rule import SSHBruteForceRule
from backend.detection_engine.alert_rules.ssh_root_login_rule import SSHRootLoginRule
from backend.incident_engine.incident_engine import IncidentEngine

from backend.storage.correlation_repository import CorrelationRepository
from backend.storage.event_repository import EventRepository
from backend.storage.alert_repository import AlertRepository
from backend.storage.incident_repository import IncidentRepository
from backend.database.database import SessionLocal

logger = logging.getLogger(__name__)


def process_events(
    event_repository,
    alert_repository,
    correlation_repository,
    incident_engine,
    detection_engine,
    correlation_engine,
):
    events = event_repository.get_unprocessed()

    for event in events:
        logger.info(
            "Processing event: %s",
            event.id,
        )

        # Detection
        alerts = detection_engine.check_for_alerts(event)
        saved_alerts = []

        for alert in alerts:
            saved_alert = alert_repository.save(alert)
            saved_alerts.append(saved_alert)

            logger.warning(
                "Alert generated: %s (%s)",
                saved_alert.title,
                saved_alert.severity,
            )

            event_broker.publish(
                "alert_created",
                {"id": saved_alert.id},
            )

        # Correlation
        correlations = correlation_engine.check_for_correlations(
            saved_alerts,
            event,
        )

        for correlation in correlations:
            saved_correlation = correlation_repository.save(
                correlation
            )

            logger.warning(
                "Correlation generated: %s",
                saved_correlation.correlation_rule_id,
            )

            event_broker.publish(
                "correlation_created",
                {"id": saved_correlation.id},
            )

            # Incident
            incident = incident_engine.process(
                saved_correlation,
                alerts,
            )

            logger.warning(
                "Incident generated: %s",
                incident.id,
            )

            event_broker.publish(
                "incident_created",
                {"id": incident.id},
            )

        # Event processing completed
        event_repository.mark_processed(event.id)

        event_broker.publish(
            "event_created",
            {"id": event.id},
        )


def siem_engine(session: Session):
    event_repository = EventRepository(session)
    alert_repository = AlertRepository(session)
    correlation_repository = CorrelationRepository(session)
    incident_repository = IncidentRepository(session)

    detection_engine = DetectionEngine(
        [
            SSHBruteForceRule(),
            SSHRootLoginRule(),
            SSHInvalidUserLogin(),
            SSHInvalidUserLoginEnumerationRule(),
        ]
    )

    correlation_engine = CorrelationEngine(
        [
            SSHAttackChainCorrelation(),
            SSHMultiHostAttack(),
            SSHCompromiseChain(),
        ]
    )

    incident_engine = IncidentEngine(
        incident_repository,
        alert_repository,
    )

    while True:
        process_events(
            event_repository,
            alert_repository,
            correlation_repository,
            incident_engine,
            detection_engine,
            correlation_engine,
        )

        time.sleep(0.1)


if __name__ == "__main__":
    with SessionLocal() as session:
        siem_engine(session)