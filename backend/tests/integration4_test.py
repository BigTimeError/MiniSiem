from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.database.database import Base
from backend.database.models import AlertDB, CorrelationDB, IncidentDB
from backend.correlation_engine.correlation_engine import CorrelationEngine
from backend.correlation_engine.correlation_rules.ssh_attack_chain_correlation import (
    SSHAttackChainCorrelation,
)
from backend.incident_engine.incident_engine import IncidentEngine
from backend.detection_engine.detection_engine import DetectionEngine
from backend.detection_engine.alert_rules.ssh_brute_force_rule import SSHBruteForceRule
from backend.detection_engine.alert_rules.ssh_invalid_user_login import (
    SSHInvalidUserLogin,
    SSHInvalidUserLoginEnumerationRule,
)
from main import process_events
from backend.models.siem_models import Event, EventType, Severity
from backend.storage.alert_repository import AlertRepository
from backend.storage.correlation_repository import CorrelationRepository
from backend.storage.event_repository import EventRepository
from backend.storage.incident_repository import IncidentRepository


DATABASE_URL = (
    "postgresql+psycopg://"
    "minisiem:minisiem_password"
    "@localhost:5432/minisiem_test"
)

@pytest.fixture
def session():
    engine = create_engine(DATABASE_URL)

    Base.metadata.create_all(engine)

    with Session(engine) as session:
        yield session

    Base.metadata.drop_all(engine)
    engine.dispose()


def test_event_triggers_alert_correlation_and_incident(session):
    event_repository = EventRepository(session)
    alert_repository = AlertRepository(session)
    correlation_repository = CorrelationRepository(session)

    detection_engine = DetectionEngine(
        [
            SSHBruteForceRule(),
            SSHInvalidUserLogin(),
            SSHInvalidUserLoginEnumerationRule(),
        ]
    )

    correlation_engine = CorrelationEngine(
        [
            SSHAttackChainCorrelation(),
        ]
    )

    incident_repository = IncidentRepository(session)

    incident_engine = IncidentEngine(
        incident_repository,
        alert_repository,
    )

    base_timestamp = datetime.now()

    source_ip = "10.0.0.50"
    host = "test-host"

    # Five failed authentication attempts.
    for i in range(5):
        event = Event(
            timestamp=base_timestamp + timedelta(seconds=i),
            source=host,
            event_type=EventType.AUTHENTICATION_FAILURE,
            severity=Severity.LOW,
            source_ip=source_ip,
            source_port=54321 + i,
            destination_port=22,
            username="testuser",
            service="ssh",
            message="Failed password",
            metadata={},
        )

        event_repository.save(event)

    # Five invalid logins with different usernames.
    for i in range(5):
        event = Event(
            timestamp=base_timestamp + timedelta(seconds=10 + i),
            source=host,
            event_type=EventType.INVALID_USER_LOGIN,
            severity=Severity.LOW,
            source_ip=source_ip,
            source_port=55000 + i,
            destination_port=22,
            username=f"invalid-user-{i}",
            service="ssh",
            message="Invalid user",
            metadata={},
        )

        event_repository.save(event)

    # Process all events through the real SIEM pipeline.
    process_events(
        event_repository,
        alert_repository,
        correlation_repository,
        incident_engine,
        detection_engine,
        correlation_engine,
    )

    alerts = session.scalars(
        select(AlertDB)
    ).all()

    correlations = session.scalars(
        select(CorrelationDB)
    ).all()

    incidents = session.scalars(
        select(IncidentDB)
    ).all()

    # Two alerts must have been generated.
    assert any(
        alert.rule_id == "SSH_BRUTE_FORCE"
        for alert in alerts
    )

    assert any(
        alert.rule_id == "SSH_USER_ENUMERATION"
        for alert in alerts
    )

    # The two alerts must have created an attack-chain correlation.
    attack_chain_correlations = [
        correlation
        for correlation in correlations
        if correlation.correlation_rule_id == "SSH_ATTACK_CHAIN"
    ]

    assert len(attack_chain_correlations) == 1

    correlation = attack_chain_correlations[0]

    assert correlation.source_ip == source_ip
    assert correlation.affected_host == host

    # The correlation must have generated an incident.
    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.source_ip == source_ip
    assert incident.affected_host == host

    # Every event must have been processed.
    unprocessed_events = event_repository.get_unprocessed()

    assert len(unprocessed_events) == 0