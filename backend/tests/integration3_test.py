from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.database.database import Base
from backend.models.siem_models import Event, EventType, Severity
from backend.storage.event_repository import EventRepository
from backend.storage.alert_repository import AlertRepository
from backend.storage.correlation_repository import CorrelationRepository

from backend.detection_engine.detection_engine import DetectionEngine
from backend.detection_engine.alert_rules.ssh_brute_force_rule import SSHBruteForceRule
from main import process_events


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

def test_event_triggers_brute_force_alert(session):
    event_repository = EventRepository(session)
    alert_repository = AlertRepository(session)
    correlation_repository = CorrelationRepository(session)

    detection_engine = DetectionEngine(
        [
            SSHBruteForceRule(),
        ]
    )

    class TestCorrelationEngine:
        def check_for_correlations(self, alerts, event):
            return []

    class TestIncidentEngine:
        def process(self, correlation, alerts):
            raise AssertionError(
                "No incident should be generated"
            )

    correlation_engine = TestCorrelationEngine()
    incident_engine = TestIncidentEngine()

    base_timestamp = datetime.now()

    # Create enough failed logins to trigger the brute-force rule.
    for i in range(5):
        event = Event(
            timestamp=base_timestamp + timedelta(seconds=i),
            source="test-host",
            event_type=EventType.AUTHENTICATION_FAILURE,
            severity=Severity.LOW,
            source_ip="10.0.0.50",
            source_port=54321 + i,
            destination_port=22,
            username="testuser",
            service="ssh",
            message="Failed password",
            metadata={},
        )

        event_repository.save(event)

    process_events(
        event_repository,
        alert_repository,
        correlation_repository,
        incident_engine,
        detection_engine,
        correlation_engine,
    )

    alerts = alert_repository.get_recent()

    assert len(alerts) > 0

    assert any(
        alert[0].source_ip == "10.0.0.50"
        for alert in alerts
    )