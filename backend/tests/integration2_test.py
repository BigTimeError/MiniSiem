from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.database.database import Base
from backend.models.siem_models import Event, EventType, Severity
from backend.storage.event_repository import EventRepository
from backend.storage.alert_repository import AlertRepository
from backend.storage.correlation_repository import CorrelationRepository

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

def test_event_is_processed(session):
    event_repository = EventRepository(session)
    alert_repository = AlertRepository(session)
    correlation_repository = CorrelationRepository(session)

    event = Event(
        timestamp=datetime.now(),
        source="test-host",
        event_type=EventType.AUTHENTICATION_FAILURE,
        severity=Severity.LOW,
        source_ip="10.0.0.50",
        source_port=54321,
        destination_port=22,
        username="testuser",
        service="ssh",
        message="Integration test",
        metadata={},
    )

    saved_event = event_repository.save(event)

    assert saved_event.id is not None

    # The event must initially be unprocessed.
    unprocessed_events = event_repository.get_unprocessed()

    assert any(
        event.id == saved_event.id
        for event in unprocessed_events
    )

    # Minimal test doubles for the detection/correlation/incident
    # pipeline.
    class TestDetectionEngine:
        def check_for_alerts(self, event):
            return []

    class TestCorrelationEngine:
        def check_for_correlations(self, alerts, event):
            return []

    class TestIncidentEngine:
        def process(self, correlation, alerts):
            raise AssertionError(
                "No incident should be generated"
            )

    incident_engine = TestIncidentEngine()
    detection_engine = TestDetectionEngine()
    correlation_engine = TestCorrelationEngine()

    process_events(
        event_repository,
        alert_repository,
        correlation_repository,
        incident_engine,
        detection_engine,
        correlation_engine,
    )

    # The event must now be marked as processed.
    unprocessed_events = event_repository.get_unprocessed()

    assert all(
        event.id != saved_event.id
        for event in unprocessed_events
    )