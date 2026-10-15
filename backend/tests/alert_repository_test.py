from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.database.database import Base
from backend.models.siem_models import Alert, AlertStatus, Event, EventType, Severity
from backend.storage.alert_repository import AlertRepository
from backend.storage.event_repository import EventRepository


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


@pytest.fixture
def alert_repository(session):
    return AlertRepository(session)


@pytest.fixture
def event_repository(session):
    return EventRepository(session)


def create_event(event_repository, source_ip="192.168.1.10"):
    event = Event(
        timestamp=datetime.now(),
        source="ssh",
        event_type=EventType.AUTHENTICATION_FAILURE,
        severity=Severity.MEDIUM,
        source_ip=source_ip,
        service="ssh",
        message="Failed password for testuser",
    )

    return event_repository.save(event)


def create_alert(event_ids):
    return Alert(
        timestamp=datetime.now(),
        rule_id="SSH_BRUTE_FORCE",
        title="SSH brute force detected",
        description="Multiple failed SSH login attempts detected.",
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        source_ip="192.168.1.10",
        affected_host="server01",
        mitre_technique="T1110",
        related_events=event_ids,
    )


def test_save_alert(session, alert_repository, event_repository, ):
    event = create_event(event_repository)

    alert = create_alert([event.id])

    saved_alert = alert_repository.save(alert)

    assert saved_alert.id is not None
    assert saved_alert.rule_id == "SSH_BRUTE_FORCE"
    assert saved_alert.title == "SSH brute force detected"
    assert saved_alert.severity == Severity.HIGH
    assert saved_alert.status == AlertStatus.OPEN
    assert saved_alert.source_ip == "192.168.1.10"
    assert saved_alert.related_events == [event.id]


def test_get_by_id(alert_repository, event_repository, ):
    event = create_event(event_repository)

    alert = create_alert([event.id])
    saved_alert = alert_repository.save(alert)

    loaded_alert = alert_repository.get_by_id(saved_alert.id)

    assert loaded_alert is not None
    assert loaded_alert.id == saved_alert.id
    assert loaded_alert.rule_id == "SSH_BRUTE_FORCE"
    assert loaded_alert.related_events == [event.id]


def test_get_by_id_returns_none_for_unknown_id(alert_repository, ):
    result = alert_repository.get_by_id(999999)

    assert result is None


def test_alert_can_have_multiple_related_events(alert_repository, event_repository, ):
    event1 = create_event(event_repository)
    event2 = create_event(event_repository)
    event3 = create_event(event_repository)

    alert = create_alert([
        event1.id,
        event2.id,
        event3.id,
    ])

    saved_alert = alert_repository.save(alert)

    loaded_alert = alert_repository.get_by_id(saved_alert.id)

    assert loaded_alert is not None
    assert set(loaded_alert.related_events) == {
        event1.id,
        event2.id,
        event3.id,
    }


def test_get_recent(alert_repository, event_repository, ):
    event1 = create_event(event_repository)
    event2 = create_event(event_repository)

    alert1 = alert_repository.save(
        create_alert([event1.id])
    )

    alert2 = alert_repository.save(
        create_alert([event2.id])
    )

    alerts = alert_repository.get_recent()

    alert_ids = [alert.id for alert in alerts[0]]

    assert alert1.id in alert_ids
    assert alert2.id in alert_ids


def test_get_open(alert_repository, event_repository, ):
    event1 = create_event(event_repository)
    event2 = create_event(event_repository)

    open_alert = create_alert([event1.id])

    resolved_alert = create_alert([event2.id])
    resolved_alert.status = AlertStatus.RESOLVED

    saved_open = alert_repository.save(open_alert)
    saved_resolved = alert_repository.save(resolved_alert)

    open_alerts = alert_repository.get_open()

    open_ids = [alert.id for alert in open_alerts]

    assert saved_open.id in open_ids
    assert saved_resolved.id not in open_ids


def test_update_status(alert_repository, event_repository, ):
    event = create_event(event_repository)

    alert = create_alert([event.id])
    saved_alert = alert_repository.save(alert)

    updated_alert = alert_repository.update_status(
        saved_alert.id,
        AlertStatus.ACKNOWLEDGED,
    )

    assert updated_alert is not None
    assert updated_alert.id == saved_alert.id
    assert updated_alert.status == AlertStatus.ACKNOWLEDGED


def test_update_status_returns_none_for_unknown_id(alert_repository, ):
    result = alert_repository.update_status(
        999999,
        AlertStatus.RESOLVED,
    )

    assert result is None