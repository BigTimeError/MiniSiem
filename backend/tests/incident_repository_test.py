from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.database.database import Base
from backend.models.siem_models import (
    Alert,
    AlertStatus,
    Correlation,
    Incident,
    IncidentStatus,
    Severity,
)
from backend.storage.alert_repository import AlertRepository
from backend.storage.correlation_repository import CorrelationRepository
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


@pytest.fixture
def incident_repository(session):
    return IncidentRepository(session)


@pytest.fixture
def alert_repository(session):
    return AlertRepository(session)


@pytest.fixture
def correlation_repository(session):
    return CorrelationRepository(session)


def create_alert():
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
        related_events=[],
    )


def create_correlation(alert_id):
    return Correlation(
        timestamp=datetime.now(),
        correlation_rule_id="SSH_COMPROMISE_CHAIN",
        source_ip="192.168.1.10",
        affected_host="server01",
        alerts=[alert_id],
    )


def create_incident(
    related_alerts=None,
    related_correlations=None,
):
    return Incident(
        timestamp=datetime.now(),
        title="Possible SSH compromise",
        description="A possible SSH compromise was detected.",
        severity=Severity.CRITICAL,
        status=IncidentStatus.OPEN,
        source_ip="192.168.1.10",
        affected_host="server01",
        related_alerts=related_alerts or [],
        related_correlations=related_correlations or [],
    )


def test_save_incident(incident_repository):
    incident = create_incident()

    saved_incident = incident_repository.save(incident)

    assert saved_incident.id is not None
    assert saved_incident.title == "Possible SSH compromise"
    assert saved_incident.description == "A possible SSH compromise was detected."
    assert saved_incident.severity == Severity.CRITICAL
    assert saved_incident.status == IncidentStatus.OPEN
    assert saved_incident.source_ip == "192.168.1.10"
    assert saved_incident.affected_host == "server01"
    assert saved_incident.related_alerts == []
    assert saved_incident.related_correlations == []


def test_get_by_id(incident_repository):
    incident = create_incident()

    saved_incident = incident_repository.save(incident)

    loaded_incident = incident_repository.get_by_id(
        saved_incident.id
    )

    assert loaded_incident is not None
    assert loaded_incident.id == saved_incident.id
    assert loaded_incident.title == "Possible SSH compromise"
    assert loaded_incident.severity == Severity.CRITICAL
    assert loaded_incident.status == IncidentStatus.OPEN


def test_get_by_id_returns_none_for_unknown_id(
    incident_repository,
):
    result = incident_repository.get_by_id(999999)

    assert result is None


def test_incident_can_have_multiple_related_alerts(
    incident_repository,
    alert_repository,
):
    alert1 = alert_repository.save(create_alert())
    alert2 = alert_repository.save(create_alert())
    alert3 = alert_repository.save(create_alert())

    incident = create_incident(
        related_alerts=[
            alert1.id,
            alert2.id,
            alert3.id,
        ]
    )

    saved_incident = incident_repository.save(incident)

    loaded_incident = incident_repository.get_by_id(
        saved_incident.id
    )

    assert loaded_incident is not None
    assert set(loaded_incident.related_alerts) == {
        alert1.id,
        alert2.id,
        alert3.id,
    }


def test_incident_can_have_multiple_related_correlations(
    incident_repository,
    alert_repository,
    correlation_repository,
):
    alert1 = alert_repository.save(create_alert())
    alert2 = alert_repository.save(create_alert())

    correlation1 = correlation_repository.save(
        create_correlation(alert1.id),
    )

    correlation2 = correlation_repository.save(
        create_correlation(alert2.id),
    )

    incident = create_incident(
        related_correlations=[
            correlation1.id,
            correlation2.id,
        ]
    )

    saved_incident = incident_repository.save(incident)

    loaded_incident = incident_repository.get_by_id(
        saved_incident.id
    )

    assert loaded_incident is not None
    assert set(loaded_incident.related_correlations) == {
        correlation1.id,
        correlation2.id,
    }


def test_incident_can_have_alerts_and_correlations(
    incident_repository,
    alert_repository,
    correlation_repository,
):
    alert = alert_repository.save(create_alert())

    correlation = correlation_repository.save(
        create_correlation(alert.id),
    )

    incident = create_incident(
        related_alerts=[alert.id],
        related_correlations=[correlation.id],
    )

    saved_incident = incident_repository.save(incident)

    loaded_incident = incident_repository.get_by_id(
        saved_incident.id
    )

    assert loaded_incident is not None
    assert loaded_incident.id == saved_incident.id
    assert loaded_incident.related_alerts == [alert.id]
    assert loaded_incident.related_correlations == [correlation.id]


def test_get_recent(
    incident_repository,
):
    incident1 = incident_repository.save(
        create_incident()
    )

    incident2 = incident_repository.save(
        create_incident()
    )

    incidents = incident_repository.get_recent()

    incident_ids = [
        incident.id
        for incident in incidents[0]
    ]

    assert incident1.id in incident_ids
    assert incident2.id in incident_ids


def test_get_recent_filters_by_severity(
    incident_repository,
):
    critical_incident = create_incident()
    critical_incident.severity = Severity.CRITICAL

    high_incident = create_incident()
    high_incident.severity = Severity.HIGH

    saved_critical = incident_repository.save(
        critical_incident
    )

    saved_high = incident_repository.save(
        high_incident
    )

    incidents = incident_repository.get_recent(
        severity=Severity.CRITICAL
    )

    incident_ids = [
        incident.id
        for incident in incidents[0]
    ]

    assert saved_critical.id in incident_ids
    assert saved_high.id not in incident_ids


def test_get_recent_filters_by_status(
    incident_repository,
):
    open_incident = create_incident()
    open_incident.status = IncidentStatus.OPEN

    resolved_incident = create_incident()
    resolved_incident.status = IncidentStatus.RESOLVED

    saved_open = incident_repository.save(
        open_incident
    )

    saved_resolved = incident_repository.save(
        resolved_incident
    )

    incidents = incident_repository.get_recent(
        status=IncidentStatus.OPEN
    )

    incident_ids = [
        incident.id
        for incident in incidents[0]
    ]

    assert saved_open.id in incident_ids
    assert saved_resolved.id not in incident_ids


def test_get_recent_filters_by_affected_host(
    incident_repository,
):
    server1_incident = create_incident()
    server1_incident.affected_host = "server01"

    server2_incident = create_incident()
    server2_incident.affected_host = "server02"

    saved_server1 = incident_repository.save(
        server1_incident
    )

    saved_server2 = incident_repository.save(
        server2_incident
    )

    incidents = incident_repository.get_recent(
        affected_host="server01"
    )

    incident_ids = [
        incident.id
        for incident in incidents[0]
    ]

    assert saved_server1.id in incident_ids
    assert saved_server2.id not in incident_ids


def test_get_count(
    incident_repository,
):
    incident_repository.save(
        create_incident()
    )

    incident_repository.save(
        create_incident()
    )

    assert incident_repository.get_count() == 2