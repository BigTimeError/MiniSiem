from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.api.dependencies import get_db
from backend.api.main import app
from backend.correlation_engine.correlation_engine import CorrelationEngine
from backend.correlation_engine.correlation_rules.ssh_attack_chain_correlation import SSHAttackChainCorrelation
from backend.database.database import Base
from backend.database.models import EventDB
from backend.detection_engine.alert_rules.ssh_brute_force_rule import SSHBruteForceRule
from backend.detection_engine.alert_rules.ssh_invalid_user_login import SSHInvalidUserLogin, SSHInvalidUserLoginEnumerationRule
from backend.detection_engine.detection_engine import DetectionEngine
from backend.incident_engine.incident_engine import IncidentEngine
from main import process_events
from backend.models.siem_models import (
    Alert,
    AlertStatus,
    Correlation,
    Event,
    EventType,
    Host,
    Severity,
)
from backend.storage.alert_repository import AlertRepository
from backend.storage.correlation_repository import CorrelationRepository
from backend.storage.event_repository import EventRepository
from backend.storage.host_repository import HostRepository
from backend.storage.incident_repository import IncidentRepository


DATABASE_URL = (
    "postgresql+psycopg://"
    "minisiem:minisiem_password"
    "@localhost:5432/minisiem_test"
)

engine = create_engine(DATABASE_URL)


@pytest.fixture
def session():
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        yield session

    Base.metadata.drop_all(engine)


@pytest.fixture
def client(session):
    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


def create_event(session, source_ip = "192.168.1.100", event_type = EventType.AUTHENTICATION_FAILURE):
    repository = EventRepository(session)

    event = Event(
        timestamp=datetime(2026, 9, 25, 10, 0, 0),
        source="test-server",
        event_type=event_type,
        severity=Severity.MEDIUM,
        source_ip=source_ip,
        username="testuser",
        service="ssh",
        message="Failed password",
    )

    return repository.save(event)


def create_alert(session, event_id, severity = Severity.HIGH, status=AlertStatus.OPEN):
    repository = AlertRepository(session)

    alert = Alert(
        timestamp=datetime(2026, 9, 25, 10, 1, 0),
        rule_id="SSH_BRUTE_FORCE",
        title="SSH brute force detected",
        description="Multiple failed SSH login attempts.",
        severity=severity,
        status=status,
        source_ip="192.168.1.100",
        affected_host="test-server",
        mitre_technique="T1110",
        related_events=[event_id],
    )

    return repository.save(alert)

def create_correlation( session, alert_ids, timestamp=None, correlation_rule_id="SSH_ATTACK_CHAIN", source_ip="192.168.1.100", affected_host="test-server", ): 
    correlation = Correlation( 
        timestamp=timestamp or datetime.now(), 
        correlation_rule_id=correlation_rule_id, 
        alerts=alert_ids, 
        source_ip=source_ip, 
        affected_host=affected_host, 
    ) 
    repository = CorrelationRepository(session) 
    
    return repository.save(correlation)


def create_host(session):
    repository = HostRepository(session)

    host = Host(
        id="server01",
        hostname="server01",
        ip_address="10.0.0.10",
        events=0,
        alerts=0,
        status="healthy",
        last_seen=datetime(2026, 10, 8, 8, 0, 0),
    )

    return repository.save(host)


def test_root(client):
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["name"] == "MiniSIEM"
    assert data["status"] == "running"

def test_get_events(client, session):
    create_event(session)
    create_event(session)

    response = client.get("/events")

    assert response.status_code == 200

    data = response.json()

    assert len(data["items"]) == 2

def test_get_event_by_id(client, session):
    event = create_event(session)

    response = client.get(f"/events/{event.id}")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == event.id
    assert data["source"] == "test-server"
    assert data["source_ip"] == "192.168.1.100"
    assert data["username"] == "testuser"

def test_get_unknown_event(client):
    response = client.get("/events/999999")

    assert response.status_code == 404

    data = response.json()

    assert data["detail"] == "Event not found"

def test_get_events_limit(client, session):
    for _ in range(5):
        create_event(session)

    response = client.get("/events?limit=3")

    assert response.status_code == 200

    data = response.json()

    assert len(data["items"]) == 3

def test_get_events_invalid_limit(client):
    response = client.get("/events?limit=0")

    assert response.status_code == 422

def test_get_events_filter_by_source_ip(client, session):
    event1 = create_event(session)
    event2 = create_event(session, "193.168.1.100")

    response = client.get(
        "/events?source_ip=192.168.1.100"
    )

    assert response.status_code == 200

    data = response.json()

    assert all(
        event["source_ip"] == "192.168.1.100"
        for event in data["items"]
    )

def test_get_events_filter_by_event_type(client, session):
    create_event(session)

    response = client.get(
        "/events?event_type=authentication_failure"
    )

    assert response.status_code == 200

    data = response.json()

    assert all(
        event["event_type"] == "authentication_failure"
        for event in data["items"]
    )

def test_get_events_with_multiple_filters(client, session):
    create_event(session, "192.168.1.100", EventType.AUTHENTICATION_FAILURE)
    create_event(session, "193.168.1.100", EventType.AUTHENTICATION_FAILURE)
    create_event(session, "192.168.1.100", EventType.AUTHENTICATION_SUCCESS)
    create_event(session, "193.168.1.100", EventType.AUTHENTICATION_SUCCESS)

    response = client.get(
        "/events"
        "?source_ip=192.168.1.100"
        "&event_type=authentication_failure"
    )

    assert response.status_code == 200

    data = response.json()

    assert all(
        event["source_ip"] == "192.168.1.100"
        and event["event_type"] == "authentication_failure"
        for event in data["items"]
    )

def test_get_events_pagination(client, session):
    for _ in range(5):
        create_event(session)

    response = client.get(
        "/events?limit=2&offset=2"
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data["items"]) == 2

def test_get_events_invalid_offset(client):
    response = client.get("/events?offset=-1")

    assert response.status_code == 422


def test_get_events_filter_pagination(client, session):
    create_event(session)

    response = client.get(
        "/events"
        "?source_ip=192.168.1.100"
        "&event_type=authentication_failure"
        "&limit=10"
        "&offset=0"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] >= 1
    assert data["limit"] == 10
    assert data["offset"] == 0

    for event in data["items"]:
        assert event["source_ip"] == "192.168.1.100"
        assert event["event_type"] == "authentication_failure"


def test_get_alerts(client, session):
    event = create_event(session)

    create_alert(session, event.id)
    create_alert(session, event.id)

    response = client.get("/alerts")

    assert response.status_code == 200

    data = response.json()

    assert len(data["items"]) == 2

def test_get_alerts_pagination(client, session):
    event = create_event(session)

    for _ in range(5):
        create_alert(session, event.id)

    response = client.get(
        "/alerts?limit=2&offset=2"
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data["items"]) == 2

def test_get_alerts_filter_pagination(client, session):
    event = create_event(session)
    create_alert(session, event.id)
    
    response = client.get(
        "/alerts"
        "?severity=high"
        "&status=open"
        "&limit=10"
        "&offset=0"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] >= 1
    assert data["limit"] == 10
    assert data["offset"] == 0

    for alert in data["items"]:
        assert alert["severity"] == "high"
        assert alert["status"] == "open"

def test_get_alerts_invalid_offset(client):
    response = client.get("/alerts?offset=-1")

    assert response.status_code == 422

def test_get_alerts_filter_by_severity(client, session):
    event = create_event(session)

    create_alert(session, event.id, Severity.HIGH, AlertStatus.OPEN)
    create_alert(session, event.id, Severity.CRITICAL, AlertStatus.OPEN)
    

    response = client.get(
        "/alerts?severity=critical"
    )

    assert response.status_code == 200

    data = response.json()

    assert all(
        alert["severity"] == "critical"
        for alert in data["items"]
    )

def test_get_alerts_filter_by_status(client, session):
    event = create_event(session)

    create_alert(session, event.id, Severity.HIGH, AlertStatus.ACKNOWLEDGED)
    create_alert(session, event.id, Severity.HIGH, AlertStatus.OPEN)

    response = client.get(
        "/alerts?status=open"
    )

    assert response.status_code == 200

    data = response.json()

    assert all(
        alert["status"] == "open"
        for alert in data["items"]
    )

def test_get_alerts_with_multiple_filters(client, session):
    event = create_event(session)
    
    create_alert(session, event.id, Severity.HIGH, AlertStatus.ACKNOWLEDGED)
    create_alert(session, event.id, Severity.LOW, AlertStatus.OPEN)
    create_alert(session, event.id, Severity.HIGH, AlertStatus.OPEN)
    create_alert(session, event.id, Severity.LOW, AlertStatus.ACKNOWLEDGED)

    response = client.get(
        "/alerts"
        "?severity=high"
        "&status=open"
    )

    assert response.status_code == 200

    data = response.json()

    assert all(
        alert["severity"] == "high"
        and alert["status"] == "open"
        for alert in data["items"]
    )

def test_get_alert_by_id(client, session):
    event = create_event(session)
    alert = create_alert(session, event.id)

    response = client.get(f"/alerts/{alert.id}")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == alert.id
    assert data["rule_id"] == "SSH_BRUTE_FORCE"
    assert data["severity"] == "high"
    assert data["status"] == "open"

def test_get_unknown_alert(client):
    response = client.get("/alerts/999999")

    assert response.status_code == 404

    data = response.json()

    assert data["detail"] == "Alert not found"

def test_get_open_alerts(client, session):
    event = create_event(session)

    alert = create_alert(session, event.id)

    response = client.get("/alerts/open")

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == alert.id
    assert data[0]["status"] == "open"

def test_get_open_alerts_only_returns_open_alerts(client, session):
    event = create_event(session)

    alert = create_alert(session, event.id)

    repository = AlertRepository(session)

    repository.update_status(
        alert.id,
        AlertStatus.RESOLVED,
    )

    response = client.get("/alerts/open")

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 0

def test_patch_alert_status(client, session):
    event = create_event(session)
    alert = create_alert(session, event.id)

    response = client.patch(
        f"/alerts/{alert.id}/status",
        json={
            "status": "acknowledged",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == alert.id
    assert data["status"] == "acknowledged"

def test_patch_alert_status_persists(client, session):
    event = create_event(session)
    alert = create_alert(session, event.id)

    response = client.patch(
        f"/alerts/{alert.id}/status",
        json={
            "status": "resolved",
        },
    )

    assert response.status_code == 200

    repository = AlertRepository(session)

    updated_alert = repository.get_by_id(alert.id)

    assert updated_alert is not None
    assert updated_alert.status == AlertStatus.RESOLVED

def test_patch_unknown_alert_status(client):
    response = client.patch(
        "/alerts/999999/status",
        json={
            "status": "resolved",
        },
    )

    assert response.status_code == 404

def test_patch_alert_invalid_status(client, session):
    event = create_event(session)
    alert = create_alert(session, event.id)

    response = client.patch(
        f"/alerts/{alert.id}/status",
        json={
            "status": "something_invalid",
        },
    )

    assert response.status_code == 422


def test_get_correlations(client, session):
    event = create_event(session)

    alert1 = create_alert(session, event.id)
    alert2 = create_alert(session, event.id)

    create_correlation(
        session,
        [alert1.id, alert2.id],
    )

    response = client.get("/correlations")

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert len(data["items"]) == 1

    correlation = data["items"][0]

    assert correlation["correlation_rule_id"] == "SSH_ATTACK_CHAIN"
    assert correlation["source_ip"] == "192.168.1.100"
    assert correlation["affected_host"] == "test-server"
    assert set(correlation["alerts"]) == {
        alert1.id,
        alert2.id,
    }


def test_get_correlations_pagination(client, session):
    event = create_event(session)

    for _ in range(5):
        alert = create_alert(session, event.id)

        create_correlation(
            session,
            [alert.id],
        )

    response = client.get(
        "/correlations?limit=2&offset=1"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 5
    assert len(data["items"]) == 2
    assert data["limit"] == 2
    assert data["offset"] == 1


def test_get_correlations_filter_by_source_ip(client, session):
    event = create_event(session)

    alert1 = create_alert(session, event.id)
    alert2 = create_alert(session, event.id)

    create_correlation(
        session,
        [alert1.id],
        source_ip="192.168.1.100",
    )

    create_correlation(
        session,
        [alert2.id],
        source_ip="192.168.1.200",
    )

    response = client.get(
        "/correlations?source_ip=192.168.1.100"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert len(data["items"]) == 1

    assert data["items"][0]["source_ip"] == "192.168.1.100"


def test_get_correlations_filter_by_affected_host(client, session):
    event = create_event(session)

    alert1 = create_alert(session, event.id)
    alert2 = create_alert(session, event.id)

    create_correlation(
        session,
        [alert1.id],
        affected_host="server01",
    )

    create_correlation(
        session,
        [alert2.id],
        affected_host="server02",
    )

    response = client.get(
        "/correlations?affected_host=server01"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert len(data["items"]) == 1

    assert data["items"][0]["affected_host"] == "server01"


def test_get_correlations_with_multiple_filters(client, session):
    event = create_event(session)

    alert1 = create_alert(session, event.id)
    alert2 = create_alert(session, event.id)
    alert3 = create_alert(session, event.id)

    create_correlation(
        session,
        [alert1.id],
        source_ip="192.168.1.100",
        affected_host="server01",
    )

    create_correlation(
        session,
        [alert2.id],
        source_ip="192.168.1.100",
        affected_host="server02",
    )

    create_correlation(
        session,
        [alert3.id],
        source_ip="192.168.1.200",
        affected_host="server01",
    )

    response = client.get(
        "/correlations"
        "?source_ip=192.168.1.100"
        "&affected_host=server01"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert len(data["items"]) == 1

    correlation = data["items"][0]

    assert correlation["source_ip"] == "192.168.1.100"
    assert correlation["affected_host"] == "server01"


def test_get_correlations_invalid_limit(client):
    response = client.get(
        "/correlations?limit=0"
    )

    assert response.status_code == 422


def test_get_correlations_invalid_offset(client):
    response = client.get(
        "/correlations?offset=-1"
    )

    assert response.status_code == 422


def test_get_correlations_count(client, session):
    event = create_event(session)

    alert1 = create_alert(session, event.id)
    alert2 = create_alert(session, event.id)

    create_correlation(
        session,
        [alert1.id],
    )

    create_correlation(
        session,
        [alert2.id],
    )

    response = client.get("/correlations/count")

    assert response.status_code == 200
    assert response.json() == 2


def test_get_correlations_count_returns_zero(client):
    response = client.get("/correlations/count")

    assert response.status_code == 200
    assert response.json() == 0


def test_get_correlation_by_id(client, session):
    event = create_event(session)

    alert = create_alert(session, event.id)

    correlation = create_correlation(
        session,
        [alert.id],
    )

    response = client.get(
        f"/correlations/{correlation.id}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == correlation.id
    assert data["correlation_rule_id"] == "SSH_ATTACK_CHAIN"
    assert data["source_ip"] == "192.168.1.100"
    assert data["affected_host"] == "test-server"
    assert data["alerts"] == [alert.id]


def test_get_unknown_correlation(client):
    response = client.get(
        "/correlations/999999"
    )

    assert response.status_code == 404

    data = response.json()

    assert data["detail"] == "Correlation not found"


def test_ingest_event(client, session):
    create_host(session)

    response = client.post(
        "/events",
        json={
            "host_id": "server01",
            "timestamp": "2026-10-08T08:30:00",
            "event_type": "authentication_failure",
            "severity": "low",
            "source_ip": "10.0.0.50",
            "source_port": 54321,
            "destination_port": 22,
            "username": "root",
            "service": "ssh",
            "message": "Failed password for root",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["id"] is not None
    assert data["source"] == "server01"
    assert data["event_type"] == "authentication_failure"
    assert data["severity"] == "low"
    assert data["source_ip"] == "10.0.0.50"
    assert data["username"] == "root"

def test_ingest_event_unknown_host(client):
    response = client.post(
        "/events",
        json={
            "host_id": "unknown",
            "timestamp": "2026-10-08T08:30:00",
            "event_type": "authentication_failure",
            "severity": "low",
        },
    )

    assert response.status_code == 404


def test_ingested_event_is_processed_by_siem(client, session):
    create_host(session)

    response = client.post(
        "/events",
        json={
            "host_id": "server01",
            "timestamp": "2026-10-08T08:30:00",
            "event_type": "authentication_failure",
            "severity": "high",
            "source_ip": "10.0.0.50",
            "source_port": 54321,
            "destination_port": 22,
            "username": "root",
            "service": "ssh",
            "message": "Failed password for root",
        },
    )

    assert response.status_code == 201

    event_id = response.json()["id"]

    event_db = session.get(EventDB, event_id)

    assert event_db is not None
    assert event_db.processed is False

    event_repository = EventRepository(session)
    alert_repository = AlertRepository(session)
    correlation_repository = CorrelationRepository(session)
    incident_repository = IncidentRepository(session)

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

    incident_engine = IncidentEngine(
        incident_repository,
        alert_repository,
    )

    process_events(
        event_repository,
        alert_repository,
        correlation_repository,
        incident_engine,
        detection_engine,
        correlation_engine,
    )

    event_db = session.get(EventDB, event_id)

    assert event_db is not None
    assert event_db.processed is True