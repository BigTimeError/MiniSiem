from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.database.database import Base
from backend.database.models import (
    AlertDB,
    CorrelationAlertDB,
    CorrelationDB,
)
from backend.models.siem_models import (
    AlertStatus,
    Correlation,
    Severity,
)
from backend.storage.correlation_repository import CorrelationRepository


DATABASE_URL = (
    "postgresql+psycopg://"
    "minisiem:minisiem_password"
    "@localhost:5432/minisiem_test"
)


@pytest.fixture
def db_session():
    engine = create_engine(DATABASE_URL)

    Base.metadata.create_all(engine)

    with Session(engine) as session:
        yield session

    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def correlation_repository(db_session):
    return CorrelationRepository(db_session)


def create_alert(
    db_session,
    timestamp: datetime,
    source_ip: str,
    affected_host: str,
) -> AlertDB:
    alert = AlertDB(
        timestamp=timestamp,
        rule_id="SSH_BRUTE_FORCE",
        title="SSH Brute Force",
        description="Possible SSH brute force attack",
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        source_ip=source_ip,
        affected_host=affected_host,
        mitre_technique="T1110 - Brute Force",
    )

    db_session.add(alert)
    db_session.flush()

    return alert


def create_correlation(
    db_session,
    timestamp: datetime,
    correlation_rule_id: str,
    source_ip: str,
    affected_host: str,
    alert_ids: list[int],
) -> CorrelationDB:
    correlation = CorrelationDB(
        timestamp=timestamp,
        correlation_rule_id=correlation_rule_id,
        source_ip=source_ip,
        affected_host=affected_host,
    )

    db_session.add(correlation)
    db_session.flush()

    for alert_id in alert_ids:
        correlation_alert = CorrelationAlertDB(
            correlation_id=correlation.id,
            alert_id=alert_id,
        )

        db_session.add(correlation_alert)

    db_session.flush()

    return correlation


def test_save_correlation(db_session):
    repository = CorrelationRepository(db_session)

    now = datetime.now()

    alert1 = create_alert(
        db_session,
        now,
        "10.0.0.50",
        "server01",
    )

    alert2 = create_alert(
        db_session,
        now + timedelta(seconds=30),
        "10.0.0.50",
        "server01",
    )

    correlation = repository.save(
        Correlation(
            timestamp=now + timedelta(seconds=30),
            correlation_rule_id="SSH_ATTACK_CHAIN",
            source_ip="10.0.0.50",
            affected_host="server01",
            alerts=[
                alert1.id,
                alert2.id,
            ],
        )
    )

    assert correlation.id is not None
    assert correlation.correlation_rule_id == "SSH_ATTACK_CHAIN"
    assert correlation.source_ip == "10.0.0.50"
    assert correlation.affected_host == "server01"
    assert set(correlation.alerts) == {
        alert1.id,
        alert2.id,
    }


def test_get_by_id(db_session):
    repository = CorrelationRepository(db_session)

    now = datetime.now()

    alert = create_alert(
        db_session,
        now,
        "10.0.0.50",
        "server01",
    )

    correlation_db = create_correlation(
        db_session,
        now,
        "SSH_ATTACK_CHAIN",
        "10.0.0.50",
        "server01",
        [alert.id],
    )

    correlation = repository.get_by_id(correlation_db.id)

    assert correlation is not None
    assert correlation.id == correlation_db.id
    assert correlation.correlation_rule_id == "SSH_ATTACK_CHAIN"
    assert correlation.source_ip == "10.0.0.50"
    assert correlation.affected_host == "server01"
    assert correlation.alerts == [alert.id]


def test_get_by_id_returns_none_for_unknown_id(db_session):
    repository = CorrelationRepository(db_session)

    correlation = repository.get_by_id(999999)

    assert correlation is None


def test_get_recent(db_session):
    repository = CorrelationRepository(db_session)

    now = datetime.now()

    alert1 = create_alert(
        db_session,
        now,
        "10.0.0.50",
        "server01",
    )

    alert2 = create_alert(
        db_session,
        now + timedelta(minutes=1),
        "10.0.0.51",
        "server02",
    )

    correlation1 = create_correlation(
        db_session,
        now,
        "SSH_ATTACK_CHAIN",
        "10.0.0.50",
        "server01",
        [alert1.id],
    )

    correlation2 = create_correlation(
        db_session,
        now + timedelta(minutes=1),
        "SSH_ATTACK_CHAIN",
        "10.0.0.51",
        "server02",
        [alert2.id],
    )

    correlations, total = repository.get_recent()

    assert total == 2
    assert len(correlations) == 2

    assert correlations[0].id == correlation2.id
    assert correlations[1].id == correlation1.id


def test_get_recent_filters_by_source_ip(db_session):
    repository = CorrelationRepository(db_session)

    now = datetime.now()

    alert1 = create_alert(
        db_session,
        now,
        "10.0.0.50",
        "server01",
    )

    alert2 = create_alert(
        db_session,
        now,
        "10.0.0.51",
        "server01",
    )

    create_correlation(
        db_session,
        now,
        "SSH_ATTACK_CHAIN",
        "10.0.0.50",
        "server01",
        [alert1.id],
    )

    create_correlation(
        db_session,
        now + timedelta(seconds=1),
        "SSH_ATTACK_CHAIN",
        "10.0.0.51",
        "server01",
        [alert2.id],
    )

    correlations, total = repository.get_recent(
        source_ip="10.0.0.50"
    )

    assert total == 1
    assert len(correlations) == 1
    assert correlations[0].source_ip == "10.0.0.50"


def test_get_recent_filters_by_affected_host(db_session):
    repository = CorrelationRepository(db_session)

    now = datetime.now()

    alert1 = create_alert(
        db_session,
        now,
        "10.0.0.50",
        "server01",
    )

    alert2 = create_alert(
        db_session,
        now,
        "10.0.0.50",
        "server02",
    )

    create_correlation(
        db_session,
        now,
        "SSH_ATTACK_CHAIN",
        "10.0.0.50",
        "server01",
        [alert1.id],
    )

    create_correlation(
        db_session,
        now + timedelta(seconds=1),
        "SSH_ATTACK_CHAIN",
        "10.0.0.50",
        "server02",
        [alert2.id],
    )

    correlations, total = repository.get_recent(
        affected_host="server01"
    )

    assert total == 1
    assert len(correlations) == 1
    assert correlations[0].affected_host == "server01"


def test_get_recent_pagination(db_session):
    repository = CorrelationRepository(db_session)

    now = datetime.now()

    alert_ids = []

    for index in range(3):
        alert = create_alert(
            db_session,
            now + timedelta(minutes=index),
            "10.0.0.50",
            "server01",
        )

        alert_ids.append(alert.id)

    correlation_ids = []

    for index, alert_id in enumerate(alert_ids):
        correlation = create_correlation(
            db_session,
            now + timedelta(minutes=index),
            "SSH_ATTACK_CHAIN",
            "10.0.0.50",
            "server01",
            [alert_id],
        )

        correlation_ids.append(correlation.id)

    correlations, total = repository.get_recent(
        limit=1,
        offset=1,
    )

    assert total == 3
    assert len(correlations) == 1

    # Newest is index 2, offset 1 therefore returns index 1.
    assert correlations[0].id == correlation_ids[1]


def test_get_count(db_session):
    repository = CorrelationRepository(db_session)

    now = datetime.now()

    alert1 = create_alert(
        db_session,
        now,
        "10.0.0.50",
        "server01",
    )

    alert2 = create_alert(
        db_session,
        now,
        "10.0.0.51",
        "server02",
    )

    assert repository.get_count() == 0

    create_correlation(
        db_session,
        now,
        "SSH_ATTACK_CHAIN",
        "10.0.0.50",
        "server01",
        [alert1.id],
    )

    assert repository.get_count() == 1

    create_correlation(
        db_session,
        now + timedelta(seconds=1),
        "SSH_ATTACK_CHAIN",
        "10.0.0.51",
        "server02",
        [alert2.id],
    )

    assert repository.get_count() == 2


def test_save_correlation_with_multiple_alerts(db_session):
    repository = CorrelationRepository(db_session)

    now = datetime.now()

    alerts = [
        create_alert(
            db_session,
            now + timedelta(seconds=index),
            "10.0.0.50",
            "server01",
        )
        for index in range(3)
    ]

    correlation = repository.save(
        Correlation(
            timestamp=now + timedelta(seconds=3),
            correlation_rule_id="SSH_ATTACK_CHAIN",
            source_ip="10.0.0.50",
            affected_host="server01",
            alerts=[
                alert.id
                for alert in alerts
            ],
        )
    )

    assert len(correlation.alerts) == 3
    assert set(correlation.alerts) == {
        alerts[0].id,
        alerts[1].id,
        alerts[2].id,
    }

