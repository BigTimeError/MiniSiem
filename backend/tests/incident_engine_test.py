from datetime import datetime
from unittest.mock import Mock

import pytest

from backend.incident_engine.incident_engine import IncidentEngine
from backend.models.siem_models import (
    Alert,
    AlertStatus,
    Correlation,
    Incident,
    IncidentStatus,
    Severity,
)


def create_alert(
    id=1,
    rule_id="SSH_BRUTE_FORCE",
    severity=Severity.HIGH,
    source_ip="192.168.1.100",
    affected_host="server01",
):
    return Alert(
        id=id,
        timestamp=datetime.now(),
        rule_id=rule_id,
        title="Test Alert",
        description="Test alert description",
        severity=severity,
        status=AlertStatus.OPEN,
        source_ip=source_ip,
        affected_host=affected_host,
    )


def create_correlation(
    id=1,
    correlation_rule_id="SSH_COMPROMISE_CHAIN",
    source_ip="192.168.1.100",
    affected_host="server01",
    alerts=None,
):
    return Correlation(
        id=id,
        timestamp=datetime.now(),
        correlation_rule_id=correlation_rule_id,
        source_ip=source_ip,
        affected_host=affected_host,
        alerts=alerts if alerts is not None else [1],
    )


def create_incident(
    id=1,
    title="Possible SSH Server Compromise",
    severity=Severity.HIGH,
    status=IncidentStatus.OPEN,
    source_ip="192.168.1.100",
    affected_host="server01",
    related_alerts=None,
    related_correlations=None,
):
    return Incident(
        id=id,
        timestamp=datetime.now(),
        title=title,
        description="Test incident description",
        severity=severity,
        status=status,
        source_ip=source_ip,
        affected_host=affected_host,
        related_alerts=(
            related_alerts
            if related_alerts is not None
            else [1]
        ),
        related_correlations=(
            related_correlations
            if related_correlations is not None
            else [1]
        ),
    )


@pytest.fixture
def incident_repository():
    return Mock()


@pytest.fixture
def alert_repository():
    return Mock()


@pytest.fixture
def engine(incident_repository, alert_repository):
    return IncidentEngine(
        incident_repository,
        alert_repository,
    )


def test_process_creates_new_incident(
    engine,
    incident_repository,
    alert_repository,
):
    alert = create_alert(id=1)
    correlation = create_correlation(
        id=1,
        alerts=[1],
    )

    expected_incident = create_incident(
        id=1,
        related_alerts=[1],
        related_correlations=[1],
    )

    incident_repository.find_open_incident.return_value = None
    incident_repository.save.return_value = expected_incident

    result = engine.process(
        correlation,
        [alert],
    )

    assert result == expected_incident

    saved_incident = incident_repository.save.call_args.args[0]

    assert saved_incident.title == "Possible SSH Server Compromise"
    assert saved_incident.severity == Severity.HIGH
    assert saved_incident.status == IncidentStatus.OPEN
    assert saved_incident.source_ip == correlation.source_ip
    assert saved_incident.affected_host == correlation.affected_host
    assert saved_incident.related_alerts == [1]
    assert saved_incident.related_correlations == [1]

    incident_repository.save.assert_called_once()


def test_process_reuses_existing_incident(
    engine,
    incident_repository,
    alert_repository,
):
    alert = create_alert(id=1)
    correlation = create_correlation(
        id=2,
        alerts=[1],
    )

    existing_incident = create_incident(
        id=10,
        related_alerts=[],
        related_correlations=[],
    )

    updated_incident = create_incident(
        id=10,
        related_alerts=[1],
        related_correlations=[2],
    )

    incident_repository.find_open_incident.return_value = existing_incident
    incident_repository.add_alert.return_value = existing_incident
    incident_repository.add_correlation.return_value = updated_incident

    result = engine.process(
        correlation,
        [alert],
    )

    assert result == updated_incident

    incident_repository.save.assert_not_called()

    incident_repository.add_alert.assert_called_once_with(
        10,
        1,
    )

    incident_repository.add_correlation.assert_called_once_with(
        10,
        2,
    )


def test_process_adds_multiple_alerts_to_existing_incident(
    engine,
    incident_repository,
    alert_repository,
):
    alert1 = create_alert(id=1)
    alert2 = create_alert(id=2)

    correlation = create_correlation(
        id=3,
        alerts=[1, 2],
    )

    existing_incident = create_incident(
        id=10,
        related_alerts=[],
        related_correlations=[],
    )

    updated_incident = create_incident(
        id=10,
        related_alerts=[1, 2],
        related_correlations=[3],
    )

    incident_repository.find_open_incident.return_value = existing_incident

    def add_alert(incident_id, alert_id):
        return existing_incident

    incident_repository.add_alert.side_effect = add_alert
    incident_repository.add_correlation.return_value = updated_incident

    result = engine.process(
        correlation,
        [alert1, alert2],
    )

    assert result == updated_incident

    assert incident_repository.add_alert.call_count == 2

    incident_repository.add_alert.assert_any_call(
        10,
        1,
    )

    incident_repository.add_alert.assert_any_call(
        10,
        2,
    )

    incident_repository.add_correlation.assert_called_once_with(
        10,
        3,
    )


def test_process_uses_critical_severity(
    engine,
    incident_repository,
    alert_repository,
):
    alert = create_alert(
        id=1,
        severity=Severity.CRITICAL,
    )

    correlation = create_correlation(
        alerts=[1],
    )

    expected_incident = create_incident(
        severity=Severity.CRITICAL,
    )

    incident_repository.find_open_incident.return_value = None
    incident_repository.save.return_value = expected_incident

    result = engine.process(
        correlation,
        [alert],
    )

    saved_incident = incident_repository.save.call_args.args[0]

    assert saved_incident.severity == Severity.CRITICAL
    assert result.severity == Severity.CRITICAL


def test_process_uses_highest_severity(
    engine,
    incident_repository,
    alert_repository,
):
    medium_alert = create_alert(
        id=1,
        severity=Severity.MEDIUM,
    )

    high_alert = create_alert(
        id=2,
        severity=Severity.HIGH,
    )

    correlation = create_correlation(
        alerts=[1, 2],
    )

    expected_incident = create_incident(
        severity=Severity.HIGH,
        related_alerts=[1, 2],
    )

    incident_repository.find_open_incident.return_value = None
    incident_repository.save.return_value = expected_incident

    result = engine.process(
        correlation,
        [medium_alert, high_alert],
    )

    saved_incident = incident_repository.save.call_args.args[0]

    assert saved_incident.severity == Severity.HIGH
    assert result.severity == Severity.HIGH


def test_process_without_alerts_uses_low_severity(
    engine,
    incident_repository,
    alert_repository,
):
    correlation = create_correlation(
        alerts=[],
    )

    expected_incident = create_incident(
        severity=Severity.LOW,
        related_alerts=[],
    )

    incident_repository.find_open_incident.return_value = None
    incident_repository.save.return_value = expected_incident

    result = engine.process(
        correlation,
        [],
    )

    saved_incident = incident_repository.save.call_args.args[0]

    assert saved_incident.severity == Severity.LOW
    assert saved_incident.related_alerts == []
    assert result.severity == Severity.LOW


def test_process_uses_attack_chain_title(
    engine,
    incident_repository,
    alert_repository,
):
    alert = create_alert(id=1)

    correlation = create_correlation(
        correlation_rule_id="SSH_ATTACK_CHAIN",
        alerts=[1],
    )

    expected_incident = create_incident(
        title="SSH Attack Chain Detected",
    )

    incident_repository.find_open_incident.return_value = None
    incident_repository.save.return_value = expected_incident

    result = engine.process(
        correlation,
        [alert],
    )

    saved_incident = incident_repository.save.call_args.args[0]

    assert saved_incident.title == "SSH Attack Chain Detected"
    assert result.title == "SSH Attack Chain Detected"


def test_process_uses_multi_host_attack_title(
    engine,
    incident_repository,
    alert_repository,
):
    alert = create_alert(id=1)

    correlation = create_correlation(
        correlation_rule_id="SSH_MULTI_HOST_ATTACK",
        alerts=[1],
    )

    expected_incident = create_incident(
        title="SSH Multi-Host Attack Detected",
    )

    incident_repository.find_open_incident.return_value = None
    incident_repository.save.return_value = expected_incident

    result = engine.process(
        correlation,
        [alert],
    )

    saved_incident = incident_repository.save.call_args.args[0]

    assert saved_incident.title == "SSH Multi-Host Attack Detected"
    assert result.title == "SSH Multi-Host Attack Detected"


def test_process_does_not_save_new_incident_when_existing_incident_exists(
    engine,
    incident_repository,
    alert_repository,
):
    alert = create_alert(id=1)

    correlation = create_correlation(
        id=2,
        alerts=[1],
    )

    existing_incident = create_incident(
        id=10,
        related_alerts=[],
        related_correlations=[],
    )

    updated_incident = create_incident(
        id=10,
        related_alerts=[1],
        related_correlations=[2],
    )

    incident_repository.find_open_incident.return_value = existing_incident
    incident_repository.add_alert.return_value = existing_incident
    incident_repository.add_correlation.return_value = updated_incident

    result = engine.process(
        correlation,
        [alert],
    )

    assert result == updated_incident
    incident_repository.save.assert_not_called()


def test_process_loads_alerts_from_correlation(
    engine,
    incident_repository,
    alert_repository,
):
    current_alert = create_alert(
        id=44,
        rule_id="SSH_ROOT_LOGIN",
        severity=Severity.HIGH,
    )

    previous_alert = create_alert(
        id=41,
        rule_id="SSH_BRUTE_FORCE",
        severity=Severity.HIGH,
    )

    correlation = create_correlation(
        id=8,
        correlation_rule_id="SSH_COMPROMISE_CHAIN",
        alerts=[41],
    )

    expected_incident = create_incident(
        id=17,
        title="Possible SSH Server Compromise",
        severity=Severity.HIGH,
        related_alerts=[41],
        related_correlations=[8],
    )

    incident_repository.find_open_incident.return_value = None
    incident_repository.save.return_value = expected_incident

    alert_repository.get_by_id.return_value = previous_alert

    result = engine.process(
        correlation,
        [current_alert],
    )

    saved_incident = incident_repository.save.call_args.args[0]

    assert saved_incident.related_alerts == [41]
    assert saved_incident.related_correlations == [8]
    assert saved_incident.severity == Severity.HIGH

    assert result == expected_incident

    alert_repository.get_by_id.assert_called_once_with(41)