from datetime import datetime, timedelta

from backend.models.siem_models import Alert, AlertStatus, Severity
from backend.correlation_engine.correlation_rules.ssh_attack_chain_correlation import (
    SSHAttackChainCorrelation,
)


def create_alert(
    alert_id: int,
    rule_id: str,
    timestamp: datetime,
    source_ip: str = "192.168.1.100",
    affected_host: str = "server01",
) -> Alert:
    return Alert(
        id=alert_id,
        timestamp=timestamp,
        rule_id=rule_id,
        title="Test Alert",
        description="Test alert",
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        source_ip=source_ip,
        affected_host=affected_host,
    )


def test_no_correlation_for_first_alert():
    rule = SSHAttackChainCorrelation()

    alert = create_alert(
        alert_id=1,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
    )

    correlation = rule.correlate(None, alert)

    assert correlation is None


def test_correlation_when_required_alerts_are_present():
    rule = SSHAttackChainCorrelation()

    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    brute_force = create_alert(
        alert_id=1,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp,
    )

    user_enumeration = create_alert(
        alert_id=2,
        rule_id="SSH_USER_ENUMERATION",
        timestamp=timestamp + timedelta(seconds=30),
    )

    assert rule.correlate(None, brute_force) is None

    correlation = rule.correlate(None, user_enumeration)

    assert correlation is not None
    assert correlation.correlation_rule_id == "SSH_ATTACK_CHAIN"
    assert set(correlation.alerts) == {1, 2}
    assert correlation.source_ip == "192.168.1.100"
    assert correlation.affected_host == "server01"


def test_no_duplicate_correlation_for_same_alert_combination():
    rule = SSHAttackChainCorrelation()

    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    brute_force = create_alert(
        alert_id=1,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp,
    )

    user_enumeration = create_alert(
        alert_id=2,
        rule_id="SSH_USER_ENUMERATION",
        timestamp=timestamp + timedelta(seconds=30),
    )

    irrelevant_alert = create_alert(
        alert_id=3,
        rule_id="SSH_INVALID_USER",
        timestamp=timestamp + timedelta(seconds=45),
    )

    assert rule.correlate(None, brute_force) is None

    first_correlation = rule.correlate(None, user_enumeration)

    assert first_correlation is not None

    second_correlation = rule.correlate(None, irrelevant_alert)

    assert second_correlation is None


def test_new_alert_combination_creates_new_correlation():
    rule = SSHAttackChainCorrelation()

    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    brute_force_1 = create_alert(
        alert_id=1,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp,
    )

    user_enumeration_1 = create_alert(
        alert_id=2,
        rule_id="SSH_USER_ENUMERATION",
        timestamp=timestamp + timedelta(seconds=30),
    )

    brute_force_2 = create_alert(
        alert_id=3,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp + timedelta(seconds=60),
    )

    user_enumeration_2 = create_alert(
        alert_id=4,
        rule_id="SSH_USER_ENUMERATION",
        timestamp=timestamp + timedelta(seconds=90),
    )

    assert rule.correlate(None, brute_force_1) is None

    first_correlation = rule.correlate(None, user_enumeration_1)

    assert first_correlation is not None
    assert set(first_correlation.alerts) == {1, 2}

    assert rule.correlate(None, brute_force_2) is None

    second_correlation = rule.correlate(None, user_enumeration_2)

    assert second_correlation is not None
    assert set(second_correlation.alerts) == {3, 4}


def test_no_correlation_for_different_source_ip():
    rule = SSHAttackChainCorrelation()

    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    brute_force = create_alert(
        alert_id=1,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp,
        source_ip="192.168.1.100",
    )

    user_enumeration = create_alert(
        alert_id=2,
        rule_id="SSH_USER_ENUMERATION",
        timestamp=timestamp + timedelta(seconds=30),
        source_ip="192.168.1.200",
    )

    assert rule.correlate(None, brute_force) is None
    assert rule.correlate(None, user_enumeration) is None


def test_no_correlation_for_different_affected_host():
    rule = SSHAttackChainCorrelation()

    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    brute_force = create_alert(
        alert_id=1,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp,
        affected_host="server01",
    )

    user_enumeration = create_alert(
        alert_id=2,
        rule_id="SSH_USER_ENUMERATION",
        timestamp=timestamp + timedelta(seconds=30),
        affected_host="server02",
    )

    assert rule.correlate(None, brute_force) is None
    assert rule.correlate(None, user_enumeration) is None


def test_no_correlation_outside_time_window():
    rule = SSHAttackChainCorrelation()

    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    brute_force = create_alert(
        alert_id=1,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp,
    )

    user_enumeration = create_alert(
        alert_id=2,
        rule_id="SSH_USER_ENUMERATION",
        timestamp=timestamp + timedelta(minutes=3),
    )

    assert rule.correlate(None, brute_force) is None
    assert rule.correlate(None, user_enumeration) is None


def test_no_correlation_without_source_ip():
    rule = SSHAttackChainCorrelation()

    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    brute_force = create_alert(
        alert_id=1,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp,
        source_ip=None,
    )

    user_enumeration = create_alert(
        alert_id=2,
        rule_id="SSH_USER_ENUMERATION",
        timestamp=timestamp + timedelta(seconds=30),
    )

    assert rule.correlate(None, brute_force) is None
    assert rule.correlate(None, user_enumeration) is None


def test_no_correlation_without_affected_host():
    rule = SSHAttackChainCorrelation()

    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    brute_force = create_alert(
        alert_id=1,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp,
        affected_host=None,
    )

    user_enumeration = create_alert(
        alert_id=2,
        rule_id="SSH_USER_ENUMERATION",
        timestamp=timestamp + timedelta(seconds=30),
    )

    assert rule.correlate(None, brute_force) is None
    assert rule.correlate(None, user_enumeration) is None


def test_no_correlation_without_alert_id():
    rule = SSHAttackChainCorrelation()

    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    brute_force = create_alert(
        alert_id=None,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp,
    )

    user_enumeration = create_alert(
        alert_id=2,
        rule_id="SSH_USER_ENUMERATION",
        timestamp=timestamp + timedelta(seconds=30),
    )

    assert rule.correlate(None, brute_force) is None
    assert rule.correlate(None, user_enumeration) is None


def test_same_rule_does_not_create_correlation():
    rule = SSHAttackChainCorrelation()

    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    brute_force_1 = create_alert(
        alert_id=1,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp,
    )

    brute_force_2 = create_alert(
        alert_id=2,
        rule_id="SSH_BRUTE_FORCE",
        timestamp=timestamp + timedelta(seconds=30),
    )

    assert rule.correlate(None, brute_force_1) is None
    assert rule.correlate(None, brute_force_2) is None
