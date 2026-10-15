from datetime import datetime, timedelta

from backend.models.siem_models import Alert, AlertStatus, Severity
from backend.correlation_engine.correlation_rules.ssh_multi_host_attack import (
    SSHMultiHostAttack,
)


def create_alert(
    alert_id: int,
    timestamp: datetime,
    source_ip: str = "192.168.1.100",
    affected_host: str = "server01",
) -> Alert:
    return Alert(
        id=alert_id,
        timestamp=timestamp,
        rule_id="SSH_BRUTE_FORCE",
        title="Test Alert",
        description="Test alert",
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        source_ip=source_ip,
        affected_host=affected_host,
    )


def test_no_correlation_for_first_host():
    rule = SSHMultiHostAttack()

    alert = create_alert(
        alert_id=1,
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
    )

    correlation = rule.correlate(None, alert)

    assert correlation is None


def test_correlation_when_same_source_ip_attacks_multiple_hosts():
    rule = SSHMultiHostAttack()
    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    server01_alert = create_alert(
        alert_id=1,
        timestamp=timestamp,
        affected_host="server01",
    )

    server02_alert = create_alert(
        alert_id=2,
        timestamp=timestamp + timedelta(seconds=30),
        affected_host="server02",
    )

    assert rule.correlate(None, server01_alert) is None

    correlation = rule.correlate(None, server02_alert)

    assert correlation is not None
    assert correlation.correlation_rule_id == "SSH_MULTI_HOST_ATTACK"
    assert set(correlation.alerts) == {1, 2}
    assert correlation.source_ip == "192.168.1.100"
    assert correlation.affected_host is None


def test_no_correlation_for_different_source_ips():
    rule = SSHMultiHostAttack()
    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    server01_alert = create_alert(
        alert_id=1,
        timestamp=timestamp,
        source_ip="192.168.1.100",
        affected_host="server01",
    )

    server02_alert = create_alert(
        alert_id=2,
        timestamp=timestamp + timedelta(seconds=30),
        source_ip="192.168.1.200",
        affected_host="server02",
    )

    assert rule.correlate(None, server01_alert) is None
    assert rule.correlate(None, server02_alert) is None


def test_no_correlation_outside_time_window():
    rule = SSHMultiHostAttack()
    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    server01_alert = create_alert(
        alert_id=1,
        timestamp=timestamp,
        affected_host="server01",
    )

    server02_alert = create_alert(
        alert_id=2,
        timestamp=timestamp + timedelta(minutes=3),
        affected_host="server02",
    )

    assert rule.correlate(None, server01_alert) is None
    assert rule.correlate(None, server02_alert) is None


def test_no_duplicate_correlation_for_same_alerts():
    rule = SSHMultiHostAttack()
    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    server01_alert = create_alert(
        alert_id=1,
        timestamp=timestamp,
        affected_host="server01",
    )

    server02_alert = create_alert(
        alert_id=2,
        timestamp=timestamp + timedelta(seconds=30),
        affected_host="server02",
    )

    assert rule.correlate(None, server01_alert) is None

    first_correlation = rule.correlate(None, server02_alert)

    assert first_correlation is not None

    second_correlation = rule.correlate(None, server02_alert)

    assert second_correlation is None


def test_no_correlation_without_source_ip():
    rule = SSHMultiHostAttack()
    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(
        alert_id=1,
        timestamp=timestamp,
        source_ip=None,
    )

    assert rule.correlate(None, alert) is None


def test_no_correlation_without_affected_host():
    rule = SSHMultiHostAttack()
    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(
        alert_id=1,
        timestamp=timestamp,
        affected_host=None,
    )

    assert rule.correlate(None, alert) is None


def test_no_correlation_without_alert_id():
    rule = SSHMultiHostAttack()
    timestamp = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(
        alert_id=None,
        timestamp=timestamp,
    )

    assert rule.correlate(None, alert) is None
