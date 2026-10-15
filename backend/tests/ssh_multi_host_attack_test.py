from datetime import datetime, timedelta

from backend.correlation_engine.correlation_rules.ssh_multi_host_attack import SSHMultiHostAttack
from backend.models.siem_models import Alert, AlertStatus, Severity

def create_alert(alert_id: int, timestamp: datetime, source_ip: str = "10.0.0.50", affected_host: str = "server01", rule_id: str = "SSH_BRUTE_FORCE") -> Alert:
    return Alert(
        id=alert_id,
        timestamp=timestamp,
        rule_id=rule_id,
        title="Security alert",
        description="Security event detected.",
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        source_ip=source_ip,
        affected_host=affected_host,
    )

def test_same_source_ip_attacking_two_hosts_creates_correlation():
    rule = SSHMultiHostAttack()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert1 = create_alert(alert_id=1, timestamp=base_time, affected_host="server01")

    first = rule.correlate(None, alert1)

    assert first is None

    alert2 = create_alert(alert_id=2, timestamp=base_time + timedelta(seconds=30), affected_host="server02")

    correlation = rule.correlate(None, alert2)

    assert correlation is not None
    assert correlation.correlation_rule_id == "SSH_MULTI_HOST_ATTACK"
    assert set(correlation.alerts) == {1, 2}
    assert correlation.source_ip == "10.0.0.50"
    assert correlation.affected_host is None

def test_same_source_ip_attacking_only_one_host_does_not_create_correlation():
    rule = SSHMultiHostAttack()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert1 = create_alert(alert_id=1, timestamp=base_time, affected_host="server01")
    alert2 = create_alert(alert_id=2, timestamp=base_time + timedelta(seconds=30), affected_host="server01")

    assert rule.correlate(None, alert1) is None
    assert rule.correlate(None, alert2) is None

def test_different_source_ips_do_not_create_correlation():
    rule = SSHMultiHostAttack()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert1 = create_alert(alert_id=1, timestamp=base_time, source_ip="10.0.0.50", affected_host="server01")
    alert2 = create_alert(alert_id=2, timestamp=base_time + timedelta(seconds=30), source_ip="10.0.0.51", affected_host="server02")

    assert rule.correlate(None, alert1) is None
    assert rule.correlate(None, alert2) is None

def test_hosts_outside_time_window_do_not_create_correlation():
    rule = SSHMultiHostAttack()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert1 = create_alert(alert_id=1, timestamp=base_time, affected_host="server01")
    alert2 = create_alert(alert_id=2, timestamp=base_time + timedelta(minutes=3), affected_host="server02")

    assert rule.correlate(None, alert1) is None
    assert rule.correlate(None, alert2) is None

def test_hosts_at_end_of_time_window_create_correlation():
    rule = SSHMultiHostAttack()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert1 = create_alert(alert_id=1, timestamp=base_time, affected_host="server01")
    alert2 = create_alert(alert_id=2, timestamp=base_time + timedelta(minutes=2), affected_host="server02")

    assert rule.correlate(None, alert1) is None

    correlation = rule.correlate(None, alert2)

    assert correlation is not None
    assert set(correlation.alerts) == {1, 2}

def test_different_alert_rules_can_be_correlated():
    rule = SSHMultiHostAttack()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert1 = create_alert(alert_id=1, timestamp=base_time, affected_host="server01", rule_id="SSH_BRUTE_FORCE")
    alert2 = create_alert(alert_id=2, timestamp=base_time + timedelta(seconds=30), affected_host="server02", rule_id="SSH_ROOT_LOGIN")

    assert rule.correlate(None, alert1) is None

    correlation = rule.correlate(None, alert2)

    assert correlation is not None
    assert set(correlation.alerts) == {1, 2}

def test_new_host_doesnt_create_new_correlation():
    rule = SSHMultiHostAttack()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert1 = create_alert(alert_id=1, timestamp=base_time, affected_host="server01")
    alert2 = create_alert(alert_id=2, timestamp=base_time + timedelta(seconds=30), affected_host="server02")

    first = rule.correlate(None, alert1)
    second = rule.correlate(None, alert2)

    assert first is None
    assert second is not None

    alert3 = create_alert(alert_id=3, timestamp=base_time + timedelta(seconds=45), affected_host="server03")

    third = rule.correlate(None, alert3)

    assert third is None

def test_same_alert_combination_is_not_correlated_twice():
    rule = SSHMultiHostAttack()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert1 = create_alert(alert_id=1, timestamp=base_time, affected_host="server01")
    alert2 = create_alert(alert_id=2, timestamp=base_time + timedelta(seconds=30), affected_host="server02")

    first = rule.correlate(None, alert1)
    second = rule.correlate(None, alert2)

    assert first is None
    assert second is not None

    duplicate = rule.correlate(None, alert2)

    assert duplicate is None

def test_alert_without_source_ip_does_not_create_correlation():
    rule = SSHMultiHostAttack()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(alert_id=1, timestamp=base_time, source_ip=None, affected_host="server01")

    assert rule.correlate(None, alert) is None

def test_alert_without_affected_host_does_not_create_correlation():
    rule = SSHMultiHostAttack()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(alert_id=1, timestamp=base_time, affected_host=None)

    assert rule.correlate(None, alert) is None

def test_alert_without_id_does_not_create_correlation():
    rule = SSHMultiHostAttack()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(alert_id=None, timestamp=base_time, affected_host="server01")

    assert rule.correlate(None, alert) is None
