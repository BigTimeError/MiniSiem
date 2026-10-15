from datetime import datetime, timedelta

from backend.correlation_engine.correlation_rules.ssh_privilege_escalation_chain import SSHPrivilegeEscalationChain
from backend.models.siem_models import Alert, AlertStatus, Event, EventType, Severity

def create_alert(alert_id: int | None, timestamp: datetime, source_ip: str = "10.0.0.50", affected_host: str = "server01", rule_id: str = "SSH_ROOT_LOGIN") -> Alert:
    return Alert(
        id=alert_id,
        timestamp=timestamp,
        rule_id=rule_id,
        title="SSH root login detected",
        description="A root login was detected.",
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        source_ip=source_ip,
        affected_host=affected_host,
    )

def create_event(event_id: int | None, timestamp: datetime, source_ip: str = "10.0.0.50", source: str = "server01", event_type: EventType = EventType.AUTHENTICATION_SUCCESS) -> Event:
    return Event(
        id=event_id,
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        severity=Severity.INFO,
        source_ip=source_ip,
        destination_ip="192.168.1.10",
        destination_port=22,
        username="root",
    )

def test_authentication_success_followed_by_root_login_creates_correlation():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event = create_event(event_id=1, timestamp=base_time)
    alert = create_alert(alert_id=1, timestamp=base_time + timedelta(seconds=30))

    first = rule.correlate(alert, event)

    assert first is not None
    assert first.correlation_rule_id == "SSH_PRIVILEGE_ESCALATION_CHAIN"
    assert first.alerts == [1]
    assert first.source_ip == "10.0.0.50"
    assert first.affected_host == "server01"

def test_event_after_alert_does_not_create_correlation():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event = create_event(event_id=1, timestamp=base_time + timedelta(seconds=30))
    alert = create_alert(alert_id=1, timestamp=base_time)

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_non_authentication_success_event_does_not_create_correlation():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event = create_event(event_id=1, timestamp=base_time, event_type=EventType.AUTHENTICATION_FAILURE)
    alert = create_alert(alert_id=1, timestamp=base_time + timedelta(seconds=30))

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_different_source_ip_does_not_create_correlation():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event = create_event(event_id=1, timestamp=base_time, source_ip="10.0.0.51")
    alert = create_alert(alert_id=1, timestamp=base_time + timedelta(seconds=30), source_ip="10.0.0.50")

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_different_host_does_not_create_correlation():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event = create_event(event_id=1, timestamp=base_time, source="server01")
    alert = create_alert(alert_id=1, timestamp=base_time + timedelta(seconds=30), affected_host="server02")

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_wrong_alert_rule_does_not_create_correlation():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event = create_event(event_id=1, timestamp=base_time)
    alert = create_alert(alert_id=1, timestamp=base_time + timedelta(seconds=30), rule_id="SSH_BRUTE_FORCE")

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_event_outside_time_window_does_not_create_correlation():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event = create_event(event_id=1, timestamp=base_time)
    alert = create_alert(alert_id=1, timestamp=base_time + timedelta(minutes=3))

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_event_at_start_of_time_window_creates_correlation():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event = create_event(event_id=1, timestamp=base_time)
    alert = create_alert(alert_id=1, timestamp=base_time + timedelta(minutes=2))

    correlation = rule.correlate(event, alert)

    assert correlation is not None

def test_same_event_and_alert_are_not_correlated_twice():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event = create_event(event_id=1, timestamp=base_time)
    alert = create_alert(alert_id=1, timestamp=base_time + timedelta(seconds=30))

    first = rule.correlate(event, alert)
    second = rule.correlate(event, alert)

    assert first is not None
    assert second is None

def test_new_event_and_alert_create_new_correlation():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event1 = create_event(event_id=1, timestamp=base_time)
    alert1 = create_alert(alert_id=1, timestamp=base_time + timedelta(seconds=30))

    first = rule.correlate(event1, alert1)

    assert first is not None

    event2 = create_event(event_id=2, timestamp=base_time + timedelta(minutes=3))
    alert2 = create_alert(alert_id=2, timestamp=base_time + timedelta(minutes=3, seconds=30))

    second = rule.correlate(event2, alert2)

    assert second is not None
    assert second.alerts == [2]

def test_missing_event_id_does_not_create_correlation():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event = create_event(event_id=None, timestamp=base_time)
    alert = create_alert(alert_id=1, timestamp=base_time + timedelta(seconds=30))

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_missing_alert_id_does_not_create_correlation():
    rule = SSHPrivilegeEscalationChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    event = create_event(event_id=1, timestamp=base_time)
    alert = create_alert(alert_id=None, timestamp=base_time + timedelta(seconds=30))

    correlation = rule.correlate(event, alert)

    assert correlation is None
