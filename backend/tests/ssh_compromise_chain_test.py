from datetime import datetime, timedelta

from backend.correlation_engine.correlation_rules.ssh_compromise_chain import SSHCompromiseChain

from backend.models.siem_models import Alert, AlertStatus, Event, EventType, Severity


def create_alert(alert_id: int, timestamp: datetime, source_ip: str = "10.0.0.50", affected_host: str = "server01", rule_id: str = "SSH_BRUTE_FORCE") -> Alert:
    return Alert(
        id=alert_id,
        timestamp=timestamp,
        rule_id=rule_id,
        title="SSH brute force detected",
        description="Multiple failed SSH login attempts detected.",
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        source_ip=source_ip,
        affected_host=affected_host,
    )

def create_event(event_id: int, timestamp: datetime, source_ip: str = "10.0.0.50", source: str = "server01", event_type: EventType = EventType.AUTHENTICATION_SUCCESS) -> Event:
    return Event(
        id=event_id,
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        severity=Severity.INFO,
        source_ip=source_ip,
        destination_ip="192.168.1.10",
        destination_port=22,
        username="admin",
    )

def test_brute_force_followed_by_successful_login_creates_correlation():
    rule = SSHCompromiseChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(alert_id=1, timestamp=base_time)
    event = create_event(event_id=1, timestamp=base_time + timedelta(seconds=30))

    correlation = rule.correlate(event, alert)

    assert correlation is not None
    assert correlation.correlation_rule_id == "SSH_COMPROMISE_CHAIN"
    assert correlation.alerts == [1]
    assert correlation.source_ip == "10.0.0.50"
    assert correlation.affected_host == "server01"

def test_non_authentication_success_event_does_not_create_correlation():
    rule = SSHCompromiseChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(alert_id=1, timestamp=base_time)
    event = create_event(event_id=1, timestamp=base_time + timedelta(seconds=30), event_type=EventType.AUTHENTICATION_FAILURE)

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_different_source_ip_does_not_create_correlation():
    rule = SSHCompromiseChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(alert_id=1, timestamp=base_time, source_ip="10.0.0.50")
    event = create_event(event_id=1, timestamp=base_time + timedelta(seconds=30), source_ip="10.0.0.51")

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_different_host_does_not_create_correlation():
    rule = SSHCompromiseChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(alert_id=1, timestamp=base_time, affected_host="server01")
    event = create_event(event_id=1, timestamp=base_time + timedelta(seconds=30), source="server02")

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_alert_rule_must_be_brute_force():
    rule = SSHCompromiseChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(alert_id=1, timestamp=base_time, rule_id="SSH_ROOT_LOGIN")
    event = create_event(event_id=1, timestamp=base_time + timedelta(seconds=30))

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_event_outside_time_window_does_not_create_correlation():
    rule = SSHCompromiseChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(alert_id=1, timestamp=base_time)
    event = create_event(event_id=1, timestamp=base_time + timedelta(minutes=3))

    correlation = rule.correlate(event, alert)

    assert correlation is None

def test_event_at_end_of_time_window_creates_correlation():
    rule = SSHCompromiseChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(alert_id=1, timestamp=base_time)
    event = create_event(event_id=1, timestamp=base_time + timedelta(minutes=2))

    correlation = rule.correlate(event, alert)

    assert correlation is not None

def test_same_alert_and_event_are_not_correlated_twice():
    rule = SSHCompromiseChain()

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert = create_alert(alert_id=1, timestamp=base_time)
    event = create_event(event_id=1, timestamp=base_time + timedelta(seconds=30))

    first = rule.correlate(event, alert)
    second = rule.correlate(event, alert)

    assert first is not None
    assert second is None

def test_new_event_can_create_new_correlation():
    rule = SSHCompromiseChain()
    base_time = datetime(2026, 1, 1, 12, 0, 0)

    alert1 = create_alert(alert_id=1, timestamp=base_time)
    event1 = create_event(event_id=1, timestamp=base_time + timedelta(seconds=30))

    first = rule.correlate(event1, alert1)

    assert first is not None

    alert2 = create_alert(alert_id=2, timestamp=base_time + timedelta(minutes=3))
    event2 = create_event(event_id=2, timestamp=base_time + timedelta(minutes=3, seconds=30))

    second = rule.correlate(event2, alert2)

    assert second is not None
    assert second.alerts == [2]
