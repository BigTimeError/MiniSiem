from datetime import datetime, timedelta

from backend.detection_engine.alert_rules.ssh_brute_force_rule import SSHBruteForceRule
from backend.detection_engine.detection_engine import DetectionEngine
from backend.models.siem_models import Event


BASE_TIME = datetime(2026, 9, 21, 12, 0, 0)


def create_event(
    event_id: int,
    timestamp: datetime,
    source_ip: str = "222.222.2.22",
    event_type: str = "authentication_failure"
) -> Event:
    return Event(
        id=event_id,
        timestamp=timestamp,
        source="server01",
        event_type=event_type,
        severity="high",
        source_ip=source_ip,
        source_port=22,
        destination_ip="111.111.1.11",
        username="admin",
        service="ssh",
        message="failed to log in",
    )

failed_event = create_event(1,BASE_TIME)
late_event = create_event(2,BASE_TIME + timedelta(seconds=65))
diff_ip_event = create_event(3,BASE_TIME + timedelta(seconds=10),source_ip="198.222.2.22")
auth_success_event = create_event(4,BASE_TIME + timedelta(seconds=10),source_ip="198.222.2.22",event_type="authentication_success")

def test_four_failed_attempts_expect_no_alert():
    detection_engine = DetectionEngine([
            SSHBruteForceRule()
    ])

    alerts = []

    alerts.append(detection_engine.check_for_alerts(failed_event))
    alerts.append(detection_engine.check_for_alerts(failed_event))
    alerts.append(detection_engine.check_for_alerts(failed_event))
    alerts.append(detection_engine.check_for_alerts(failed_event))

    assert all(alert == [] for alert in alerts)


def test_five_failed_attempts_expect_alert():
    detection_engine = DetectionEngine([
            SSHBruteForceRule()
    ])

    alerts = []
    alerts.append(detection_engine.check_for_alerts(failed_event))
    alerts.append(detection_engine.check_for_alerts(failed_event))
    alerts.append(detection_engine.check_for_alerts(failed_event))
    alerts.append(detection_engine.check_for_alerts(failed_event))
    alerts.append(detection_engine.check_for_alerts(failed_event))

    assert alerts[0] == []
    assert alerts[1] == []
    assert alerts[2] == []
    assert alerts[3] == []
    assert len(alerts[4]) == 1

    assert alerts[4][0].rule_id == "SSH_BRUTE_FORCE"
    assert alerts[4][0].title == "Possible SSH Brute Force Attack"
    assert alerts[4][0].severity == "high"
    assert alerts[4][0].status == "open"
    assert alerts[4][0].source_ip == "222.222.2.22"
    assert alerts[4][0].affected_host == "server01"
    assert alerts[4][0].mitre_technique == "T1110 - Brute Force"
    assert alerts[4][0].related_events == [1]

def test_five_events_span_over_one_minute_expect_no_alert():
    detection_engine = DetectionEngine([
                SSHBruteForceRule()
    ])

    alerts = []

    alerts.append(detection_engine.check_for_alerts(failed_event))
    alerts.append(detection_engine.check_for_alerts(failed_event))
    alerts.append(detection_engine.check_for_alerts(failed_event))
    alerts.append(detection_engine.check_for_alerts(failed_event))
    alerts.append(detection_engine.check_for_alerts(late_event))

    assert all(alert == [] for alert in alerts)

def test_failed_attempts_from_different_ips_expect_no_alert():
    detection_engine = DetectionEngine([
        SSHBruteForceRule()
    ])

    alerts = []

    alerts.append(detection_engine.check_for_alerts(create_event(1, BASE_TIME, "222.222.2.22")))
    alerts.append(detection_engine.check_for_alerts(create_event(2, BASE_TIME + timedelta(seconds=5), "222.222.2.22")))
    alerts.append(detection_engine.check_for_alerts(create_event(3, BASE_TIME + timedelta(seconds=10), "198.222.2.22")))
    alerts.append(detection_engine.check_for_alerts(create_event(4, BASE_TIME + timedelta(seconds=15), "198.222.2.22")))
    alerts.append(detection_engine.check_for_alerts(create_event(5, BASE_TIME + timedelta(seconds=20), "222.222.2.22")))

    assert all(alert == [] for alert in alerts)

def test_five_events_with_auth_success_expect_no_alert():
    detection_engine = DetectionEngine([
                    SSHBruteForceRule()
    ])

    alerts = []

    alerts.append(detection_engine.check_for_alerts(auth_success_event))
    alerts.append(detection_engine.check_for_alerts(auth_success_event))
    alerts.append(detection_engine.check_for_alerts(auth_success_event))
    alerts.append(detection_engine.check_for_alerts(auth_success_event))
    alerts.append(detection_engine.check_for_alerts(auth_success_event))

    assert all(alert == [] for alert in alerts)


def test_five_failed_attempts_within_exactly_60_seconds_expect_alert():
    detection_engine = DetectionEngine([
        SSHBruteForceRule()
    ])

    alerts = []

    alerts.append(detection_engine.check_for_alerts(create_event(1, BASE_TIME)))
    alerts.append(detection_engine.check_for_alerts(create_event(2, BASE_TIME + timedelta(seconds=15))))
    alerts.append(detection_engine.check_for_alerts(create_event(3, BASE_TIME + timedelta(seconds=30))))
    alerts.append(detection_engine.check_for_alerts(create_event(4, BASE_TIME + timedelta(seconds=45))))
    alerts.append(detection_engine.check_for_alerts(create_event(5, BASE_TIME + timedelta(seconds=60))))

    assert all(alert == [] for alert in alerts[:4])
    assert len(alerts[4]) == 1


def test_ten_failed_attempts_expect_only_one_alert():
    detection_engine = DetectionEngine([
            SSHBruteForceRule()
    ])

    alerts = []
    for i in range(10):
        event = create_event(
            event_id=i + 1,
            timestamp=BASE_TIME + timedelta(seconds=i)
        )

        alerts.append(
            detection_engine.check_for_alerts(event)
        )

    assert sum(len(alert) for alert in alerts) == 1