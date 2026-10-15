from datetime import datetime, timedelta

from backend.detection_engine.alert_rules.ssh_brute_force_rule import SSHBruteForceRule
from backend.detection_engine.alert_rules.ssh_invalid_user_login import SSHInvalidUserLogin, SSHInvalidUserLoginEnumerationRule
from backend.detection_engine.detection_engine import DetectionEngine
from backend.models.siem_models import Event


BASE_TIME = datetime(2026, 9, 21, 12, 0, 0)


def create_event(
    event_id: int,
    timestamp: datetime,
    source_ip: str = "222.222.2.22",
    event_type: str = "invalid_user_login",
    username: str = "littleBiggy"
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
        username=username,
        service="ssh",
        message="failed to log in",
    )

invalid_event1 = create_event(1,BASE_TIME)
invalid_event2 = create_event(2,BASE_TIME + timedelta(seconds=2), username = "coolBoy")
invalid_event3 = create_event(3,BASE_TIME + timedelta(seconds=3), username = "mrGreedy")
invalid_event4 = create_event(4,BASE_TIME + timedelta(seconds=4), username = "admin")
invalid_event5 = create_event(5,BASE_TIME + timedelta(seconds=5), username = "thisIsNotAHacker")
invalid_event6 = create_event(6,BASE_TIME + timedelta(seconds=65), username = "thisIsNotAHackerButLater")
invalid_event7 = create_event(7,BASE_TIME + timedelta(seconds=60), username = "thisIsNotAHackerButJustInTime")


def test_four_different_username_attempts_expect_no_alert():
    detection_engine = DetectionEngine([
        SSHInvalidUserLoginEnumerationRule()
    ])

    alerts = []

    alerts.append(detection_engine.check_for_alerts(invalid_event1))
    alerts.append(detection_engine.check_for_alerts(invalid_event2))
    alerts.append(detection_engine.check_for_alerts(invalid_event3))
    alerts.append(detection_engine.check_for_alerts(invalid_event4))

    assert all(alert == [] for alert in alerts)


def test_five_different_username_attempts_expect_alert():
    detection_engine = DetectionEngine([
        SSHInvalidUserLoginEnumerationRule()
    ])

    alerts = []
    alerts.append(detection_engine.check_for_alerts(invalid_event1))
    alerts.append(detection_engine.check_for_alerts(invalid_event2))
    alerts.append(detection_engine.check_for_alerts(invalid_event3))
    alerts.append(detection_engine.check_for_alerts(invalid_event4))
    alerts.append(detection_engine.check_for_alerts(invalid_event5))

    assert alerts[0] == []
    assert alerts[1] == []
    assert alerts[2] == []
    assert alerts[3] == []
    assert len(alerts[4]) == 1

    assert alerts[4][0].rule_id == "SSH_USER_ENUMERATION"
    assert alerts[4][0].title == "Possible SSH user enumeration"
    assert alerts[4][0].severity == "medium"
    assert alerts[4][0].status == "open"
    assert alerts[4][0].source_ip == "222.222.2.22"
    assert alerts[4][0].affected_host == "server01"
    assert alerts[4][0].mitre_technique == "T1087 - Account Discovery"
    assert alerts[4][0].related_events == [5]

def test_five_events_span_over_one_minute_expect_no_alert():
    detection_engine = DetectionEngine([
        SSHInvalidUserLoginEnumerationRule()
    ])

    alerts = []

    alerts.append(detection_engine.check_for_alerts(invalid_event1))
    alerts.append(detection_engine.check_for_alerts(invalid_event2))
    alerts.append(detection_engine.check_for_alerts(invalid_event3))
    alerts.append(detection_engine.check_for_alerts(invalid_event4))
    alerts.append(detection_engine.check_for_alerts(invalid_event6))

    assert all(alert == [] for alert in alerts)

def test_single_invalid_username_expect_low_severity_alert():
    detection_engine = DetectionEngine([
        SSHInvalidUserLogin()
    ])

    alerts = []

    alerts.append(detection_engine.check_for_alerts(invalid_event1))


    assert len(alerts[0]) == 1
    
    assert alerts[0][0].rule_id == "SSH_INVALID_USER_LOGIN_ATTEMPT"
    assert alerts[0][0].title == "Attempted login with invalid user"
    assert alerts[0][0].severity == "low"
    assert alerts[0][0].status == "open"
    assert alerts[0][0].source_ip == "222.222.2.22"
    assert alerts[0][0].affected_host == "server01"
    assert alerts[0][0].mitre_technique == "T1087 - Account Discovery"
    assert alerts[0][0].related_events == [1]


def test_five_failed_unique_invalid_username_attempts_within_exactly_60_seconds_expect_alert():
    detection_engine = DetectionEngine([
        SSHInvalidUserLoginEnumerationRule()
    ])

    alerts = []

    alerts.append(detection_engine.check_for_alerts(invalid_event1))
    alerts.append(detection_engine.check_for_alerts(invalid_event2))
    alerts.append(detection_engine.check_for_alerts(invalid_event3))
    alerts.append(detection_engine.check_for_alerts(invalid_event4))
    alerts.append(detection_engine.check_for_alerts(invalid_event7))

    assert all(alert == [] for alert in alerts[:4])
    assert len(alerts[4]) == 1


def test_ten_failed_unique_invalid_username_attempts_expect_only_one_alert():
    detection_engine = DetectionEngine([
        SSHInvalidUserLoginEnumerationRule()
    ])

    alerts = []
    alerts.append(detection_engine.check_for_alerts(invalid_event1))
    alerts.append(detection_engine.check_for_alerts(invalid_event2))
    alerts.append(detection_engine.check_for_alerts(invalid_event3))
    alerts.append(detection_engine.check_for_alerts(invalid_event4))
    alerts.append(detection_engine.check_for_alerts(invalid_event5))
    alerts.append(detection_engine.check_for_alerts(create_event(9, BASE_TIME + timedelta(seconds=5), username = "rootPerhaps")))
    alerts.append(detection_engine.check_for_alerts(create_event(10, BASE_TIME + timedelta(seconds=5), username = "thisIsTotallyNotSuspicious")))
    alerts.append(detection_engine.check_for_alerts(create_event(11, BASE_TIME + timedelta(seconds=5), username = "sukuna")))
    alerts.append(detection_engine.check_for_alerts(create_event(12, BASE_TIME + timedelta(seconds=5), username = "gojo")))
    alerts.append(detection_engine.check_for_alerts(create_event(13, BASE_TIME + timedelta(seconds=5), username = "yuji")))

    assert alerts[0] == []
    assert alerts[1] == []
    assert alerts[2] == []
    assert alerts[3] == []
    assert len(alerts[4]) == 1
    assert alerts[5] == []
    assert alerts[6] == []
    assert alerts[7] == []
    assert alerts[8] == []
    assert alerts[9] == []