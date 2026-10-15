from datetime import datetime

from backend.detection_engine.alert_rules.ssh_root_login_rule import SSHRootLoginRule
from backend.detection_engine.detection_engine import DetectionEngine
from backend.models.siem_models import Event


def create_event(
    event_id: int,
    source_ip: str = "222.222.2.22",
    event_type: str = "authentication_success",
    username: str = "MrGreedy"
) -> Event:
    return Event(
        id=event_id,
        timestamp=datetime.now(),
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

root_event = create_event(1, username = "root")
random_event = create_event(1)

def test_root_login_expect_alert():
    detection_engine = DetectionEngine([
            SSHRootLoginRule()
    ])

    alerts = []

    alerts.append(detection_engine.check_for_alerts(random_event))
    alerts.append(detection_engine.check_for_alerts(root_event))

    assert alerts[0] == []
    assert len(alerts[1]) == 1

    assert alerts[1][0].rule_id == "SSH_ROOT_LOGIN"
    assert alerts[1][0].title == "Root login detected"
    assert alerts[1][0].severity == "high"
    assert alerts[1][0].status == "open"
    assert alerts[1][0].source_ip == "222.222.2.22"
    assert alerts[1][0].affected_host == "server01"
    assert alerts[1][0].mitre_technique == "T1087 - Account Discovery"
    assert alerts[1][0].related_events == [1]