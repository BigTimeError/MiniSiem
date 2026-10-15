from datetime import datetime
from enum import Enum
from backend.models.siem_models import Event, Alert
from pydantic import ValidationError
import pytest

test_cases_Event = [
    {
    'id': 1,
    'timestamp': datetime.now(),
    'source': "server01",
    'event_type': "authentication_failure",
    'severity': "high",
    'source_ip': "222.222.2.22",
    'source_port': 22,
    'destination_ip': "111.111.1.11",
    'username': "admin",
    'service': "ssh",
    'message': "failed to log in",
    },
    {
    'id': 1,
    'timestamp': datetime.now(),
    'source': "server01",
    'event_type': "authentication_failure",
    'severity': "high",
    },
    {
    'id': '123',
    'timestamp': datetime.now(),
    'source': 10012,
    'event_type': "authentication_success",
    },
]

test_cases_Alert = [
    {
    'id': 1,
    'timestamp': datetime.now(),
    'rule_id': "rule01",
    'title': "authentication_alert",
    'description': "describing something",
    'severity': "high",
    'status': "open",
    'source_ip': "222.222.2.22",
    'affected_host': "111.111.1.11",
    'mitre_technique': "mitre001",
    'related_events': {1, 22, 45},
    },
    {
    'id': 1,
    'timestamp': datetime.now(),
    'rule_id': "rule01",
    'title': "authentication_alert",
    'description': "describing something",
    'severity': "high",
    'status': "open",
    },
    {
    'id': 1,
    'timestamp': datetime.now(),
    'rule_id': 11,
    'title': "authentication_alert",
    'description': "describing something",
    'severity': "high",
    'status': "in progress",
    },
]

print(f"===== Testing {len(test_cases_Event)} Event-Class cases =====")
def test_regular_Event_Input_except_Success():
    event = Event(**test_cases_Event[0])

    assert event is not None
    assert event.event_type == "authentication_failure"
    assert event.severity == "high"
    assert event.source == "server01"
    assert event.source_ip == "222.222.2.22"
    assert event.source_port == 22
    assert event.username == "admin"
    assert event.service == "ssh"

def test_simple_Event_Input_except_Success():
    event = Event(**test_cases_Event[1])
    
    assert event is not None
    assert event.event_type == "authentication_failure"
    assert event.severity == "high"
    assert event.source == "server01"

def test_incorrect_Event_Input_expect_Exception():
    with pytest.raises(ValidationError):
        tmp = Event(**test_cases_Event[2])

def test_regular_Alert_Input_except_Success():
    alert = Alert(**test_cases_Alert[0])
    
    assert alert is not None
    assert alert.rule_id == "rule01"
    assert alert.title == "authentication_alert"
    assert alert.description == "describing something"
    assert alert.severity == "high"
    assert alert.status == "open"
    assert alert.source_ip == "222.222.2.22"
    assert alert.affected_host == "111.111.1.11"
    assert alert.mitre_technique == "mitre001"
    assert alert.related_events is not None

def test_simple_Alert_Input_except_Success():
    alert = Alert(**test_cases_Alert[0])
        
    assert alert is not None
    assert alert.rule_id == "rule01"
    assert alert.title == "authentication_alert"
    assert alert.description == "describing something"
    assert alert.severity == "high"
    assert alert.status == "open"

def test_incorrect_Alert_Input_expect_Exception():
    with pytest.raises(ValidationError):
            tmp = Event(**test_cases_Alert[2])

