from datetime import datetime
import pytest 
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from backend.database.database import Base
from backend.models.siem_models import Event, EventType, Severity
from backend.storage.event_repository import EventRepository

DATABASE_URL = ( 
    "postgresql+psycopg://"
    "minisiem:minisiem_password"
    "@localhost:5432/minisiem_test"
) 

@pytest.fixture 
def repository(): 
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine) 

    with Session(engine) as session:
        yield EventRepository(session)

    Base.metadata.drop_all(engine)
    engine.dispose() 

def create_test_event( event_id: int = 1, timestamp: datetime | None = None, ) -> Event:
    return Event(
        id=event_id,
        timestamp=timestamp or datetime(2026, 9, 23, 12, 0, 0),
        source="server01",
        event_type=EventType.AUTHENTICATION_FAILURE,
        severity=Severity.HIGH,
        source_ip="192.168.1.100",
        source_port=54321,
        destination_ip="192.168.1.10",
        destination_port=22,
        username="admin",
        service="ssh",
        message="Failed password for admin",
        metadata={ "test": True, },
        ) 

def test_save_event(repository): 
    event = create_test_event()
    saved_event = repository.save(event)

    assert saved_event.id == event.id
    assert saved_event.timestamp == event.timestamp
    assert saved_event.source == event.source
    assert saved_event.event_type == event.event_type
    assert saved_event.severity == event.severity
    assert saved_event.source_ip == event.source_ip
    assert saved_event.source_port == event.source_port
    assert saved_event.destination_ip == event.destination_ip
    assert saved_event.destination_port == event.destination_port
    assert saved_event.username == event.username
    assert saved_event.service == event.service
    assert saved_event.message == event.message
    assert saved_event.metadata == event.metadata

def test_get_event_by_id(repository): 
    event = create_test_event()
    repository.save(event)
    loaded_event = repository.get_by_id(event.id)

    assert loaded_event is not None
    assert loaded_event.id == event.id
    assert loaded_event.source_ip == event.source_ip
    assert loaded_event.username == event.username

def test_get_nonexistent_event(repository): 
    event = repository.get_by_id(999)
    assert event is None 

def test_get_recent_events(repository): 
    event1 = create_test_event(
        event_id=1,
        timestamp=datetime(2026, 9, 23, 12, 0, 0),
    ) 
    event2 = create_test_event(
        event_id=2,
        timestamp=datetime(2026, 9, 23, 12, 1, 0),
    ) 
    event3 = create_test_event(
        event_id=3,
        timestamp=datetime(2026, 9, 23, 12, 2, 0),
    ) 

    repository.save(event1)
    repository.save(event2)
    repository.save(event3)
    events = repository.get_recent() 

    assert len(events[0]) == 3
    assert events[0][0].id == 3 
    assert events[0][1].id == 2
    assert events[0][2].id == 1

def test_get_recent_with_limit(repository):
    for event_id in range(1, 6): 
        event = create_test_event(
            event_id=event_id,
            timestamp=datetime( 2026, 9, 23, 12, event_id, ),
        ) 
        repository.save(event) 

    events = repository.get_recent(limit=3)

    assert len(events[0]) == 3
    assert [event.id for event in events[0]] == [5, 4, 3]