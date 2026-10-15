from datetime import datetime, timedelta

from sqlalchemy import select, func
from sqlalchemy.orm import Session 
from backend.database.models import EventDB 

from backend.models.siem_models import Event, EventTimeBucket, EventType, Host, TimeInterval


class EventRepository:

    def __init__(self, session: Session): 
        self.session = session

    def save(self, event: Event):
        """Saves the event on the postgresql database inside the docker container

        Args:
            event (Event): the event that needs to be saved

        Returns:
            Event:
        """
        event_db = EventDB(
            timestamp = event.timestamp,
            source = event.source,
            event_type = event.event_type,
            severity = event.severity,
            source_ip = event.source_ip,
            source_port = event.source_port,
            destination_ip = event.destination_ip,
            destination_port = event.destination_port,
            username = event.username,
            service = event.service,
            message = event.message,
            event_metadata = event.metadata,
        )

        self.session.add(event_db)
        self.session.commit()
        self.session.refresh(event_db)

        return self._to_event(event_db)
    
    def get_recent(self, limit: int = 100, offset: int = 0, source_ip: str | None = None, destination_ip: str | None = None, event_type: EventType | None = None) -> tuple[list[Event], int]:
        statement = select(EventDB)

        if source_ip is not None:
            statement = statement.where(EventDB.source_ip == source_ip)

        if destination_ip is not None:
            statement = statement.where(EventDB.destination_ip == destination_ip)

        if event_type is not None:
            statement = statement.where(EventDB.event_type == event_type)

        count_statement = select(func.count()).select_from(statement.subquery())
        total = self.session.scalar(count_statement) or 0

        statement = statement.order_by(EventDB.timestamp.desc()).offset(offset).limit(limit)
        events_db = self.session.scalars(statement).all()

        events = [
            self._to_event(event_db)
            for event_db in events_db
        ]

        return events, total

    def get_by_id(self, event_id: int) -> Event | None:
        """Generic get event by id

        Args:
            event_id (int): id of the wanted event

        Returns:
            Event:
        """
        statement = select(EventDB).where(EventDB.id == event_id)
        event_db = self.session.scalar(statement) 

        if event_db is None: 
            return None 

        return self._to_event(event_db)

    def get_count(self) -> int:
        statement = select(func.count(EventDB.id))

        return self.session.scalar(statement) or 0

    def get_hosts(self) -> list[str]:
        unique_hosts = []

        for host in self.session.query(EventDB.destination_ip).distinct():
           unique_hosts.append(host[0])

        return unique_hosts

    def get_host_info(self, host:str) -> Host:
        if host is None:
            return None

        statement = select(EventDB).where(EventDB.destination_ip == host).order_by(EventDB.timestamp.desc())
        events_db = self.session.scalars(statement).all()

        if not events_db:
            return None

        return Host(
            id=events_db[0].destination_ip,
            hostname=events_db[0].source,
            ip_address=events_db[0].destination_ip,
            events=len(events_db),
            alerts=0,
            status="online",
            last_seen=events_db[0].timestamp,
        )
    

    def get_over_time_stats(self, interval: TimeInterval) -> list[EventTimeBucket]:
        response: list[EventTimeBucket] = []

        if interval == TimeInterval.HOUR:
            now = datetime.now()

            base_time = now.replace(minute=0, second=0, microsecond=0)

            for _ in range(24):
                start = base_time
                end = base_time + timedelta(hours=1)

                count = select(func.count(EventDB.id)).where(EventDB.timestamp >= start, EventDB.timestamp < end)
                event_count = self.session.scalar(count) or 0

                response.append(EventTimeBucket(timestamp=start, count=event_count))

                base_time -= timedelta(hours=1)

        elif interval == TimeInterval.DAY:
            now = datetime.now()

            base_time = now.replace(hour=0, minute=0, second=0, microsecond=0)

            for _ in range(7):
                start = base_time
                end = base_time + timedelta(days=1)

                count = select(func.count(EventDB.id)).where(EventDB.timestamp >= start, EventDB.timestamp < end)
                event_count = self.session.scalar(count) or 0

                response.append(EventTimeBucket(timestamp=start, count=event_count))

                base_time -= timedelta(days=1)

        elif interval == TimeInterval.WEEK:
            now = datetime.now()

            base_time = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)

            for _ in range(4):
                start = base_time
                end = base_time + timedelta(weeks=1)

                count = select(func.count(EventDB.id)).where(EventDB.timestamp >= start, EventDB.timestamp < end)
                event_count = self.session.scalar(count) or 0

                response.append(EventTimeBucket(timestamp=start, count=event_count))

                base_time -= timedelta(weeks=1)

        response.reverse()
        return response

    def get_host_recent(self, hostname: str, limit: int = 10, offset: int = 0) -> tuple[list[Event], int]:
        statement = select(EventDB).where(EventDB.source == hostname)
        count_statement = select(func.count()).select_from(statement.subquery())

        total = self.session.scalar(count_statement)

        statement = statement.order_by(EventDB.timestamp.desc()).offset(offset).limit(limit)

        events_db = self.session.scalars(statement).all()

        events = [
            self._to_event(event_db)
            for event_db in events_db
        ]

        return events, total

    def get_unprocessed(self, limit: int = 100) -> list[Event]:
        statement = (
            select(EventDB)
            .where(EventDB.processed == False)
            .order_by(EventDB.timestamp)
            .limit(limit)
        )

        events_db = self.session.scalars(statement).all()

        return [self._to_event(event_db) for event_db in events_db]

    def mark_processed(self, event_id: int) -> None:
        event_db = self.session.get(EventDB, event_id)

        if event_db is None:
            return

        event_db.processed = True
        self.session.commit()

    def is_processed(self, event_id: int) -> bool:
        event_db = self.session.get(EventDB, event_id)

        if event_db is None:
            return False

        return event_db.processed
    
    @staticmethod 
    def _to_event(event_db: EventDB) -> Event: 
        return Event( 
            id=event_db.id,
            timestamp=event_db.timestamp,
            source=event_db.source,
            event_type=event_db.event_type,
            severity=event_db.severity,
            source_ip=event_db.source_ip,
            source_port=event_db.source_port,
            destination_ip=event_db.destination_ip,
            destination_port=event_db.destination_port,
            username=event_db.username,
            service=event_db.service,
            message=event_db.message,
            metadata=event_db.event_metadata,
        )