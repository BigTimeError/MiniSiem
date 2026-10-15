from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database.models import AlertDB, EventDB, HostDB
from backend.models.siem_models import Host


class HostRepository:
    def __init__(self, session: Session):
        self.session = session

    def save(self, host: Host) -> Host:
        host_db = HostDB(
            id=host.id,
            hostname=host.hostname,
            ip_address=host.ip_address,
            status=host.status,
            last_seen=host.last_seen,
        )

        self.session.add(host_db)
        self.session.commit()
        self.session.refresh(host_db)

        return self._to_host(host_db)

    def get_by_id(self, host_id: str) -> Host | None:
        statement = select(HostDB).where(HostDB.id == host_id)

        host_db = self.session.scalar(statement)

        if host_db is None:
            return None

        return self._to_host(host_db)

    def get_by_hostname(self, hostname: str) -> Host | None:
        statement = select(HostDB).where(HostDB.hostname == hostname)

        host_db = self.session.scalar(statement)

        if host_db is None:
            return None

        return self._to_host(host_db)

    def get_by_ip(self, ip_address: str) -> Host | None:
        statement = select(HostDB).where(HostDB.ip_address == ip_address)

        host_db = self.session.scalar(statement)

        if host_db is None:
            return None

        return self._to_host(host_db)

    def get_all(self) -> list[Host]:
        statement = select(HostDB).order_by(HostDB.hostname)

        hosts_db = self.session.scalars(statement).all()

        return [
            self._to_host(host_db)
            for host_db in hosts_db
        ]

    def update_last_seen(self, host_id: str, timestamp: datetime) -> Host | None:
        host_db = self.session.get(HostDB, host_id)

        if host_db is None:
            return None

        host_db.last_seen = timestamp

        self.session.commit()
        self.session.refresh(host_db)

        return self._to_host(host_db)

    def _to_host(self, host_db: HostDB) -> Host:
        event_count = self.session.scalar(
            select(func.count(EventDB.id))
            .where(EventDB.source == host_db.hostname)
        )

        alert_count = self.session.scalar(
            select(func.count(AlertDB.id))
            .where(AlertDB.affected_host == host_db.hostname)
        )

        #time_since_last_seen = datetime.now() - host_db.last_seen
        #
        #if time_since_last_seen < timedelta(seconds=30):
        #    status = "online"
        #elif time_since_last_seen < timedelta(minutes=5):
        #    status = "unknown"
        #else:
        #    status = "offline"

        return Host(
            id=host_db.id,
            hostname=host_db.hostname,
            ip_address=host_db.ip_address,
            events=event_count or 0,
            alerts=alert_count or 0,
            status="online",
            last_seen=host_db.last_seen,
        )