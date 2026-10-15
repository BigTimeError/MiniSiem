from datetime import datetime, timedelta

from backend.models.siem_models import Alert, AlertStatus, EventTimeBucket, Host, Severity, TimeInterval
from sqlalchemy import func, select 
from sqlalchemy.orm import Session 
from backend.database.models import AlertDB, AlertEventDB 


class AlertRepository:

    def __init__(self, session: Session):
        self.session = session

    def save(self, alert: Alert):
        """Saves the alert on the postgresql database inside the docker container

        Args:
            alert (Alert): the alert that needs to be saved

        Returns:
            Alert:
        """
        alert_db = AlertDB(
            timestamp = alert.timestamp,
            rule_id = alert.rule_id,
            title = alert.title,
            description = alert.description,
            severity = alert.severity,
            status = alert.status,
            source_ip = alert.source_ip,
            affected_host = alert.affected_host,
            mitre_technique = alert.mitre_technique,
        )

        self.session.add(alert_db)
        self.session.flush()

        for event_id in alert.related_events:
            alert_event = AlertEventDB(
                alert_id=alert_db.id,
                event_id=event_id,
            )

            self.session.add(alert_event)

        self.session.commit()
        self.session.refresh(alert_db)

        return self._to_alert(alert_db)

    def get_by_id(self, alert_id: int) -> Alert | None:
        """Generic get Alert by alert id

        Args:
            alert_id (int): wanted id

        Returns:
            Alert:
        """
        statement = (select(AlertDB).where(AlertDB.id == alert_id))
        alert_db = self.session.scalar(statement)

        if alert_db is None:
            return None

        return self._to_alert(alert_db)

    def get_open(self) -> list[Alert]:
        """Returns all alerts that have the status: OPEN

        Returns:
            list[Alert]:
        """
        statement = (select(AlertDB).where(AlertDB.status == AlertStatus.OPEN).order_by(AlertDB.timestamp.desc()))
        alerts_db = self.session.scalars(statement).all()

        if alerts_db is None:
            return None

        return [
            self._to_alert(alert_db)
            for alert_db in alerts_db
        ]

    def update_status(self, alert_id: int, new_status: AlertStatus) -> Alert | None:
        """Update the status of an alert

        Args:
            alert_id (int): the id of the alert which status needs to be changed
            new_status (AlertStatus): the new status to be applied

        Returns:
            Alert | None:
        """
        statement = (select(AlertDB).where(AlertDB.id == alert_id))
        alert_db = self.session.scalar(statement)

        if alert_db is None:
            return None

        alert_db.status = new_status

        self.session.commit()
        self.session.refresh(alert_db)

        return self._to_alert(alert_db)

    
    def get_recent(self, limit: int = 100, offset: int = 0, severity: Severity | None = None, status: AlertStatus | None = None, affected_host: str | None = None) -> tuple[list[Alert], int]:
        """Return the most recent alerts, default alert limit is 100 alerts

        Args:
            limit (int, optional): Amount of alerts to be returned. Defaults to 100
            offset (int, optional): the offset from the first alert in the database. Defaults to 0
            severity (Severity, optional): return only alerts of a specific severity
            status (AlertStatus, optional): return only alerts with a specific status

        Returns:
            tuple[list[Alert], int]: returns a list of the alerts plus the total amount of alerts that match the search
        """
        statement = select(AlertDB) 

        if severity is not None:
            statement = statement.where(AlertDB.severity == severity)

        if status is not None:
            statement = statement.where(AlertDB.status == status)

        if affected_host is not None:
            statement = statement.where(AlertDB.affected_host == affected_host)

        count_statement = select(func.count()).select_from(statement.subquery())
        total = self.session.scalar(count_statement)
        
        statement = statement.order_by(AlertDB.timestamp.desc()).offset(offset).limit(limit) 
        alerts_db = self.session.scalars(statement).all()

        alerts = [
            self._to_alert(alert_db)
            for alert_db in alerts_db
        ]

        return alerts, total


    def get_count(self, status: AlertStatus | None = None, severity: Severity | None = None,) -> int:
        statement = select(func.count(AlertDB.id))

        if status is not None:
            statement = statement.where(AlertDB.status == status)

        if severity is not None:
            statement = statement.where(AlertDB.severity == severity)

        return self.session.scalar(statement) or 0

    def get_host_info(self, host:Host) -> Host:
        statement = select(AlertDB).where(AlertDB.affected_host == host.hostname).order_by(AlertDB.timestamp.desc())
        alerts_db = self.session.scalars(statement).all()

        host.alerts = len(alerts_db)

        if alerts_db:
            timestamp = alerts_db[0].timestamp

            if timestamp > host.last_seen:
                host.last_seen = timestamp

        return host

    def get_host_recent(self, host_id:str, limit: int = 10, offset: int = 0) -> tuple[list[Alert], int]:
        statement = select(AlertDB).where(AlertDB.affected_host == host_id) 

        count_statement = select(func.count()).select_from(statement.subquery())
        total = self.session.scalar(count_statement)
        
        statement = statement.order_by(AlertDB.timestamp.desc()).offset(offset).limit(limit) 
        alerts_db = self.session.scalars(statement).all()

        alerts = [
            self._to_alert(alert_db)
            for alert_db in alerts_db
        ]

        return alerts, total

    def get_over_time_stats(self, interval: TimeInterval) -> list[EventTimeBucket]:
            response: list[EventTimeBucket] = []
    
            if interval == TimeInterval.HOUR:
                now = datetime.now()
    
                base_time = now.replace(minute=0, second=0, microsecond=0)
    
                for _ in range(24):
                    start = base_time
                    end = base_time + timedelta(hours=1)
    
                    count = select(func.count(AlertDB.id)).where(AlertDB.timestamp >= start, AlertDB.timestamp < end)
                    event_count = self.session.scalar(count) or 0
    
                    response.append(EventTimeBucket(timestamp=start, count=event_count))
    
                    base_time -= timedelta(hours=1)

            elif interval == TimeInterval.DAY:
                now = datetime.now()
    
                base_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
                for _ in range(7):
                    start = base_time
                    end = base_time + timedelta(days=1)
    
                    count = select(func.count(AlertDB.id)).where(AlertDB.timestamp >= start, AlertDB.timestamp < end)
                    event_count = self.session.scalar(count) or 0
    
                    response.append(EventTimeBucket(timestamp=start, count=event_count))
    
                    base_time -= timedelta(days=1)
            
            elif interval == TimeInterval.WEEK:
                now = datetime.now()

                base_time = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)

                for _ in range(4):
                    start = base_time
                    end = base_time + timedelta(weeks=1)

                    count = select(func.count(AlertDB.id)).where(AlertDB.timestamp >= start, AlertDB.timestamp < end)
                    event_count = self.session.scalar(count) or 0

                    response.append(EventTimeBucket(timestamp=start, count=event_count))

                    base_time -= timedelta(weeks=1)

            response.reverse()
            return response

    def _to_alert(self, alert_db: AlertDB) -> Alert:
        statement = (
            select(AlertEventDB.event_id)
            .where(AlertEventDB.alert_id == alert_db.id)
        )

        event_ids = self.session.scalars(statement).all()

        return Alert(
            id=alert_db.id,
            timestamp=alert_db.timestamp,
            rule_id=alert_db.rule_id,
            title=alert_db.title,
            description=alert_db.description,
            severity=alert_db.severity,
            status=alert_db.status,
            source_ip=alert_db.source_ip,
            affected_host=alert_db.affected_host,
            mitre_technique=alert_db.mitre_technique,
            related_events=list(event_ids),
        )