from sqlalchemy import select, func
from sqlalchemy.orm import Session 
from backend.database.models import IncidentAlertDB, IncidentCorrelationDB, IncidentDB 

from backend.models.siem_models import  Incident, IncidentStatus, Severity


class IncidentRepository:

    def __init__(self, session: Session): 
        self.session = session

    def save(self, incident: Incident):
        """Saves the incident on the postgresql database inside the docker container

        Args:
            incident (Incident): the incident that needs to be saved

        Returns:
            Incident:
        """
        incident_db = IncidentDB(
            timestamp = incident.timestamp,
            title = incident.title,
            description = incident.description,
            severity = incident.severity,
            status = incident.status,
            source_ip = incident.source_ip,
            affected_host = incident.affected_host,
        )

        self.session.add(incident_db)
        self.session.flush()

        for alert_id in incident.related_alerts:
            incident_alert = IncidentAlertDB(
                incident_id=incident_db.id,
                alert_id=alert_id,
            )

            self.session.add(incident_alert)

        for correlation_id in incident.related_correlations:
            incident_correlation = IncidentCorrelationDB(
                incident_id=incident_db.id,
                correlation_id=correlation_id,
            )

            self.session.add(incident_correlation)

        self.session.commit()
        self.session.refresh(incident_db)

        return self._to_incident(incident_db)
    
    def get_recent(self, limit: int = 100, offset: int = 0, severity: Severity | None = None, status: IncidentStatus | None = None, affected_host: str | None = None) -> tuple[list[Incident], int]:
        """Return the most recent incidents, default alert limit is 100 alerts

        Args:
            limit (int, optional): Amount of incidents to be returned. Defaults to 100
            offset (int, optional): the offset from the first incident in the database. Defaults to 0
            severity (Severity, optional): return only incidents of a specific severity
            status (IncidentStatus, optional): return only incidents with a specific status

        Returns:
            tuple[list[Incident], int]: returns a list of the incidents plus the total amount of incidents that match the search
        """
        statement = select(IncidentDB) 

        if severity is not None:
            statement = statement.where(IncidentDB.severity == severity)

        if status is not None:
            statement = statement.where(IncidentDB.status == status)

        if affected_host is not None:
            statement = statement.where(IncidentDB.affected_host == affected_host)

        count_statement = select(func.count()).select_from(statement.subquery())
        total = self.session.scalar(count_statement)
        
        statement = statement.order_by(IncidentDB.timestamp.desc()).offset(offset).limit(limit) 
        incidents_db = self.session.scalars(statement).all()

        incidents = [
            self._to_incident(incident_db)
            for incident_db in incidents_db
        ]

        return incidents, total

    def get_by_id(self, incident_id: int) -> Incident | None:
        """Generic get incident by id

        Args:
            incident_id (int): id of the wanted incident

        Returns:
            Incident:
        """
        statement = select(IncidentDB).where(IncidentDB.id == incident_id)
        incident_db = self.session.scalar(statement) 

        if incident_db is None: 
            return None 

        return self._to_incident(incident_db)


    def update_status(self, incident_id: int, status: IncidentStatus) -> Incident | None:
        """Update the status of an incident."""

        statement = select(IncidentDB).where(IncidentDB.id == incident_id)
        incident_db = self.session.scalar(statement)

        if incident_db is None:
            return None

        incident_db.status = status

        self.session.commit()
        self.session.refresh(incident_db)

        return self._to_incident(incident_db)


    def find_open_incident(self, source_ip: str | None, affected_host: str | None) -> Incident | None:
        """Find an existing open or investigating incident."""

        statement = (
            select(IncidentDB)
            .where(
                IncidentDB.source_ip == source_ip,
                IncidentDB.affected_host == affected_host,
                IncidentDB.status.in_(
                    [
                        IncidentStatus.OPEN,
                        IncidentStatus.INVESTIGATING,
                    ]
                ),
            )
            .order_by(IncidentDB.timestamp.desc())
        )

        incident_db = self.session.scalar(statement)

        if incident_db is None:
            return None

        return self._to_incident(incident_db)

    def add_correlation(self, incident_id: int, correlation_id: int) -> Incident | None:
        """Add a correlation to an existing incident."""

        incident = self.session.get(IncidentDB, incident_id)

        if incident is None:
            return None

        existing = self.session.scalar(
            select(IncidentCorrelationDB).where(
                IncidentCorrelationDB.incident_id == incident_id,
                IncidentCorrelationDB.correlation_id == correlation_id,
            )
        )

        if existing is None:
            self.session.add(
                IncidentCorrelationDB(
                    incident_id=incident_id,
                    correlation_id=correlation_id,
                )
            )

        self.session.commit()
        self.session.refresh(incident)

        return self._to_incident(incident)

    def add_alert(self, incident_id: int, alert_id: int) -> Incident | None:
        """Add an alert to an existing incident."""

        incident = self.session.get(IncidentDB, incident_id)

        if incident is None:
            return None

        existing = self.session.scalar(
            select(IncidentAlertDB).where(
                IncidentAlertDB.incident_id == incident_id,
                IncidentAlertDB.alert_id == alert_id,
            )
        )

        if existing is None:
            self.session.add(
                IncidentAlertDB(
                    incident_id=incident_id,
                    alert_id=alert_id,
                )
            )

        self.session.commit()
        self.session.refresh(incident)

        return self._to_incident(incident)

    def get_count(self) -> int:
        statement = select(func.count(IncidentDB.id))

        return self.session.scalar(statement) or 0

    
    def _to_incident(self, incident_db: IncidentDB) -> Incident: 
        statement = (
            select(IncidentAlertDB.alert_id)
            .where(IncidentAlertDB.incident_id == incident_db.id)
        )

        statement2 = (
            select(IncidentCorrelationDB.correlation_id)
            .where(IncidentCorrelationDB.incident_id == incident_db.id)
        )

        alert_ids = self.session.scalars(statement).all()
        correlation_ids = self.session.scalars(statement2).all()

        return Incident(
            id=incident_db.id,
            timestamp = incident_db.timestamp,
            title = incident_db.title,
            description = incident_db.description,
            severity = incident_db.severity,
            status = incident_db.status,
            source_ip = incident_db.source_ip,
            affected_host = incident_db.affected_host,
            related_alerts= list(alert_ids),
            related_correlations= list(correlation_ids),
        )