from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database.models import CorrelationAlertDB, CorrelationDB
from backend.models.siem_models import Correlation


class CorrelationRepository:

    def __init__(self, session: Session):
        self.session = session

    def save(self, correlation: Correlation) -> Correlation:
        """Saves the correlation on the postgresql database inside the docker container
    
        Args:
            correlation (Correlation): the correlation that needs to be saved

        Returns:
            Correlation:
        """
        correlation_db = CorrelationDB(
            timestamp = correlation.timestamp,
            correlation_rule_id = correlation.correlation_rule_id,
            source_ip = correlation.source_ip,
            affected_host = correlation.affected_host,
        )

        self.session.add(correlation_db)
        self.session.flush()

        for alert_id in correlation.alerts:
            correlation_alert = CorrelationAlertDB(
                correlation_id=correlation_db.id,
                alert_id=alert_id,
            )

            self.session.add(correlation_alert)

        self.session.commit()
        self.session.refresh(correlation_db)

        return self._to_correlation(correlation_db)
        
    def get_recent(self, limit: int = 100, offset: int = 0, source_ip: str | None = None, affected_host: str | None = None) -> tuple[list[Correlation], int]:
        statement = select(CorrelationDB)

        if source_ip is not None:
            statement = statement.where(CorrelationDB.source_ip == source_ip)

        if affected_host is not None:
            statement = statement.where(CorrelationDB.affected_host == affected_host)

        count_statement = select(func.count()).select_from(statement.subquery())
        total = self.session.scalar(count_statement) or 0

        statement = statement.order_by(CorrelationDB.timestamp.desc()).offset(offset).limit(limit)
        correlations_db = self.session.scalars(statement).all()

        correlations = [
            self._to_correlation(correlation_db)
            for correlation_db in correlations_db
        ]

        return correlations, total

    def get_by_id(self, correlation_id: int) -> Correlation | None:
        """Generic get correlation by id

        Args:
            correlation_id (int): id of the wanted correlation

        Returns:
            Correlation:
        """
        statement = select(CorrelationDB).where(CorrelationDB.id == correlation_id)
        correlation_db = self.session.scalar(statement) 

        if correlation_db is None: 
            return None 

        return self._to_correlation(correlation_db)

    def get_count(self) -> int:
        statement = select(func.count(CorrelationDB.id))

        return self.session.scalar(statement) or 0


    def _to_correlation(self, correlation_db: CorrelationDB) -> Correlation: 
        statement = (
            select(CorrelationAlertDB.alert_id)
            .where(CorrelationAlertDB.correlation_id == correlation_db.id)
        )

        alert_ids = self.session.scalars(statement).all()

        return Correlation(
            id=correlation_db.id,
            timestamp = correlation_db.timestamp,
            correlation_rule_id = correlation_db.correlation_rule_id,
            source_ip = correlation_db.source_ip,
            affected_host = correlation_db.affected_host,
            alerts=list(alert_ids),
        )