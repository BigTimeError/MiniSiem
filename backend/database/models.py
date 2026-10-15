from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Enum
from sqlalchemy.dialects.postgresql import JSONB
from backend.database.database import Base
from backend.models.siem_models import AlertStatus, EventType, IncidentStatus, Severity

severity_enum = Enum(
    Severity,
    name="severity",
    values_callable=lambda enum: [e.value for e in enum],
)

alert_status_enum = Enum(
    AlertStatus,
    name="alert_status",
    values_callable=lambda enum: [e.value for e in enum],
)

incident_status_enum = Enum(
    IncidentStatus,
    name="incident_status",
    values_callable=lambda enum: [e.value for e in enum],
)


class EventDB(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, )
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, )
    source: Mapped[str] = mapped_column(String(255), nullable=False, )
    event_type: Mapped[EventType] = mapped_column(Enum(EventType), nullable=False, )
    severity: Mapped[Severity] = mapped_column(severity_enum, nullable=False, )
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, )
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True, )
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, )    
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True, )
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, )
    service: Mapped[str | None] = mapped_column(String(100), nullable=True, )
    message: Mapped[str | None] = mapped_column(Text, nullable=True, )
    event_metadata: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict, )
    processed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, )

class AlertDB(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, )
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, )
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, )
    title: Mapped[str] = mapped_column(String(100), nullable=False, )
    description: Mapped[str] = mapped_column(Text, nullable=False, )
    severity: Mapped[Severity] = mapped_column(severity_enum, nullable=False, )
    status: Mapped[AlertStatus] = mapped_column(alert_status_enum, nullable=False, )
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, )
    affected_host: Mapped[str | None] = mapped_column(String(255), nullable=True, )    
    mitre_technique: Mapped[str | None] = mapped_column(String(255), nullable=True, )


class AlertEventDB(Base):
    __tablename__ = "alert_events"

    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True, )
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), primary_key=True, )

class CorrelationDB(Base):
    __tablename__ = "correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, )
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, )
    correlation_rule_id: Mapped[str] = mapped_column(String(255), nullable=False, )
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, )
    affected_host: Mapped[str | None] = mapped_column(String(255), nullable=True, )

class CorrelationAlertDB(Base):
    __tablename__ = "correlation_alerts"

    correlation_id: Mapped[int] = mapped_column(ForeignKey("correlations.id", ondelete="CASCADE"), primary_key=True, )
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True, )

class IncidentDB(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, )
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, )
    title: Mapped[str] = mapped_column(String(100), nullable=False, )
    description: Mapped[str] = mapped_column(Text, nullable=False, )
    severity: Mapped[Severity] = mapped_column(severity_enum, nullable=False, )
    status: Mapped[IncidentStatus] = mapped_column(incident_status_enum, nullable=False, )
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, )
    affected_host: Mapped[str | None] = mapped_column(String(255), nullable=True, )    

class IncidentAlertDB(Base):
    __tablename__ = "incident_alerts"

    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True, )
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True, )

class IncidentCorrelationDB(Base):
    __tablename__ = "incident_correlations"

    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True, )
    correlation_id: Mapped[int] = mapped_column(ForeignKey("correlations.id", ondelete="CASCADE"), primary_key=True, )

class HostDB(Base):
    __tablename__ = "hosts"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="online")
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )