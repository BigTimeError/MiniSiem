from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict, IPvAnyAddress

class EventType(str, Enum):
    AUTHENTICATION_FAILURE = "authentication_failure"
    INVALID_USER_LOGIN = "invalid_user_login"
    AUTHENTICATION_SUCCESS = "authentication_success"
    SESSION_TERMIATION = "session_termination"
    NETWORK_CONNECTION = "network_connection"
    PROCESS_EXECUTION = "process_execution"
    HTTP_REQUEST = "http_request"

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class TimeInterval(str, Enum):
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"

# source stands for the source of the logs
class Event(BaseModel):
    id: int | None = None
    timestamp: datetime
    source: str
    event_type: EventType
    severity: Severity
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    username: str | None = None
    service: str | None = None
    message: str | None = None
    metadata: dict = Field(default_factory=dict)

class Alert(BaseModel):
    id: int | None = None
    timestamp: datetime
    rule_id: str
    title: str
    description: str
    severity: Severity
    status: AlertStatus
    source_ip: str | None = None
    affected_host: str | None = None
    mitre_technique: str | None = None
    related_events: list[int] = Field(default_factory=list)

class AlertStatusUpdate(BaseModel):
    status: AlertStatus

class EventListResponse(BaseModel):
    items: list[Event]
    total: int
    limit: int
    offset: int

class AlertListResponse(BaseModel):
    items: list[Alert]
    total: int
    limit: int
    offset: int

class DashboardStats(BaseModel):
    total_events: int
    open_alerts: int
    critical_alerts: int

class EventTimeBucket(BaseModel):
    timestamp: datetime
    count: int

class EventIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host_id: str = Field(min_length=1, max_length=100)
    timestamp: datetime
    event_type: EventType
    severity: Severity
    source_ip: IPvAnyAddress | None = None
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_ip: IPvAnyAddress | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=255)
    service: str | None = Field(default=None, max_length=100)
    message: str | None = Field(default=None, max_length=4096)
    metadata: dict = Field(default_factory=dict)


class HostRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: IPvAnyAddress | None = None

class Host(BaseModel):
    id: str
    hostname: str
    ip_address: str
    events: int
    alerts: int
    status: str
    last_seen: datetime

class Correlation(BaseModel):
    id: int | None = None
    timestamp: datetime
    correlation_rule_id: str
    source_ip: str | None = None
    affected_host: str | None = None
    alerts: list[int]

class CorrelationListResponse(BaseModel):
    items: list[Correlation]
    total: int
    limit: int
    offset: int

class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"

class Incident(BaseModel):
    id: int | None = None
    timestamp: datetime
    title: str
    description: str
    severity: Severity
    status: IncidentStatus
    source_ip: str | None = None
    affected_host: str | None = None
    related_alerts: list[int] = Field(default_factory=list)
    related_correlations: list[int] = Field(default_factory=list)

class IncidentListResponse(BaseModel):
    items: list[Incident]
    total: int
    limit: int
    offset: int

class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus
