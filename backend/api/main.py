from datetime import datetime
import os

from dotenv import load_dotenv

from fastapi import Depends, FastAPI, Query, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.api.dependencies import get_db
from backend.storage.alert_repository import AlertRepository
from backend.storage.correlation_repository import CorrelationRepository
from backend.storage.event_repository import EventRepository

from backend.models.siem_models import AlertListResponse, AlertStatus, AlertStatusUpdate, Correlation, CorrelationListResponse, DashboardStats, Event, Alert, EventIngestRequest, EventListResponse, EventTimeBucket, EventType, Host, HostRegisterRequest, Incident, IncidentListResponse, IncidentStatus, IncidentStatusUpdate, Severity, TimeInterval
from backend.api.event_stream import event_broker

import threading
from contextlib import asynccontextmanager

from backend.database.database import SessionLocal
from main import siem_engine

from backend.storage.host_repository import HostRepository
from backend.storage.incident_repository import IncidentRepository
import secrets


load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    def run_siem():
        print("SIEM THREAD STARTING", flush=True)

        with SessionLocal() as session:
            siem_engine(session)

    siem_thread = threading.Thread(
        target=run_siem,
        name="siem-engine",
        daemon=True,
    )

    siem_thread.start()

    print("SIEM THREAD CREATED", flush=True)

    yield


app = FastAPI(
    title="MiniSIEM API",
    description="API for the MiniSIEM security monitoring system",
    version="0.1.0",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        os.getenv("FRONTEND_ORIGIN", "http://localhost:5173"),
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_agent_token(authorization: str | None = Header(default=None)):
    expected_token = os.getenv("AGENT_API_TOKEN")

    if not expected_token:
        raise HTTPException(
            status_code=500,
            detail="Agent authentication is not configured"
        )

    scheme, _, token = (authorization or "").partition(" ")

    if (
        scheme.lower() != "bearer"
        or not secrets.compare_digest(token, expected_token)
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing agent token"
        )


@app.get("/")
def root():
    return {
        "name": "MiniSIEM",
        "status": "running",
    }


@app.get("/stream")
async def stream():
    queue = event_broker.subscribe()

    async def event_generator():
        try:
            while True:
                message = await queue.get()
                yield message
        finally:
            event_broker.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )

@app.get("/events", response_model=EventListResponse)
def get_events(limit: int = Query(default=100, ge=1, le=1000), offset: int = Query(default=0, ge=0), source_ip: str | None = None, destination_ip: str | None = None, event_type: EventType | None = None, db: Session = Depends(get_db)):
    repository = EventRepository(db)

    events, total = repository.get_recent(limit=limit, offset=offset, source_ip=source_ip, destination_ip=destination_ip, event_type=event_type)

    return EventListResponse(items=events, total=total, limit=limit, offset=offset)

@app.post("/events", response_model=Event, status_code=201)
def ingest_event(request: EventIngestRequest, db: Session = Depends(get_db), _: None = Depends(verify_agent_token)):
    host_repository = HostRepository(db)
    event_repository = EventRepository(db)

    host = host_repository.get_by_id(request.host_id)

    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")

    event = Event(
    timestamp=request.timestamp,
    source=host.hostname,
    event_type=request.event_type,
    severity=request.severity,
    source_ip=str(request.source_ip) if request.source_ip is not None else None,
    source_port=request.source_port,
    destination_ip=str(request.destination_ip) if request.destination_ip is not None else None,
    destination_port=request.destination_port,
    username=request.username,
    service=request.service,
    message=request.message,
    metadata=request.metadata,
)

    saved_event = event_repository.save(event)

    host_repository.update_last_seen(
        host.id,
        saved_event.timestamp,
    )

    return saved_event


@app.get("/events/count", response_model=int)
def get_events_count(db: Session = Depends(get_db)):
    repository = EventRepository(db)

    return repository.get_count()


@app.get("/events/{event_id}", response_model=Event)
def get_event_by_id(event_id: int, db: Session = Depends(get_db)):
    repository = EventRepository(db)
    event = repository.get_by_id(event_id)

    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")

    return event


@app.get("/alerts", response_model=AlertListResponse)
def get_alerts(limit: int = Query(default=100, ge=1, le=1000), offset: int = Query(default=0, ge=0), severity: Severity | None = None, status: AlertStatus | None = None, affected_host: str | None = None, db: Session = Depends(get_db)):
    repository = AlertRepository(db)

    alerts, total = repository.get_recent(limit=limit, offset=offset, severity=severity, status=status, affected_host=affected_host)

    return AlertListResponse(items=alerts, total=total, limit=limit, offset=offset)


@app.get("/alerts/open", response_model=list[Alert])
def get_open_alerts(db: Session = Depends(get_db)):
    repository = AlertRepository(db)
    
    return repository.get_open()


@app.get("/alerts/{alert_id}", response_model=Alert)
def get_alert_by_id(alert_id: int, db: Session = Depends(get_db)):
    repository = AlertRepository(db)
    alert = repository.get_by_id(alert_id)

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    return alert


@app.patch("/alerts/{alert_id}/status", response_model=Alert)
def patch_alert_status(alert_id: int, update: AlertStatusUpdate, db: Session = Depends(get_db)):
    repository = AlertRepository(db)
    alert = repository.update_status(alert_id, update.status)

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    return alert


@app.get("/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    alert_repository = AlertRepository(db)
    event_repository = EventRepository(db)
    
    total_events = event_repository.get_count()
    open_alerts = alert_repository.get_count(status = AlertStatus.OPEN)
    critical_alerts = alert_repository.get_count(severity = Severity.CRITICAL)

    return DashboardStats(total_events=total_events, open_alerts=open_alerts, critical_alerts=critical_alerts)

@app.get("/dashboard/events-over-time", response_model=list[EventTimeBucket])
def get_events_over_time(interval: TimeInterval = TimeInterval.HOUR, db: Session = Depends(get_db)):
    event_repository = EventRepository(db)
    
    return event_repository.get_over_time_stats(interval)

@app.get("/dashboard/alerts-over-time", response_model=list[EventTimeBucket])
def get_alerts_over_time(interval: TimeInterval = TimeInterval.HOUR, db: Session = Depends(get_db)):
    alert_repository = AlertRepository(db)
    
    return alert_repository.get_over_time_stats(interval)

@app.get("/hosts", response_model=list[Host])
def get_hosts(db: Session = Depends(get_db)):
    host_repository = HostRepository(db)

    return host_repository.get_all()

@app.post("/hosts/register", response_model=Host)
def register_host(request: HostRegisterRequest, db: Session = Depends(get_db), _: None = Depends(verify_agent_token)):
    host_repository = HostRepository(db)

    host = host_repository.get_by_id(request.id)

    if host is None:
        host = Host(
            id=request.id,
            hostname=request.hostname,
            ip_address=str(request.ip_address) if request.ip_address is not None else None,
            events=0,
            alerts=0,
            status="healthy",
            last_seen=datetime.now(),
        )

        return host_repository.save(host)

    return host_repository.update_last_seen(
        host.id,
        datetime.now(),
    )

@app.get("/hosts/{host_id}", response_model=Host)
def get_host(host_id: str, db: Session = Depends(get_db)):
    host_repository = HostRepository(db)

    host = host_repository.get_by_id(host_id)

    if host is None:
        raise HTTPException(
            status_code=404,
            detail="Host not found",
        )

    return host

@app.get("/hosts/{host_id}/events", response_model=EventListResponse)
def get_host_events(host_id: str, limit: int = Query(default=10, ge=1, le=100), offset: int = Query(default=0, ge=0), db: Session = Depends(get_db)):
    host_repository = HostRepository(db)
    event_repository = EventRepository(db)

    host = host_repository.get_by_id(host_id)

    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")

    events, total = event_repository.get_host_recent(host.hostname, limit, offset)

    return EventListResponse(
        items=events,
        total=total,
        limit=limit,
        offset=offset,
    )

@app.get("/hosts/{host_id}/alerts", response_model=AlertListResponse)
def get_host_alerts(host_id: str, limit:int = Query(default=10, ge=1, le=100), offset:int = Query(default=0, ge=0), db: Session = Depends(get_db)):
    alert_repository = AlertRepository(db)
    
    alerts, total = alert_repository.get_host_recent(host_id, limit, offset)

    return AlertListResponse(items=alerts, total=total, limit=limit, offset=offset)

@app.get("/correlations", response_model=CorrelationListResponse)
def get_correlations(limit: int = Query(default=100, ge=1, le=1000), offset: int = Query(default=0, ge=0), source_ip: str | None = None, affected_host: str | None = None, db: Session = Depends(get_db)):
    repository = CorrelationRepository(db)

    correlations, total = repository.get_recent(limit=limit, offset=offset, source_ip=source_ip, affected_host=affected_host)

    return CorrelationListResponse(items=correlations, total=total, limit=limit, offset=offset)


@app.get("/correlations/count", response_model=int)
def get_correlations_count(db: Session = Depends(get_db)):
    repository = CorrelationRepository(db)

    return repository.get_count()


@app.get("/correlations/{correlation_id}", response_model=Correlation)
def get_correlation_by_id(correlation_id: int, db: Session = Depends(get_db)):
    repository = CorrelationRepository(db)
    correlation = repository.get_by_id(correlation_id)

    if correlation is None:
        raise HTTPException(status_code=404, detail="Correlation not found")

    return correlation


@app.get("/incidents", response_model=IncidentListResponse)
def get_incidents(limit: int = Query(default=100, ge=1, le=1000), offset: int = Query(default=0, ge=0), severity: Severity | None = None, status: IncidentStatus | None = None, affected_host: str | None = None, db: Session = Depends(get_db)):
    repository = IncidentRepository(db)

    incidents, total = repository.get_recent(limit=limit, offset=offset, severity=severity, status=status, affected_host=affected_host)

    return IncidentListResponse(items=incidents, total=total, limit=limit, offset=offset)


@app.get("/incidents/{incident_id}", response_model=Incident)
def get_incident_by_id(incident_id: int, db: Session = Depends(get_db)):
    repository = IncidentRepository(db)
    incident = repository.get_by_id(incident_id)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident

@app.patch("/incidents/{incident_id}/status", response_model=Incident)
def patch_incident_status(incident_id: int, update: IncidentStatusUpdate, db: Session = Depends(get_db)):
    repository = IncidentRepository(db)
    incident = repository.update_status(incident_id, update.status)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident