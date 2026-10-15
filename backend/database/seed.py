from datetime import datetime, timedelta

from sqlalchemy import delete, select

from backend.database.database import SessionLocal
from backend.database.models import (
    AlertDB,
    AlertEventDB,
    CorrelationAlertDB,
    CorrelationDB,
    EventDB,
    IncidentAlertDB,
    IncidentCorrelationDB,
    IncidentDB,
)
from backend.models.siem_models import (
    AlertStatus,
    EventType,
    IncidentStatus,
    Severity,
)


SEED_MARKER = "demo"


def create_events(session):
    now = datetime.now().replace(microsecond=0)

    events = [
        EventDB(
            timestamp=now - timedelta(minutes=5),
            source="server01",
            event_type=EventType.AUTHENTICATION_SUCCESS,
            severity=Severity.INFO,
            source_ip="192.168.1.50",
            source_port=54321,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="admin",
            service="ssh",
            message="Accepted publickey for admin",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(minutes=12),
            source="server01",
            event_type=EventType.AUTHENTICATION_FAILURE,
            severity=Severity.HIGH,
            source_ip="10.0.0.50",
            source_port=41231,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="admin",
            service="ssh",
            message="Failed password for admin",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(minutes=13),
            source="server01",
            event_type=EventType.AUTHENTICATION_FAILURE,
            severity=Severity.HIGH,
            source_ip="10.0.0.50",
            source_port=41232,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="admin",
            service="ssh",
            message="Failed password for admin",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(minutes=14),
            source="server01",
            event_type=EventType.AUTHENTICATION_FAILURE,
            severity=Severity.HIGH,
            source_ip="10.0.0.50",
            source_port=41233,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="admin",
            service="ssh",
            message="Failed password for admin",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(minutes=15),
            source="server01",
            event_type=EventType.AUTHENTICATION_FAILURE,
            severity=Severity.HIGH,
            source_ip="10.0.0.50",
            source_port=41234,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="admin",
            service="ssh",
            message="Failed password for admin",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(minutes=16),
            source="server01",
            event_type=EventType.AUTHENTICATION_FAILURE,
            severity=Severity.HIGH,
            source_ip="10.0.0.50",
            source_port=41235,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="admin",
            service="ssh",
            message="Failed password for admin",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(minutes=25),
            source="server01",
            event_type=EventType.INVALID_USER_LOGIN,
            severity=Severity.MEDIUM,
            source_ip="10.0.0.51",
            source_port=42100,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="test",
            service="ssh",
            message="Invalid user test from 10.0.0.51",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(minutes=26),
            source="server01",
            event_type=EventType.INVALID_USER_LOGIN,
            severity=Severity.MEDIUM,
            source_ip="10.0.0.51",
            source_port=42101,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="backup",
            service="ssh",
            message="Invalid user backup from 10.0.0.51",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(minutes=27),
            source="server01",
            event_type=EventType.INVALID_USER_LOGIN,
            severity=Severity.MEDIUM,
            source_ip="10.0.0.51",
            source_port=42102,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="oracle",
            service="ssh",
            message="Invalid user oracle from 10.0.0.51",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(minutes=35),
            source="server01",
            event_type=EventType.AUTHENTICATION_SUCCESS,
            severity=Severity.CRITICAL,
            source_ip="192.168.1.60",
            source_port=53120,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="root",
            service="ssh",
            message="Accepted password for root",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(hours=1),
            source="server01",
            event_type=EventType.HTTP_REQUEST,
            severity=Severity.INFO,
            source_ip="192.168.1.100",
            source_port=49821,
            destination_ip="192.168.1.20",
            destination_port=80,
            service="http",
            message="GET /index.html 200",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(hours=1, minutes=5),
            source="server01",
            event_type=EventType.HTTP_REQUEST,
            severity=Severity.INFO,
            source_ip="192.168.1.101",
            source_port=49822,
            destination_ip="192.168.1.20",
            destination_port=80,
            service="http",
            message="GET /login 200",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(hours=2),
            source="server01",
            event_type=EventType.HTTP_REQUEST,
            severity=Severity.MEDIUM,
            source_ip="10.0.0.99",
            source_port=50123,
            destination_ip="192.168.1.20",
            destination_port=80,
            service="http",
            message="GET /admin 403",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(hours=3),
            source="server01",
            event_type=EventType.AUTHENTICATION_SUCCESS,
            severity=Severity.INFO,
            source_ip="192.168.1.20",
            source_port=55001,
            destination_ip="192.168.1.30",
            destination_port=5432,
            username="app",
            service="postgresql",
            message="Database authentication successful",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(hours=4),
            source="server01",
            event_type=EventType.AUTHENTICATION_FAILURE,
            severity=Severity.HIGH,
            source_ip="10.0.0.75",
            source_port=55002,
            destination_ip="192.168.1.30",
            destination_port=5432,
            username="postgres",
            service="postgresql",
            message="Database authentication failed",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(hours=5),
            source="server01",
            event_type=EventType.PROCESS_EXECUTION,
            severity=Severity.LOW,
            source_ip=None,
            source_port=None,
            destination_ip="192.168.1.30",
            destination_port=None,
            service="postgresql",
            message="PostgreSQL background worker started",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(hours=8),
            source="server01",
            event_type=EventType.AUTHENTICATION_FAILURE,
            severity=Severity.HIGH,
            source_ip="10.0.0.52",
            source_port=43001,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="root",
            service="ssh",
            message="Failed password for root",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(hours=12),
            source="server01",
            event_type=EventType.HTTP_REQUEST,
            severity=Severity.LOW,
            source_ip="192.168.1.110",
            source_port=51111,
            destination_ip="192.168.1.20",
            destination_port=443,
            service="https",
            message="GET /api/status 200",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(days=1),
            source="server01",
            event_type=EventType.AUTHENTICATION_SUCCESS,
            severity=Severity.INFO,
            source_ip="192.168.1.50",
            source_port=54001,
            destination_ip="192.168.1.10",
            destination_port=22,
            username="admin",
            service="ssh",
            message="Accepted publickey for admin",
            event_metadata={"seed": SEED_MARKER},
        ),
        EventDB(
            timestamp=now - timedelta(days=1, hours=3),
            source="server01",
            event_type=EventType.HTTP_REQUEST,
            severity=Severity.INFO,
            source_ip="192.168.1.120",
            source_port=52001,
            destination_ip="192.168.1.20",
            destination_port=443,
            service="https",
            message="GET / 200",
            event_metadata={"seed": SEED_MARKER},
        ),
    ]

    session.add_all(events)
    session.flush()

    return events


def create_alerts(session, events):
    now = datetime.now().replace(microsecond=0)

    brute_force_events = events[1:6]
    enumeration_events = events[6:9]
    root_login_event = events[9]
    database_event = events[14]

    brute_force_alert = AlertDB(
        timestamp=now - timedelta(minutes=12),
        rule_id="ssh_brute_force",
        title="SSH Brute Force Detected",
        description=(
            "Multiple failed SSH authentication attempts were detected "
            "from the same source IP within a short period."
        ),
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        source_ip="10.0.0.50",
        affected_host="server01",
        mitre_technique="T1110",
    )

    enumeration_alert = AlertDB(
        timestamp=now - timedelta(minutes=25),
        rule_id="ssh_invalid_user_enumeration",
        title="SSH User Enumeration Detected",
        description=(
            "Multiple authentication attempts using invalid usernames "
            "were detected from the same source."
        ),
        severity=Severity.MEDIUM,
        status=AlertStatus.ACKNOWLEDGED,
        source_ip="10.0.0.51",
        affected_host="server01",
        mitre_technique="T1087",
    )

    root_login_alert = AlertDB(
        timestamp=now - timedelta(minutes=35),
        rule_id="ssh_root_login",
        title="Root Login Detected",
        description=(
            "A successful SSH authentication for the root account "
            "was detected."
        ),
        severity=Severity.CRITICAL,
        status=AlertStatus.OPEN,
        source_ip="192.168.1.60",
        affected_host="server01",
        mitre_technique="T1078",
    )

    database_alert = AlertDB(
        timestamp=now - timedelta(hours=4),
        rule_id="database_authentication_failure",
        title="Database Authentication Failure",
        description=(
            "A failed PostgreSQL authentication attempt was detected "
            "against the monitored database server."
        ),
        severity=Severity.HIGH,
        status=AlertStatus.RESOLVED,
        source_ip="10.0.0.75",
        affected_host="server01",
        mitre_technique="T1110",
    )

    old_alert = AlertDB(
        timestamp=now - timedelta(days=1, hours=2),
        rule_id="ssh_failed_login",
        title="Repeated SSH Authentication Failure",
        description=(
            "Repeated SSH authentication failures were observed "
            "against the monitored server."
        ),
        severity=Severity.HIGH,
        status=AlertStatus.FALSE_POSITIVE,
        source_ip="10.0.0.52",
        affected_host="server01",
        mitre_technique="T1110",
    )

    alerts = [
        brute_force_alert,
        enumeration_alert,
        root_login_alert,
        database_alert,
        old_alert,
    ]

    session.add_all(alerts)
    session.flush()

    links = []

    for event in brute_force_events:
        links.append(
            AlertEventDB(
                alert_id=brute_force_alert.id,
                event_id=event.id,
            )
        )

    for event in enumeration_events:
        links.append(
            AlertEventDB(
                alert_id=enumeration_alert.id,
                event_id=event.id,
            )
        )

    links.append(
        AlertEventDB(
            alert_id=root_login_alert.id,
            event_id=root_login_event.id,
        )
    )

    links.append(
        AlertEventDB(
            alert_id=database_alert.id,
            event_id=database_event.id,
        )
    )

    session.add_all(links)
    session.flush()

    return alerts


def create_correlations(session, alerts):
    now = datetime.now().replace(microsecond=0)

    brute_force_alert = alerts[0]
    enumeration_alert = alerts[1]
    root_login_alert = alerts[2]
    database_alert = alerts[3]

    ssh_attack_chain = CorrelationDB(
        timestamp=now - timedelta(minutes=10),
        correlation_rule_id="SSH_ATTACK_CHAIN",
        source_ip="10.0.0.50",
        affected_host="server01",
    )

    root_compromise_chain = CorrelationDB(
        timestamp=now - timedelta(minutes=30),
        correlation_rule_id="SSH_ROOT_COMPROMISE_CHAIN",
        source_ip="192.168.1.60",
        affected_host="server01",
    )

    database_attack_chain = CorrelationDB(
        timestamp=now - timedelta(hours=4),
        correlation_rule_id="DATABASE_ATTACK_CHAIN",
        source_ip="10.0.0.75",
        affected_host="server01",
    )

    correlations = [
        ssh_attack_chain,
        root_compromise_chain,
        database_attack_chain,
    ]

    session.add_all(correlations)
    session.flush()

    links = [
        CorrelationAlertDB(
            correlation_id=ssh_attack_chain.id,
            alert_id=brute_force_alert.id,
        ),
        CorrelationAlertDB(
            correlation_id=ssh_attack_chain.id,
            alert_id=enumeration_alert.id,
        ),
        CorrelationAlertDB(
            correlation_id=root_compromise_chain.id,
            alert_id=brute_force_alert.id,
        ),
        CorrelationAlertDB(
            correlation_id=root_compromise_chain.id,
            alert_id=root_login_alert.id,
        ),
        CorrelationAlertDB(
            correlation_id=database_attack_chain.id,
            alert_id=database_alert.id,
        ),
    ]

    session.add_all(links)
    session.flush()

    return correlations


def create_incidents(session, alerts, correlations):
    now = datetime.now().replace(microsecond=0)

    brute_force_alert = alerts[0]
    enumeration_alert = alerts[1]
    root_login_alert = alerts[2]
    database_alert = alerts[3]

    ssh_attack_chain = correlations[0]
    root_compromise_chain = correlations[1]
    database_attack_chain = correlations[2]

    ssh_attack_incident = IncidentDB(
        timestamp=now - timedelta(minutes=9),
        title="SSH Attack Chain Detected",
        description=(
            "A coordinated SSH attack was detected. Multiple failed "
            "authentication attempts were followed by attempts to "
            "enumerate valid usernames."
        ),
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        source_ip="10.0.0.50",
        affected_host="server01",
    )

    root_compromise_incident = IncidentDB(
        timestamp=now - timedelta(minutes=29),
        title="Possible SSH Server Compromise",
        description=(
            "A successful root SSH login was detected in the context "
            "of suspicious authentication activity. Further investigation "
            "is required to determine whether the server was compromised."
        ),
        severity=Severity.CRITICAL,
        status=IncidentStatus.OPEN,
        source_ip="192.168.1.60",
        affected_host="server01",
    )

    database_incident = IncidentDB(
        timestamp=now - timedelta(hours=3, minutes=55),
        title="Database Authentication Attack",
        description=(
            "A failed PostgreSQL authentication attempt was detected "
            "against the monitored database server. The related alert "
            "has already been resolved."
        ),
        severity=Severity.HIGH,
        status=IncidentStatus.RESOLVED,
        source_ip="10.0.0.75",
        affected_host="server01",
    )

    false_positive_incident = IncidentDB(
        timestamp=now - timedelta(days=1, hours=1, minutes=50),
        title="Repeated SSH Authentication Failure",
        description=(
            "Repeated SSH authentication failures were observed from "
            "a single source. The activity was investigated and determined "
            "to be a false positive."
        ),
        severity=Severity.MEDIUM,
        status=IncidentStatus.FALSE_POSITIVE,
        source_ip="10.0.0.52",
        affected_host="server01",
    )

    incidents = [
        ssh_attack_incident,
        root_compromise_incident,
        database_incident,
        false_positive_incident,
    ]

    session.add_all(incidents)
    session.flush()

    links = [
        # SSH attack chain
        IncidentAlertDB(
            incident_id=ssh_attack_incident.id,
            alert_id=brute_force_alert.id,
        ),
        IncidentAlertDB(
            incident_id=ssh_attack_incident.id,
            alert_id=enumeration_alert.id,
        ),
        IncidentCorrelationDB(
            incident_id=ssh_attack_incident.id,
            correlation_id=ssh_attack_chain.id,
        ),

        # Possible SSH compromise
        IncidentAlertDB(
            incident_id=root_compromise_incident.id,
            alert_id=root_login_alert.id,
        ),
        IncidentCorrelationDB(
            incident_id=root_compromise_incident.id,
            correlation_id=root_compromise_chain.id,
        ),

        # Database attack
        IncidentAlertDB(
            incident_id=database_incident.id,
            alert_id=database_alert.id,
        ),
        IncidentCorrelationDB(
            incident_id=database_incident.id,
            correlation_id=database_attack_chain.id,
        ),
    ]

    # The false-positive incident has no correlation in this demo.
    # It is linked directly to the original alert.
    links.append(
        IncidentAlertDB(
            incident_id=false_positive_incident.id,
            alert_id=alerts[4].id,
        )
    )

    session.add_all(links)
    session.flush()

    return incidents


def clear_seed_data(session):
    seed_event_ids = session.scalars(
        select(EventDB.id).where(
            EventDB.event_metadata["seed"].as_string() == SEED_MARKER
        )
    ).all()

    # Find demo alerts before deleting anything.
    seed_alert_ids = session.scalars(
        select(AlertDB.id).where(
            AlertDB.source_ip.in_(
                [
                    "10.0.0.50",
                    "10.0.0.51",
                    "192.168.1.60",
                    "10.0.0.75",
                    "10.0.0.52",
                ]
            )
        )
    ).all()

    # Find demo correlations through their linked demo alerts.
    seed_correlation_ids = []

    if seed_alert_ids:
        seed_correlation_ids = session.scalars(
            select(CorrelationAlertDB.correlation_id).where(
                CorrelationAlertDB.alert_id.in_(seed_alert_ids)
            )
        ).all()

    # Find demo incidents through their linked demo alerts/correlations.
    seed_incident_ids = set()

    if seed_alert_ids:
        incident_ids_from_alerts = session.scalars(
            select(IncidentAlertDB.incident_id).where(
                IncidentAlertDB.alert_id.in_(seed_alert_ids)
            )
        ).all()

        seed_incident_ids.update(incident_ids_from_alerts)

    if seed_correlation_ids:
        incident_ids_from_correlations = session.scalars(
            select(IncidentCorrelationDB.incident_id).where(
                IncidentCorrelationDB.correlation_id.in_(
                    seed_correlation_ids
                )
            )
        ).all()

        seed_incident_ids.update(incident_ids_from_correlations)

    # ---------------------------------------------------------
    # Delete incidents first.
    # ---------------------------------------------------------

    if seed_incident_ids:
        session.execute(
            delete(IncidentAlertDB).where(
                IncidentAlertDB.incident_id.in_(seed_incident_ids)
            )
        )

        session.execute(
            delete(IncidentCorrelationDB).where(
                IncidentCorrelationDB.incident_id.in_(seed_incident_ids)
            )
        )

        session.execute(
            delete(IncidentDB).where(
                IncidentDB.id.in_(seed_incident_ids)
            )
        )

    # ---------------------------------------------------------
    # Delete correlations.
    # ---------------------------------------------------------

    if seed_correlation_ids:
        session.execute(
            delete(CorrelationAlertDB).where(
                CorrelationAlertDB.correlation_id.in_(
                    seed_correlation_ids
                )
            )
        )

        session.execute(
            delete(CorrelationDB).where(
                CorrelationDB.id.in_(seed_correlation_ids)
            )
        )

    # ---------------------------------------------------------
    # Delete alert/event relationships.
    # ---------------------------------------------------------

    if seed_event_ids:
        session.execute(
            delete(AlertEventDB).where(
                AlertEventDB.event_id.in_(seed_event_ids)
            )
        )

    if seed_alert_ids:
        session.execute(
            delete(AlertEventDB).where(
                AlertEventDB.alert_id.in_(seed_alert_ids)
            )
        )

        session.execute(
            delete(AlertDB).where(
                AlertDB.id.in_(seed_alert_ids)
            )
        )

    # ---------------------------------------------------------
    # Delete events.
    # ---------------------------------------------------------

    if seed_event_ids:
        session.execute(
            delete(EventDB).where(
                EventDB.id.in_(seed_event_ids)
            )
        )

    session.commit()


def seed_database():
    session = SessionLocal()

    try:
        events = create_events(session)
        alerts = create_alerts(session, events)
        correlations = create_correlations(session, alerts)
        incidents = create_incidents(
            session,
            alerts,
            correlations,
        )

        session.commit()

        print(f"Created {len(events)} events.")
        print(f"Created {len(alerts)} alerts.")
        print(f"Created {len(correlations)} correlations.")
        print(f"Created {len(incidents)} incidents.")

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Create or remove MiniSIEM demo data."
    )

    parser.add_argument(
        "--clear",
        action="store_true",
        help="Remove demo data.",
    )

    parser.add_argument(
        "--reset",
        action="store_true",
        help="Remove existing demo data and create it again.",
    )

    args = parser.parse_args()

    if args.clear and args.reset:
        parser.error(
            "--clear and --reset cannot be used together."
        )

    session = SessionLocal()

    try:
        if args.clear or args.reset:
            clear_seed_data(session)
            print("Demo data cleared.")

    finally:
        session.close()

    if args.reset or (not args.clear):
        seed_database()


if __name__ == "__main__":
    main()