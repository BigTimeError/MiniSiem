from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.collectors.ssh_collector import SSHCollector
from backend.correlation_engine.correlation_engine import CorrelationEngine
from backend.correlation_engine.correlation_rules.ssh_attack_chain_correlation import (
    SSHAttackChainCorrelation,
)
from backend.database.database import Base
from backend.detection_engine.alert_rules.ssh_brute_force_rule import (
    SSHBruteForceRule,
)
from backend.detection_engine.alert_rules.ssh_invalid_user_login import (
    SSHInvalidUserLogin,
    SSHInvalidUserLoginEnumerationRule,
)
from backend.detection_engine.alert_rules.ssh_root_login_rule import (
    SSHRootLoginRule,
)
from backend.detection_engine.detection_engine import DetectionEngine
from backend.models.siem_models import AlertStatus
from backend.parsers.ssh_parser import SSHParser
from backend.storage.alert_repository import AlertRepository
from backend.storage.correlation_repository import CorrelationRepository
from backend.storage.event_repository import EventRepository


DATABASE_URL = (
    "postgresql+psycopg://"
    "minisiem:minisiem_password"
    "@localhost:5432/minisiem_test"
)


def test_ssh_pipeline(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "\n".join(
            [
                # -----------------------------------------------------
                # Root login
                # -----------------------------------------------------

                (
                    "Sep 25 10:00:00 server01 sshd[1234]: "
                    "Accepted password for root from "
                    "192.168.1.100 port 54321 ssh2"
                ),

                # -----------------------------------------------------
                # Five failed authentication attempts.
                # Should trigger SSH_BRUTE_FORCE.
                # -----------------------------------------------------

                (
                    "Sep 25 10:00:01 server01 sshd[1235]: "
                    "Failed password for admin from "
                    "10.0.0.50 port 41231 ssh2"
                ),
                (
                    "Sep 25 10:00:10 server01 sshd[1236]: "
                    "Failed password for admin from "
                    "10.0.0.50 port 41232 ssh2"
                ),
                (
                    "Sep 25 10:00:20 server01 sshd[1237]: "
                    "Failed password for admin from "
                    "10.0.0.50 port 41233 ssh2"
                ),
                (
                    "Sep 25 10:00:30 server01 sshd[1238]: "
                    "Failed password for admin from "
                    "10.0.0.50 port 41234 ssh2"
                ),
                (
                    "Sep 25 10:00:40 server01 sshd[1239]: "
                    "Failed password for admin from "
                    "10.0.0.50 port 41235 ssh2"
                ),

                # -----------------------------------------------------
                # Three invalid users.
                # Should trigger SSH_USER_ENUMERATION.
                # -----------------------------------------------------

                (
                    "Sep 25 10:00:50 server01 sshd[1240]: "
                    "Invalid user test from "
                    "10.0.0.50 port 42100"
                ),
                (
                    "Sep 25 10:01:00 server01 sshd[1241]: "
                    "Invalid user backup from "
                    "10.0.0.50 port 42101"
                ),
                (
                    "Sep 25 10:01:10 server01 sshd[1242]: "
                    "Invalid user oracle from "
                    "10.0.0.50 port 42102"
                ),
                (
                    "Sep 25 10:01:20 server01 sshd[1243]: "
                    "Invalid user guest from "
                    "10.0.0.50 port 42103"
                ),
                (
                    "Sep 25 10:01:30 server01 sshd[1244]: "
                    "Invalid user deploy from "
                    "10.0.0.50 port 42104"
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    engine = create_engine(DATABASE_URL)

    Base.metadata.create_all(engine)

    try:
        with Session(engine) as session:
            collector = SSHCollector(
                log_file,
                follow=False,
            )

            parser = SSHParser()

            event_repository = EventRepository(session)
            alert_repository = AlertRepository(session)
            correlation_repository = CorrelationRepository(session)

            detection_engine = DetectionEngine(
                [
                    SSHRootLoginRule(),
                    SSHBruteForceRule(),
                    SSHInvalidUserLoginEnumerationRule(),
                ]
            )

            correlation_engine = CorrelationEngine(
                [
                    SSHAttackChainCorrelation(),
                ]
            )

            # ---------------------------------------------------------
            # Complete SIEM pipeline
            # ---------------------------------------------------------

            for line in collector.stream():
                event = parser.parse(line) 
                
                if event is None: 
                    continue 
                

                # Event pipeline
                event = event_repository.save(event)

                # Detection pipeline
                alerts = detection_engine.check_for_alerts(event)
                saved_alerts = []

                for alert in alerts:
                    saved_alert = alert_repository.save(alert)
                    saved_alerts.append(saved_alert)

                # Correlation pipeline
                correlations = (
                    correlation_engine.check_for_correlations(
                        saved_alerts,
                        event,
                    )
                )
        
                for correlation in correlations:
                    saved_correlation = correlation_repository.save(correlation)
            # ---------------------------------------------------------
            # Events
            # ---------------------------------------------------------

            events = event_repository.get_recent()

            assert len(events[0]) == 11

            root_event = next(
                event
                for event in events[0]
                if event.username == "root"
            )

            assert root_event.id is not None
            assert root_event.username == "root"
            assert root_event.source_ip == "192.168.1.100"

            # ---------------------------------------------------------
            # Alerts
            # ---------------------------------------------------------

            alerts = alert_repository.get_recent()

            assert len(alerts[0]) >= 3

            alert_list = alerts[0]

            root_alert = next(
                alert
                for alert in alert_list
                if alert.rule_id == "SSH_ROOT_LOGIN"
            )

            brute_force_alert = next(
                alert
                for alert in alert_list
                if alert.rule_id == "SSH_BRUTE_FORCE"
            )

            enumeration_alert = next(
                alert
                for alert in alert_list
                if alert.rule_id == "SSH_USER_ENUMERATION"
            )

            assert root_alert.id is not None
            assert root_alert.status == AlertStatus.OPEN
            assert root_alert.related_events == [root_event.id]

            assert brute_force_alert.id is not None
            assert brute_force_alert.source_ip == "10.0.0.50"
            assert brute_force_alert.affected_host == "server01"

            assert enumeration_alert.id is not None
            assert enumeration_alert.source_ip == "10.0.0.50"
            assert enumeration_alert.affected_host == "server01"

            # ---------------------------------------------------------
            # Correlations
            # ---------------------------------------------------------

            correlations = correlation_repository.get_recent()

            assert len(correlations[0]) >= 1

            correlation = next(
                correlation
                for correlation in correlations[0]
                if correlation.correlation_rule_id
                == "SSH_ATTACK_CHAIN"
            )

            assert correlation.id is not None
            assert correlation.source_ip == "10.0.0.50"
            assert correlation.affected_host == "server01"

            assert brute_force_alert.id in correlation.alerts
            assert enumeration_alert.id in correlation.alerts

    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
