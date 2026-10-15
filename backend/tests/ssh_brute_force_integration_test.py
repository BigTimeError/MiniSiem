from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.collectors.ssh_collector import SSHCollector
from backend.database.database import Base
from backend.detection_engine.detection_engine import DetectionEngine
from backend.parsers.ssh_parser import SSHParser
from backend.storage.alert_repository import AlertRepository
from backend.storage.event_repository import EventRepository
from backend.detection_engine.alert_rules.ssh_brute_force_rule import SSHBruteForceRule


DATABASE_URL = (
    "postgresql+psycopg://"
    "minisiem:minisiem_password"
    "@localhost:5432/minisiem_test"
)


def test_ssh_brute_force_pipeline(tmp_path):


    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "\n".join([
            "Sep 25 10:00:00 server sshd[1001]: Failed password for testuser from 192.168.1.100 port 50001 ssh2",
            "Sep 25 10:00:10 server sshd[1002]: Failed password for testuser from 192.168.1.100 port 50002 ssh2",
            "Sep 25 10:00:20 server sshd[1003]: Failed password for testuser from 192.168.1.100 port 50003 ssh2",
            "Sep 25 10:00:30 server sshd[1004]: Failed password for testuser from 192.168.1.100 port 50004 ssh2",
            "Sep 25 10:00:40 server sshd[1005]: Failed password for testuser from 192.168.1.100 port 50005 ssh2",
        ]),
        encoding="utf-8",
    )


    engine = create_engine(DATABASE_URL)

    Base.metadata.create_all(engine)

    with Session(engine) as session:

        collector = SSHCollector(
            log_file,
            follow=False,
        )

        parser = SSHParser()

        event_repository = EventRepository(session)
        alert_repository = AlertRepository(session)

        detection_engine = DetectionEngine([
            SSHBruteForceRule(),
        ])


        for line in collector.stream():

            event = parser.parse(line)

            if event is None:
                continue

            event = event_repository.save(event)

            alerts = detection_engine.check_for_alerts(event)

            for alert in alerts:
                alert_repository.save(alert)


        events = event_repository.get_recent()

        assert len(events[0]) == 5

        for event in events[0]:
            assert event.id is not None
            assert event.source_ip == "192.168.1.100"
            assert event.username == "testuser"

        alerts = alert_repository.get_recent()

        assert len(alerts[0]) == 1

        alert = alerts[0][0]

        assert alert.id is not None
        assert alert.rule_id == "SSH_BRUTE_FORCE"
        assert alert.source_ip == "192.168.1.100"

        assert len(alert.related_events) == 1
        assert alert.related_events[0] in [
            event.id for event in events[0]
        ]


    Base.metadata.drop_all(engine)
    engine.dispose()