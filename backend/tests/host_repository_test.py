from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.database.database import Base
from backend.models.siem_models import Host
from backend.storage.host_repository import HostRepository

DATABASE_URL = (
    "postgresql+psycopg://"
    "minisiem:minisiem_password"
    "@localhost:5432/minisiem_test"
)


@pytest.fixture 
def host_repository(): 
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine) 

    with Session(engine) as session:
        yield HostRepository(session)

    Base.metadata.drop_all(engine)
    engine.dispose() 


def create_host(
    host_id="server01",
    hostname="server01",
    ip_address="10.0.0.10",
):
    return Host(
        id=host_id,
        hostname=hostname,
        ip_address=ip_address,
        events=0,
        alerts=0,
        status="online",
        last_seen=datetime(2026, 10, 8, 10, 0, 0),
    )


def test_save_host(host_repository):

    host = create_host()

    saved_host = host_repository.save(host)

    assert saved_host.id == "server01"
    assert saved_host.hostname == "server01"
    assert saved_host.ip_address == "10.0.0.10"
    assert saved_host.status == "online"


def test_get_host_by_id(host_repository):
    host_repository.save(create_host())

    host = host_repository.get_by_id("server01")

    assert host is not None
    assert host.hostname == "server01"


def test_get_host_by_hostname(host_repository):
    host_repository.save(create_host())

    host = host_repository.get_by_hostname("server01")

    assert host is not None
    assert host.id == "server01"


def test_get_host_by_ip(host_repository):
    host_repository.save(create_host())

    host = host_repository.get_by_ip("10.0.0.10")

    assert host is not None
    assert host.hostname == "server01"


def test_get_host_returns_none_for_unknown_host(host_repository):
    host = host_repository.get_by_id("unknown")

    assert host is None


def test_get_all_hosts(host_repository):
    host_repository.save(
        create_host(
            host_id="server02",
            hostname="server02",
            ip_address="10.0.0.11",
        )
    )

    host_repository.save(create_host())

    hosts = host_repository.get_all()

    assert len(hosts) == 2
    assert hosts[0].hostname == "server01"
    assert hosts[1].hostname == "server02"


def test_update_last_seen(host_repository):
    host_repository.save(create_host())

    timestamp = datetime(2026, 10, 8, 11, 0, 0)

    updated_host = host_repository.update_last_seen(
        "server01",
        timestamp,
    )

    assert updated_host is not None
    assert updated_host.last_seen == timestamp