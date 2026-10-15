from backend.parsers.ssh_parser import SSHParser


def test_failed_login_except_Success():
    parser = SSHParser()

    line = (
        "Sep 15 14:32:01 server01 "
        "sshd[1234]: Failed password for admin "
        "from 222.222.2.22 port 54321 ssh2"
    )

    event = parser.parse(line)

    assert event is not None
    assert event.event_type == "authentication_failure"
    assert event.severity == "medium"
    assert event.source == "server01"
    assert event.source_ip == "222.222.2.22"
    assert event.source_port == 54321
    assert event.destination_port == 22
    assert event.username == "admin"
    assert event.service == "ssh"

def test_successful_login_except_Success():
    parser = SSHParser()

    line = (
        "Sep 15 14:32:01 server33 "
        "sshd[1234]: Accepted password for goofy "
        "from 222.222.2.22 port 67676 ssh2"
    )

    event = parser.parse(line)

    assert event is not None
    assert event.event_type == "authentication_success"
    assert event.severity == "low"
    assert event.source == "server33"
    assert event.source_ip == "222.222.2.22"
    assert event.source_port == 67676
    assert event.destination_port == 22
    assert event.username == "goofy"
    assert event.service == "ssh"

def test_pubkey_login_except_Success():
    parser = SSHParser()

    line = (
        "Sep 15 14:32:01 bigboy01 "
        "sshd[1234]: Accepted publickey for boss "
        "from 222.222.2.22 port 12345 ssh2: RSA SHA256:LmNoPqRsTuVwXyZ1234567890AbCdEfGhIjK"
    )

    event = parser.parse(line)

    assert event is not None
    assert event.event_type == "authentication_success"
    assert event.severity == "low"
    assert event.source == "bigboy01"
    assert event.source_ip == "222.222.2.22"
    assert event.source_port == 12345
    assert event.destination_port == 22
    assert event.username == "boss"
    assert event.service == "ssh"

def test_session_termination_except_Success():
    parser = SSHParser()

    line = (
        "Sep 15 14:32:01 daServer "
        "sshd[1234]: Disconnected from user admin 222.222.2.22 "
        "port 54321"
    )

    event = parser.parse(line)

    print(event)

    assert event is not None
    assert event.event_type == "session_termination"
    assert event.severity == "low"
    assert event.source == "daServer"
    assert event.source_ip == "222.222.2.22"
    assert event.source_port == 54321
    assert event.destination_port == 22
    assert event.username == "admin"
    assert event.service == "ssh"

def test_unknown_log_except_None():
    parser = SSHParser()

    line = "Sep 15 14:32:05 server01 systemd[1]: beep boop beep"

    event = parser.parse(line)

    assert event is None