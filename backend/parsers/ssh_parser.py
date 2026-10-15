from datetime import datetime
import re

from backend.models.siem_models import Event


class SSHParser:

    INVALID_USER_PATTERN = re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
        r"(?P<host>\S+) "
        r"sshd\[\d+\]: "
        r"Invalid user "
        r"(?P<username>\S+) "
        r"from (?P<source_ip>\S+) "
        r"port (?P<source_port>\d+)"
    )

    FAILED_PASSWORD_PATTERN = re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
        r"(?P<host>\S+) "
        r"sshd\[\d+\]: "
        r"Failed password for "
        r"(?:(?P<invalid_user>invalid user) )?"
        r"(?P<username>\S+) "
        r"from (?P<source_ip>\S+) "
        r"port (?P<source_port>\d+) "
        r"ssh2"
    )

    SUCCESSFUL_LOGIN_PATTERN = re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
        r"(?P<host>\S+) "
        r"sshd\[\d+\]: "
        r"Accepted password for "
        r"(?P<username>\S+) "
        r"from (?P<source_ip>\S+) "
        r"port (?P<source_port>\d+) "
        r"ssh2"
    )

    PUBKEY_AUTHENTICATION_PATTERN = re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
        r"(?P<host>\S+) "
        r"sshd\[\d+\]: "
        r"Accepted publickey for "
        r"(?P<username>\S+) "
        r"from (?P<source_ip>\S+) "
        r"port (?P<source_port>\d+) "
        r"ssh2: "
        r"(?P<public_key>\S+)"
    )

    SESSION_TERMINATION_PATTERN = re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
        r"(?P<host>\S+) "
        r"sshd\[\d+\]: "
        r"Disconnected from user "
        r"(?P<username>\S+) "
        r"(?P<source_ip>\S+) "
        r"port (?P<source_port>\d+)"
    )

    def parse(self, line: str) -> Event | None:
        """
        Parse an SSH log line and return the corresponding Event.

        Returns None if the line does not match any known SSH log pattern.
        """

        match = self.INVALID_USER_PATTERN.match(line)

        if match:
            return self.parse_invalid_user(
                match.groupdict(),
                line,
            )

        match = self.FAILED_PASSWORD_PATTERN.match(line)

        if match:
            data = match.groupdict()

            if data["invalid_user"] is not None:
                return self.parse_invalid_user(
                    data,
                    line,
                )

            return self.parse_failed_login(
                data,
                line,
            )

        match = self.SUCCESSFUL_LOGIN_PATTERN.match(line)

        if match:
            return self.parse_successful_login(
                match.groupdict(),
                line,
            )

        match = self.PUBKEY_AUTHENTICATION_PATTERN.match(line)

        if match:
            return self.parse_pubkey_authentication(
                match.groupdict(),
                line,
            )

        match = self.SESSION_TERMINATION_PATTERN.match(line)

        if match:
            return self.parse_session_termination(
                match.groupdict(),
                line,
            )

        return None

    def parse_timestamp(self, timestamp: str) -> datetime:
        return datetime.strptime(
            f"{datetime.now().year} {timestamp}",
            "%Y %b %d %H:%M:%S",
        )

    def parse_failed_login(self, data: dict, line: str) -> Event:
        return Event(
            timestamp=self.parse_timestamp(data["timestamp"]),
            source=data["host"],
            event_type="authentication_failure",
            severity="medium",
            source_ip=data["source_ip"],
            source_port=int(data["source_port"]),
            destination_port=22,
            username=data["username"],
            service="ssh",
            message=line,
        )

    def parse_invalid_user(self, data: dict, line: str) -> Event:
        return Event(
            timestamp=self.parse_timestamp(data["timestamp"]),
            source=data["host"],
            event_type="invalid_user_login",
            severity="medium",
            source_ip=data["source_ip"],
            source_port=int(data["source_port"]),
            destination_port=22,
            username=data["username"],
            service="ssh",
            message=line,
        )

    def parse_successful_login(self, data: dict, line: str) -> Event:
        return Event(
            timestamp=self.parse_timestamp(data["timestamp"]),
            source=data["host"],
            event_type="authentication_success",
            severity="low",
            source_ip=data["source_ip"],
            source_port=int(data["source_port"]),
            destination_port=22,
            username=data["username"],
            service="ssh",
            message=line,
        )

    def parse_pubkey_authentication(self, data: dict, line: str) -> Event:
        return Event(
            timestamp=self.parse_timestamp(data["timestamp"]),
            source=data["host"],
            event_type="authentication_success",
            severity="low",
            source_ip=data["source_ip"],
            source_port=int(data["source_port"]),
            destination_port=22,
            username=data["username"],
            service="ssh",
            message=line,
        )

    def parse_session_termination(self, data: dict, line: str) -> Event:
        return Event(
            timestamp=self.parse_timestamp(data["timestamp"]),
            source=data["host"],
            event_type="session_termination",
            severity="low",
            source_ip=data["source_ip"],
            source_port=int(data["source_port"]),
            destination_port=22,
            username=data["username"],
            service="ssh",
            message=line,
        )
