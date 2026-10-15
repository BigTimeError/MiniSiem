from pathlib import Path
import requests
from backend.collectors.ssh_collector import SSHCollector
from backend.parsers.ssh_parser import SSHParser
from backend.agent.config import (
    HOSTNAME,
    IP_ADDRESS,
    SERVER_URL,
    HOST_ID,
    LOG_PATH,
    AGENT_API_TOKEN,
)


def register_host():
    headers = {
        "Authorization": f"Bearer {AGENT_API_TOKEN}"
    }

    response = requests.post(
        f"{SERVER_URL}/hosts/register",
        json={
            "id": HOST_ID,
            "hostname": HOSTNAME,
            "ip_address": IP_ADDRESS,
        },
        headers=headers,
    )
    response.raise_for_status()


def send_event(event):
    data = {
        "host_id": HOST_ID,
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type.value,
        "severity": event.severity.value,
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "username": event.username,
        "service": event.service,
        "message": event.message,
        "metadata": event.metadata,
    }

    headers = {
        "Authorization": f"Bearer {AGENT_API_TOKEN}"
    }

    response = requests.post(
        f"{SERVER_URL}/events",
        json=data,
        headers=headers,
    )
    response.raise_for_status()


def main():
    register_host()

    collector = SSHCollector(Path(LOG_PATH), follow=True)
    parser = SSHParser()

    for line in collector.stream():
        event = parser.parse(line)

        if event is None:
            continue

        send_event(event)


if __name__ == "__main__":
    main()
