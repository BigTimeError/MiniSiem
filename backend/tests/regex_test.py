import re

line = (
    "Sep 15 14:32:01 daServer "
    "sshd[1234]: Disconnected from user admin 222.222.2.22 "
    "port 54321"
)

pattern = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"sshd\[\d+\]: "
    r"Disconnected from user (?P<username>\S+) "
    r"(?P<source_ip>\S+) "
    r"port (?P<source_port>\d+)"
)

match = pattern.match(line)

print(match)

if match:
    print(match.groupdict())