import os
from dotenv import load_dotenv

load_dotenv()

AGENT_API_TOKEN = os.getenv("AGENT_API_TOKEN")

if not AGENT_API_TOKEN:
    raise RuntimeError("AGENT_API_TOKEN is not configured")

SERVER_URL = "http://localhost:8000"

HOST_ID = "server01"
HOSTNAME = "server01"
IP_ADDRESS = "192.168.1.10"

LOG_PATH = "/var/log/auth.log"