import platform
import subprocess
import time
import urllib.request

URL = "http://localhost:3000"

print("Starting MiniSIEM...")

subprocess.run(
    ["docker", "compose", "up", "-d"],
    check=True,
)

print("Waiting for MiniSIEM...")

while True:
    try:
        urllib.request.urlopen(URL, timeout=2)
        break
    except Exception:
        time.sleep(1)

print("MiniSIEM is ready.")
print(f"Opening {URL}...")

system = platform.system()

if system == "Windows":
    subprocess.Popen(["cmd", "/c", "start", "", URL])

elif system == "Darwin":
    subprocess.Popen(["open", URL])

elif system == "Linux":
    subprocess.Popen(["xdg-open", URL])

else:
    print(f"Please open {URL} manually.")