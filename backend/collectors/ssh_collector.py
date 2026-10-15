from pathlib import Path
import time

class SSHCollector:

    def __init__(self, log_path: Path, follow: bool = True):
        self.log_path = log_path
        self.follow = follow

    def stream(self):
        """Stream that constantly reads the log file and parses each new line that is being added

        Yields:
            str: yields each new line that is being added to the log file
        """

        with self.log_path.open("r", encoding="utf-8") as file:

            if self.follow:
                file.seek(0, 2)

            for line in file:
                yield line.strip()

            if not self.follow:
                return

            while True:
                line = file.readline()

                if not line:
                    time.sleep(0.1)
                    continue

                yield line.strip()