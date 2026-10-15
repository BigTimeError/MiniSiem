import threading
import time

from backend.collectors.ssh_collector import SSHCollector


def test_stream_reads_new_line_expect_success(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")

    collector = SSHCollector(log_file)

    result = []

    def read_line():
        stream = collector.stream()
        result.append(next(stream))

    thread = threading.Thread(target=read_line)
    thread.start()

    time.sleep(0.2)

    with log_file.open("a", encoding="utf-8") as file:
        file.write("Jul 17 14:32:45 myserver sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 45678 ssh2: RSA SHA256:Ab3d9EfGhIjK1mN0pQrSt2uVwXyZ\n")
        file.flush()

    thread.join(timeout=1)

    assert not thread.is_alive()
    assert result == ["Jul 17 14:32:45 myserver sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 45678 ssh2: RSA SHA256:Ab3d9EfGhIjK1mN0pQrSt2uVwXyZ"]

def test_stream_reads_several_new_lines_expect_success(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")

    collector = SSHCollector(log_file)

    result = []

    def read_lines():
        stream = collector.stream()

        for line in stream:
            result.append(line)

            if len(result) == 3:
                break

    thread = threading.Thread(target=read_lines)
    thread.start()

    time.sleep(0.2)

    with log_file.open("a", encoding="utf-8") as file:
        file.write("Jul 17 14:32:45 myserver sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 45678 ssh2: RSA SHA256:Ab3d9EfGhIjK1mN0pQrSt2uVwXyZ\n")
        file.flush()
        file.write("Jul 17 15:45:23 webserver sshd[5678]: Accepted password for devuser from 10.0.2.15 port 49812 ssh2\n")    
        file.flush()
        file.write("Jul 17 15:47:10 webserver sshd[5679]: Failed password for invalid user admin from 45.227.253.82 port 38654 ssh2\n")
        file.flush()

    thread.join(timeout=1)

    assert not thread.is_alive()
    assert result == ["Jul 17 14:32:45 myserver sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 45678 ssh2: RSA SHA256:Ab3d9EfGhIjK1mN0pQrSt2uVwXyZ", 
                      "Jul 17 15:45:23 webserver sshd[5678]: Accepted password for devuser from 10.0.2.15 port 49812 ssh2",
                      "Jul 17 15:47:10 webserver sshd[5679]: Failed password for invalid user admin from 45.227.253.82 port 38654 ssh2"]


def test_stream_reads_random_logs_expect_success(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")

    collector = SSHCollector(log_file)

    result = []

    def read_lines():
            stream = collector.stream()
    
            for line in stream:
                result.append(line)
    
                if len(result) == 3:
                    break

    thread = threading.Thread(target=read_lines)
    thread.start()

    time.sleep(0.2)

    with log_file.open("a", encoding="utf-8") as file:
        file.write("Jul 17 14:32:45 myserver sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 45678 ssh2: RSA SHA256:Ab3d9EfGhIjK1mN0pQrSt2uVwXyZ\n")
        file.flush()
        file.write("Jul 17 15:45:23 webserver sshd[5678]: Going in hot\n")    
        file.flush()
        file.write("And so he said: Failed password for invalid user admin from 45.227.253.82 port 38654 ssh2\n")
        file.flush()

    thread.join(timeout=1)

    assert not thread.is_alive()
    assert result == ["Jul 17 14:32:45 myserver sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 45678 ssh2: RSA SHA256:Ab3d9EfGhIjK1mN0pQrSt2uVwXyZ", 
                      "Jul 17 15:45:23 webserver sshd[5678]: Going in hot",
                      "And so he said: Failed password for invalid user admin from 45.227.253.82 port 38654 ssh2"]