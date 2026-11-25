"""Drive the PIN fixture through an owned terminal and a detached session."""
import errno
import os
import pty
import select
import signal
import subprocess
import sys
import termios
import time

executable = sys.argv[1]
arguments = [executable, "--exact", "pin_provider::tests::interactive_pin_fixture", "--ignored", "--nocapture"]

# No controlling terminal: a PIN request must fail closed.
environment = dict(os.environ, KIT_TEST_PIN_TERMINAL="detached")
result = subprocess.run(arguments, env=environment, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        start_new_session=True, timeout=30)
assert result.returncode == 0, "detached PIN request did not fail closed"

for retries in (0, 2):
    environment = dict(os.environ, KIT_TEST_PIN_TERMINAL=str(retries))
    pid, master = pty.fork()
    if pid == 0:
        os.execve(executable, arguments, environment)
    reaped = False
    try:
        deadline = time.monotonic() + 30
        captured = bytearray()
        while not captured.endswith(b": "):
            assert time.monotonic() < deadline, "PIN prompt did not arrive"
            if select.select([master], [], [], 0.1)[0]:
                captured.extend(os.read(master, 4096))
        expected = b"Device: " if retries == 0 else b"Device (2 attempt(s) remaining): "
        assert captured.endswith(expected), "wrong retry hint"
        while termios.tcgetattr(master)[3] & termios.ECHO:
            assert time.monotonic() < deadline, "PIN echo was not disabled"
            time.sleep(0.005)
        os.write(master, b"2468\n")
        while True:
            finished, status = os.waitpid(pid, os.WNOHANG)
            if finished:
                reaped = True
                break
            assert time.monotonic() < deadline, "PIN fixture did not exit"
            if select.select([master], [], [], 0.1)[0]:
                try:
                    os.read(master, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, "PIN fixture failed"
        assert termios.tcgetattr(master)[3] & termios.ECHO, "terminal echo was not restored"
    finally:
        if not reaped:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(master)
