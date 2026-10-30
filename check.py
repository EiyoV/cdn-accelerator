# cdn-accelerator periodic keeper, run by Task Scheduler every 5 minutes.
# Fully independent of any app process tree (Task Scheduler owns this):
# if the optimizer or watchdog died - crash, kill, or an app's exit
# cleanup killing children - relaunch them here. No powershell.exe
# dependency (this machine is pwsh-only); uses only the bundled python.
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PYW = os.path.join(HERE, "runtime", "python312", "pythonw.exe")
if not os.path.isfile(PYW):
    PYW = "pythonw.exe"
MAIN = os.path.join(HERE, "cdn-accelerator.py")
WATCH = os.path.join(HERE, "watch.py")
HEARTBEAT = os.path.join(HERE, "watch.heartbeat")
UPSTREAM = "192.168.1.1,223.5.5.5,119.29.29.29"
LAN = "--lan"


def udp53_alive():
    """Any listener on :53? Try binding both addresses (LAN binds 0.0.0.0)."""
    for addr in ("127.0.0.1", "0.0.0.0"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((addr, 53))
        except OSError:
            return True
        finally:
            s.close()
    return False


def watch_alive():
    """Watchdog alive if its heartbeat file was touched within ~90s.

    No wmic (removed on new Windows), no powershell.exe (pwsh-only machine):
    the watchdog writes watch.heartbeat every ~20s, so freshness is the
    signal. A stale heartbeat means the watchdog died -> relaunch."""
    try:
        age = time.time() - os.path.getmtime(HEARTBEAT)
        return age < 90
    except Exception:
        # no heartbeat file at all -> definitely not alive
        return False


def launch(script, extra=None):
    args = [PYW, "-u", script, "--upstream", UPSTREAM]
    if LAN:
        args.append(LAN)
    if extra:
        args += extra
    try:
        subprocess.Popen(args, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


def main():
    if not udp53_alive():
        launch(MAIN)
    if not watch_alive():
        launch(WATCH)


if __name__ == "__main__":
    main()