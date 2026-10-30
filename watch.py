# CDN Accelerator - watchdog
# Keeps the optimizer alive. Every ~20s it checks that something actually
# answers on 127.0.0.1:53; if not (crash, kill, reboot race), it relaunches
# cdn-accelerator.py with the same arguments this watchdog was started with.
# Runs headless via pythonw; install.ps1 registers it on logon.
#
# Why: the system DNS is pointed at 127.0.0.1 at install time. If the python
# process ever dies, the machine keeps resolving through a dead socket - pages
# already in cache still open, but every new lookup (images, subresources)
# fails with "remote host forcibly closed". The watchdog closes that gap.
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
HEARTBEAT = os.path.join(HERE, "watch.heartbeat")

# Parameters mirrored from the main process (install.ps1 passes the same ones).
UPSTREAM = "192.168.1.1,223.5.5.5,119.29.29.29"
LAN = False
if "--upstream" in sys.argv:
    try:
        UPSTREAM = sys.argv[sys.argv.index("--upstream") + 1]
    except Exception:
        pass
LAN = "--lan" in sys.argv

def alive():
    """True if some process already listens on the DNS port.

    Probe by TRYING TO BIND without SO_REUSEADDR: bind fails when a listener
    exists, succeeds (we close immediately) when it is free. BOTH bind
    addresses are tested: in LAN mode the optimizer binds 0.0.0.0, and on
    Windows binding 127.0.0.1 can succeed even though 0.0.0.0:53 is taken -
    a single-address probe would misread "free" and relaunch an instance that
    then dies on bind (the zombie-farm bug). Either bind failing means alive."""
    for addr in ("127.0.0.1", "0.0.0.0"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((addr, 53))
        except OSError:
            return True  # in use -> a listener exists
        finally:
            s.close()
    return False  # both free -> nobody listening -> not alive


def start():
    args = [PYW, "-u", MAIN, "--upstream", UPSTREAM]
    if LAN:
        args.append("--lan")
    try:
        subprocess.Popen(args, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


def main():
    while True:
        try:
            # heartbeat so check.py (Task Scheduler, every 5 min) can tell
            # this watchdog is alive without needing wmic/powershell.exe
            try:
                now = time.time()
                with open(HEARTBEAT, "w") as f:
                    f.write("%d" % int(now))
                os.utime(HEARTBEAT, (now, now))
            except Exception:
                pass
            if not alive():
                start()
                time.sleep(5)
        except Exception:
            pass
        time.sleep(20)


if __name__ == "__main__":
    main()
