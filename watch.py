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

# Parameters mirrored from the main process (install.ps1 passes the same ones).
UPSTREAM = "192.168.1.1,223.5.5.5,119.29.29.29"
LAN = False
if "--upstream" in sys.argv:
    try:
        UPSTREAM = sys.argv[sys.argv.index("--upstream") + 1]
    except Exception:
        pass
LAN = "--lan" in sys.argv

# localhost query (A record) - reuses the wire format from the main app
_PKT = (b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07localhost\x00\x00\x01\x00\x01")


def alive():
    """True if something is listening and answering on 127.0.0.1:53."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    try:
        s.sendto(_PKT, ("127.0.0.1", 53))
        data, _ = s.recvfrom(512)
        return len(data) > 0
    except Exception:
        return False
    finally:
        s.close()


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
            if not alive():
                start()
                time.sleep(5)
        except Exception:
            pass
        time.sleep(20)


if __name__ == "__main__":
    main()
