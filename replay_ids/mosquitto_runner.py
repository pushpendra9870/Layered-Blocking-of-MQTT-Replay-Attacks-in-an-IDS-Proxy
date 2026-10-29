"""Starts a private Mosquitto instance (loopback, anonymous, unlimited queues, debug log).
The debug log ('Received PUBLISH from <client> ...') is the broker-side ground truth for
'what actually reached the broker'."""
import os, re, shutil, socket, subprocess, sys, time
from pathlib import Path

CANDIDATES = [r"C:\Program Files\mosquitto\mosquitto.exe",
              r"C:\Program Files (x86)\mosquitto\mosquitto.exe",
              "/usr/sbin/mosquitto", "/usr/local/sbin/mosquitto", "/opt/homebrew/sbin/mosquitto"]
RECV = re.compile(r"Received PUBLISH from (\S+) \(d(\d), q(\d), r(\d), m(\d+), '([^']*)'")


def find_mosquitto():
    exe = os.environ.get("MOSQUITTO_EXE")
    for c in ([exe] if exe else []) + [shutil.which("mosquitto")] + CANDIDATES:
        if c and Path(c).exists():
            return str(c)
    return None


def version(exe):
    try:
        out = subprocess.run([exe, "-h"], capture_output=True, text=True, timeout=5)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except Exception:
        return "mosquitto (version unknown)"


def start(port, workdir, log_path, debug=True):
    exe = find_mosquitto()
    if not exe:
        raise RuntimeError("Mosquitto not found. Install it (README section 2) or set MOSQUITTO_EXE, "
                           "or use --broker mini.")
    workdir = Path(workdir); workdir.mkdir(parents=True, exist_ok=True)
    log_path = Path(log_path).resolve()
    log_path.write_text("")
    conf = ["listener %d 127.0.0.1" % port, "allow_anonymous true", "max_queued_messages 0",
            "max_inflight_messages 0", "message_size_limit 0", "persistence false",
            "log_dest file %s" % str(log_path).replace("\\", "/"), ("log_type all" if debug else "log_type error"),
            "log_timestamp false"]
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        conf.append("user root")             # avoid privilege-drop log permission problems
    cf = workdir / f"mosquitto_{port}.conf"
    cf.write_text("\n".join(conf) + "\n")
    p = subprocess.Popen([exe, "-c", str(cf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = time.time() + 10
    while time.time() < end:
        if p.poll() is not None:
            raise RuntimeError(f"mosquitto exited early (code {p.returncode}); see {log_path}")
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close(); return p
        except OSError:
            time.sleep(0.1)
    p.kill(); raise RuntimeError("mosquitto did not open its port")


def count_publishes(log_path, client_prefix=None):
    """Number of PUBLISH packets Mosquitto logged as received (optionally per client prefix)."""
    n = 0
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = RECV.search(line)
                if m and (client_prefix is None or m.group(1).startswith(client_prefix)):
                    n += 1
    except FileNotFoundError:
        pass
    return n
