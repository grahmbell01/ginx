"""HTTP client for the control-plane agent API."""
import httpx

from agent.config import AgentSettings


class ControlError(RuntimeError):
    pass


class ControlClient:
    def __init__(self, settings: AgentSettings):
        self.base_url = settings.control_url.rstrip("/")
        self.headers = {
            "X-Agent-Secret": settings.agent_secret,
            "X-Agent-Vps": settings.vps_id,
        }
        self._client = httpx.Client(base_url=self.base_url, headers=self.headers, timeout=20.0)

    def _ensure(self, resp: httpx.Response) -> dict:
        if resp.status_code >= 400:
            raise ControlError(f"{resp.status_code}: {resp.text[:200]}")
        return resp.json()

    def heartbeat(self, hostname: str = "", load: float | None = None,
                  mem_used_pct: float | None = None, disk_used_pct: float | None = None,
                  active_instances: int | None = None) -> dict:
        return self._ensure(self._client.post("/agent/heartbeat", json={
            "hostname": hostname,
            "load": load,
            "mem_used_pct": mem_used_pct,
            "disk_used_pct": disk_used_pct,
            "active_instances": active_instances,
        }))

    def fetch_jobs(self) -> list[dict]:
        return self._ensure(self._client.get("/agent/jobs"))

    def report_job(self, job_id: str, ok: bool, result: dict | None = None, error: str | None = None) -> dict:
        return self._ensure(self._client.post(f"/agent/jobs/{job_id}/result", json={
            "ok": ok,
            "result": result,
            "error": error,
        }))