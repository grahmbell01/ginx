import os
from dataclasses import dataclass, field


@dataclass
class AgentSettings:
    control_url: str = field(default_factory=lambda: os.environ.get("CONTROL_URL", "http://127.0.0.1:8000"))
    agent_secret: str = field(default_factory=lambda: os.environ.get("AGENT_SECRET", ""))
    vps_id: str = field(default_factory=lambda: os.environ.get("AGENT_VPS_ID", ""))
    poll_interval: int = int(os.environ.get("AGENT_POLL_INTERVAL", "5"))

    evilginx_bin: str = field(default_factory=lambda: os.environ.get("EVILGINX_BIN", "/opt/evilginx/dist/evilginx"))
    phishlets_dir: str = field(default_factory=lambda: os.environ.get("PHISHLETS_DIR", "/opt/evilginx/dist/phishlets"))
    data_root: str = field(default_factory=lambda: os.environ.get("AGENT_DATA_ROOT", "/opt/evilginx/users"))
    config_root: str = field(default_factory=lambda: os.environ.get("AGENT_CONFIG_ROOT", os.environ.get("AGENT_DATA_ROOT", "/opt/evilginx/users")))
    state_file: str = field(default_factory=lambda: os.environ.get("AGENT_STATE_FILE", "/opt/evilginx/agent-state.json"))

    external_ip: str = field(default_factory=lambda: os.environ.get("EXTERNAL_IP", ""))
    nginx_conf: str = field(default_factory=lambda: os.environ.get("NGINX_CONF", "/etc/nginx/conf.d/evilginx-sni.conf"))
    nginx_http_conf: str = field(default_factory=lambda: os.environ.get("NGINX_HTTP_CONF", "/etc/nginx/conf.d/evilginx-http.conf"))
    nginx_apply: bool = os.environ.get("NGINX_APPLY", "0") == "1"
    loopback_apply: bool = os.environ.get("LOOPBACK_APPLY", "0") == "1"

    targets_path: str = field(default_factory=lambda: os.environ.get("AGENT_TARGETS", "/opt/evilginx/dist/targets"))


def load_settings() -> AgentSettings:
    return AgentSettings()