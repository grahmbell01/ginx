# Troubleshooting & Lessons Learned

Every issue hit while building the local test lab, ordered roughly by when it appeared.
Each entry: **symptom** -> **cause** -> **fix**. Use this as a checklist when re-deploying
(especially on a fresh VPS).

## 1. `go: command not found` after installing Go

- **Symptom:** `go build` fails, but Go is installed.
- **Cause:** Go is not on `$PATH` (e.g. `/usr/local/go/bin`).
- **Fix:** `export PATH=$PATH:/usr/local/go/bin` (add to `~/.bashrc` / `~/.zshrc`).

## 2. Low-port bind fails with `permission denied` (macOS)

- **Symptom:** `error: listen tcp 127.0.0.1:443: bind: permission denied`, or the server only
  listens on `::` (IPv6 wildcard).
- **Cause:** On macOS, non-root processes can only bind the IPv6 dual-stack wildcard `::` on
  ports < 1024. Binding a specific address (127.0.0.1 / 127.0.0.2 / ::1) requires root.
- **Fix:** run evilginx (and the mock on the second loopback IP) as root via `sudo`.

Related traps:

- Two processes CAN share port 443 if each binds a different specific loopback IP
  (evilginx on 127.0.0.1, mock on 127.0.0.2).
- A wildcard `::` bind CONFLICTS with specific IPv4 binds on the same port (`EADDRINUSE`).
  Don't leave stray wildcard listeners around.

## 3. `sudo` changes `$HOME` — config "disappears"

- **Symptom:** evilginx starts but doesn't load the phishlets/config you carefully set up
  (`/Users/dev/.evilginx`).
- **Cause:** `sudo` sets `$HOME=/var/root`, so evilginx reads `/var/root/.evilginx` instead.
- **Fix:** always pass the config dir explicitly:
  `sudo ./build/evilginx -p ./phishlets -c /Users/dev/.evilginx`

## 4. Evilginx MITM's itself — infinite loop / broken pages (`.localhost` trap)

- **Symptom:** requests to `https://x.mockgh.localhost` hit evilginx itself (or loop), never
  the mock; or the mock's Go server never sees the traffic.
- **Cause:** Go's resolver ignores `/etc/hosts` for `.localhost` names; macOS mDNS wildcard
  `*.localhost` resolves to `127.0.0.1`/`::1` — i.e. evilginx's own IP.
- **Fix:** never use `.localhost` phish hostnames. Use the reserved `.test` TLD and map it in
  `/etc/hosts` (Go honors `/etc/hosts` for `.test`):
  ```
  127.0.0.2 auth.test www.auth.test login.auth.test
  ```

## 5. Chrome silently rejects `Set-Cookie: Domain=localhost` — nothing captured

- **Symptom:** the lure -> login -> dashboard flow works in a real browser, but evilginx
  sessions have empty `username`/`password`/`tokens`. The sid cookie never appears in the
  browser (Chrome DevTools / cookie list).
- **Cause:** Chrome treats `localhost` specially and rejects cookies with
  `Domain=localhost` set by a subdomain host. evilginx sets the session cookie with
  `Domain=<config domain>`, so with `domain: localhost` the sid cookie is dropped -> login
  POST has no session context -> no credential extraction.
- **Fix:** the config `domain` must be a parent suffix of EVERY phish host. Here:
  `domain: auth.test` covers `www.auth.test`, `auth.test`, `login.auth.test`.

## 6. `hostname unsupported: xxx` / phish host unreachable in browser

- **Symptom:** evilginx logs `[dbg] hostname unsupported: github.auth.test`; browser gets
  `ERR_CONNECTION_REFUSED` or timeout.
- **Cause:** the phish host is derived as `phish_sub + "." + <configured hostname>`
  (`combineHost` in `core/shared.go`). With hostname `github.auth.test` and `phish_sub:
  github`, the active host becomes `github.github.auth.test` (double prefix), so
  `github.auth.test` is not in `activeHostnames`.
- **Fix:** configure the phishlet `hostname` as the BASE domain (`auth.test`), not the full
  host. Phish hosts then compose correctly: `www.auth.test`, `login.auth.test`, ...

## 7. `phishlets: hostname 'x' collision between 'a' and 'b'` warning

- **Symptom:** startup warning; SNI lookups for the phishlet misbehave.
- **Cause:** two `proxy_hosts` entries in one phishlet resolve to the SAME phish host
  (e.g. both `phish_sub: github` while hostname is `github.auth.test` -> `github.github.auth.test`
  twice). Even a single phishlet can collide with itself.
- **Fix:** give each `proxy_hosts` entry a distinct `phish_sub` (`www`, `login`, `account`,
  ...), or drop entries the origin doesn't actually redirect to. Note: the stock
  `github` template itself warns about `github.github.com` when loaded — harmless while
  disabled.

## 8. curl works but captures nothing (browser is the real test)

- **Symptom:** full chain works with `curl --resolve`, creds submitted, but sessions stay
  empty; or the sid cookie looks "born expired" in curl's jar.
- **Cause:** curl/browser cookie handling differs; also evilginx logs expiry in UTC/GMT
  (Go's `http.TimeFormat`) which can look wrong compared to local time. After a lure visit
  the client IP is whitelisted, so subsequent requests proxy fine even WITHOUT the session
  cookie — masking the real problem.
- **Fix:** verify captures with a REAL browser (headless Chrome + playwright), not curl.
  The sid cookie must be present in the browser's cookie store before the login POST.

## 9. Credentials not captured even though the dashboard loads

- **Symptom:** POST /login returns the dashboard (proxy works) but no
  `[+++] Username/Password` lines in evilginx's log.
- **Cause:** credential extraction (`core/http_proxy.go`) requires `ps.SessionId != ""`
  (the evilginx session cookie on the POST). The whitelist lets the request through anyway.
- **Fix:** ensure the browser actually has the sid cookie (issue #5), or test from a fresh
  browser profile so the IP whitelist doesn't mask missing cookies.

## 10. evilginx always talks to the origin on port 443

- **Symptom:** "connection refused" when the origin (mock) listens on another port.
- **Cause:** evilginx's HTTPS worker hardcodes CONNECT to `orig_host:443`
  (`core/http_proxy.go`, `net.JoinHostPort(hostname, "443")`).
- **Fix:** serve the origin on 443. Outbound TLS verification is skipped
  (`InsecureSkipVerify`), so self-signed certs on the mock are fine.

## 11. `data.db` is not SQLite — my queries fail

- **Symptom:** `sqlite3 data.db` fails; grep shows `*3\r\n$3\r\nset\r\n...` garbage.
- **Cause:** the session store is a Redis RESP-style JSON dump, one record per write
  (session updates append NEW records; the last record per `sessions:<id>` wins).
- **Fix:** parse RESP (see `telegram_notify.py::resp_sessions()`). Cookie tokens live under
  the **`tokens`** key in 3.3 (older docs call it `cookie_tokens`).

## 12. Hand-edited `config.json` gets reverted on restart

- **Symptom:** you edit config.json, restart evilginx, and your edits are gone.
- **Cause:** evilginx rewrites config.json from its in-memory state on graceful exit,
  clobbering manual edits made while it was running.
- **Fix:** stop with SIGKILL (`sudo pkill -9 -f 'build/evilginx'`), THEN edit, then start.
  Or make changes through the console.

## 13. Browser goes straight to the mock, bypassing evilginx

- **Symptom:** login page loads but there's no lure/session (no evilginx log lines).
- **Cause:** /etc/hosts maps `www.auth.test` -> `127.0.0.2` (the mock); the browser resolves
  it there and never touches evilginx on 127.0.0.1.
- **Fix:** launch Chrome with resolver overrides (they beat /etc/hosts):
  ```
  --host-resolver-rules="MAP www.auth.test 127.0.0.1, MAP login.auth.test 127.0.0.1, MAP auth.test 127.0.0.1"
  ```

## 14. Lure stops setting the session cookie after the first visit

- **Symptom:** first lure visit creates a session; repeat visits from the same IP don't
  (no `Set-Cookie` in the response).
- **Cause:** the client IP is whitelisted after the first lure hit, so new requests skip
  session creation.
- **Fix:** clear browser cookies / use a fresh browser profile between test runs.

## 15. Session cookie name is random per evilginx instance

- **Symptom:** the sid cookie name (e.g. `df69-035d`) changes every restart.
- **Cause:** `cookieName` is 8 random chars per process; the cookie name is
  `sha256(phishlet_name + "-" + cookie_name)` truncated to `xxxx-xxxx`.
- **Fix:** don't hardcode it in tests; read it from the lure response's `Set-Cookie`.

## 16. VPS: `autocert` fails / certificates don't appear

- **Symptom:** `phishlets enable` hangs or errors; browser shows cert errors.
- **Cause:** Let's Encrypt HTTP-01 challenge needs port 80 open AND the phish hostname to
  resolve publicly to `external_ipv4` BEFORE enabling the phishlet.
- **Fix:** `ufw allow 80/tcp`, create the DNS A records first, set
  `external_ipv4` to the public IP, then enable. Check with `test-certs` in the console.

## 17. VPS: victims' sessions show the VPS's own IP as remote_addr

- **Symptom:** all captures report the same local/private IP.
- **Cause:** testing from the VPS itself (its own IP is whitelisted and everything loops);
  or `bind_ipv4` is 127.0.0.1.
- **Fix:** test from another machine/phone on mobile data; set `bind_ipv4: 0.0.0.0`.

## 18. Random cookie / session-state confusion during debugging

- **Symptom:** captures land in different session ids, or sessions repeat.
- **Cause:** evilginx appends new RESP records on every update; also the Telegram notifier
  state file only marks sessions as done once tokens are seen.
- **Fix:** for inspections, keep the RESP parser (`telegram_notify.py --once`) as the source
  of truth; clear the notifier state file (`~/.evilginx/telegram_state.json`) when re-testing.

## 19. Microsoft capture: creds + `esctx`/`MSPOK`/`OParams` but NO `ESTSAUTH`/`ESTSAUTHPERSISTENT`

- **Symptom:** JSON export shows `"is_valid": false` on every origin; the Telegram message says
  `WARNING: creds only - no session tokens captured`; the injector contains only flow cookies
  and never logs you in.
- **Cause (most common):** the victim submitted the password on the `login.microsoftonline.com`
  page, got redirected to `login.live.com` (normal for consumer/outlook.com accounts — the
  "double password" flow), and did **not** complete the password step on `login.live.com`
  (abandoned, or typed a wrong password and gave up). The cookies that would carry the session
  (`ESTSAUTH`/`ESTSAUTHPERSISTENT`/`MSTSA`) are only set by the response of the
  `login.live.com/ppsecure/post.srf` password POST — if that request never transits the proxy,
  nothing is captured. This is **not** a phishlet bug.
- **Verify:** in the evilginx debug log, `session: N: .login.live.com: ESTSAUTH = ...` lines
  confirm the password POST went through the proxy; `[+++] Password` on the microsoftonline
  origin alone confirms only the first page's password was submitted. The VPS `data.db`
  record for the session shows which cookies arrived (`--once` printout).
- **Fix:** nothing to change in the phishlet — `.*,regexp` keys already capture everything.
  Reuse the captured creds directly, or re-lure (a victim that completes both steps yields a
  working injector). Optionally narrow `trigger_paths`/UX so the second password prompt is
  less surprising — the flow is identical to the real Microsoft behavior, so victims abort
  at the same point they would abort on the real site.
- **Tip:** `login.microsoftonline.com` consumer redirects to `login.live.com`; your phishlet
  must proxy **both** (the `sso`/`login` phish_subs in `microsoft-online.yaml` do exactly
  this). If `login.live.com` is not proxied, no `ESTSAUTH` can ever be captured.

---

## Pre-flight checklist for a fresh VPS

1. `ufw allow OpenSSH 80/tcp 443/tcp` (add `53/udp+tcp` only if using the built-in DNS).
2. DNS A records for `domain` + every phish host -> VPS public IP (or delegate NS + built-in
   DNS server).
3. Go installed; evilginx built; phishlets in place.
4. `config.json`: `domain`, `external_ipv4` (public IP!), `bind_ipv4: 0.0.0.0`,
   `autocert: true`, `https_port: 443`.
5. Start via systemd; `journalctl -u evilginx -f` to watch.
6. `phishlets enable <name>` after DNS propagates (LE cert retrieval).
7. `config autocert on` if not already; verify with `test-certs`.
8. Test the lure from an EXTERNAL device (not the VPS's own IP).
9. Confirm in evilginx log: `[+++] Username/Password`, `all authorization tokens intercepted!`.
10. Confirm Telegram notification arrives with IP / country / city / device.
11. Keep the RESP parser handy: `python3 telegram_notify.py --once`.