"""Web management UI + JSON API (AdGuard Home style). Standard library only."""
from __future__ import annotations

import json
import logging
import re
import secrets
import ssl
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from . import __version__
from .api import ROUTES, ApiConfig, ApiError, Params, Raw
from .filters import PRESET_LISTS
from .manage import Manager, ValidationError
from .querylog import WINDOWS

log = logging.getLogger("dnslens.web")

COOKIE = "dnslens_session"
MAX_BODY = 2 * 1024 * 1024
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/charts.js": ("charts.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class HttpError(Exception):
    def __init__(self, status: int, message: str, headers: Optional[Dict[str, str]] = None) -> None:
        super().__init__(message)
        self.status, self.message, self.headers = status, message, headers or {}


class Req:
    def __init__(self, web: WebServer, method: str, path: str, qs: Dict[str, List[str]], body: Dict[str, Any],
                 groups: Tuple[str, ...], client: str, user: str, token: str) -> None:
        self.web, self.mgr, self.method, self.path, self.qs, self.body = web, web.mgr, method, path, qs, body
        self.groups, self.client, self.user, self.token = groups, client, user, token

    def arg(self, key: str, default: str = "") -> str:
        v = self.qs.get(key)
        return v[0] if v else default

    def int_arg(self, key: str, default: int, lo: int, hi: int) -> int:
        try:
            n = int(self.arg(key, str(default)))
        except ValueError:
            raise HttpError(400, f"'{key}' must be an integer") from None
        return max(lo, min(hi, n))


Handler = Callable[[Req], Any]


class WebServer:
    def __init__(self, mgr: Manager, host: str = "127.0.0.1", port: int = 8080, cert: Optional[str] = None,
                 key: Optional[str] = None, session_hours: int = 24, local_dns: str = "") -> None:
        self.mgr = mgr
        self.tls = bool(cert and key)
        self.session_seconds = session_hours * 3600
        self.sessions: Dict[str, Tuple[str, float]] = {}
        self.fails: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._tools_sem = threading.BoundedSemaphore(4)
        extra = {}
        if local_dns:
            from .core import Target
            extra["this-server"] = Target("this-server", local_dns)
        self.tools_cfg = ApiConfig(default_timeout=3.0, extra=extra)
        self.assets = {p: (resources.files("dnslens").joinpath("webui", f).read_bytes(), ct)
                       for p, (f, ct) in ASSETS.items()}
        self.routes: List[Tuple[str, re.Pattern[str], Handler, bool]] = []
        self._register()
        server_cls = _Server6 if ":" in host else _Server
        self.httpd = server_cls((host, port), _make_handler(self))
        if self.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cert, key)  # type: ignore[arg-type]
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.host, self.port = host, self.httpd.server_address[1]
        self._thread: Optional[threading.Thread] = None

    # ---- sessions / throttling ----
    def new_session(self, user: str) -> str:
        tok = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self.sessions = {t: v for t, v in self.sessions.items() if v[1] > now}
            if len(self.sessions) > 200:
                self.sessions.pop(next(iter(self.sessions)))
            self.sessions[tok] = (user, now + self.session_seconds)
        return tok

    def session_user(self, tok: str) -> Optional[str]:
        if not tok:
            return None
        now = time.time()
        with self._lock:
            v = self.sessions.get(tok)
            if not v or v[1] < now:
                self.sessions.pop(tok, None)
                return None
            self.sessions[tok] = (v[0], now + self.session_seconds)  # sliding expiry
            return v[0]

    def drop_session(self, tok: str, keep: bool = False) -> None:
        with self._lock:
            if keep:
                self.sessions = {t: v for t, v in self.sessions.items() if t == tok}
            else:
                self.sessions.pop(tok, None)

    def throttled(self, ip: str) -> int:
        now = time.time()
        with self._lock:
            recent = [t for t in self.fails.get(ip, []) if now - t < 300]
            self.fails[ip] = recent
            return int(300 - (now - recent[0])) if len(recent) >= 5 else 0

    def note_fail(self, ip: str) -> None:
        with self._lock:
            self.fails.setdefault(ip, []).append(time.time())

    # ---- routes ----
    def route(self, method: str, pattern: str, fn: Handler, auth: bool = True) -> None:
        self.routes.append((method, re.compile("^" + pattern + "$"), fn, auth))

    def _register(self) -> None:
        r = self.route
        r("GET", "/api/session", self.h_session, auth=False)
        r("POST", "/api/login", self.h_login, auth=False)
        r("POST", "/api/logout", self.h_logout)
        r("GET", "/api/status", lambda q: q.mgr.status())
        r("GET", "/api/stats", self.h_stats)
        r("GET", "/api/querylog", self.h_querylog)
        r("POST", "/api/querylog/clear", self.h_log_clear)
        r("GET", "/api/clients", lambda q: q.mgr.qlog.summary(self._window(q), 100)["top_clients"])
        r("GET", "/api/settings", lambda q: q.mgr.get_settings())
        r("PUT", "/api/settings", lambda q: q.mgr.update_settings(q.body))
        r("POST", "/api/protection", self.h_protection)
        r("GET", "/api/rewrites", lambda q: q.mgr.list_rewrites())
        r("POST", "/api/rewrites", lambda q: (201, q.mgr.add_rewrite(q.body)))
        r(r"PUT", r"/api/rewrites/(\d+)", lambda q: q.mgr.update_rewrite(int(q.groups[0]), q.body))
        r("DELETE", r"/api/rewrites/(\d+)", self.h_rewrite_delete)
        r("GET", "/api/filters", self.h_filters)
        r("POST", "/api/filters", lambda q: (201, q.mgr.add_filter(str(q.body.get("name", "")), str(q.body.get("url", "")))))
        r("POST", "/api/filters/refresh", lambda q: q.mgr.refresh_filters(q.body.get("id")))
        r("PUT", r"/api/filters/(\d+)", lambda q: q.mgr.update_filter(int(q.groups[0]), q.body))
        r("DELETE", r"/api/filters/(\d+)", self.h_filter_delete)
        r("GET", "/api/rules", lambda q: {"text": q.mgr.get_rules()})
        r("PUT", "/api/rules", lambda q: {"rules": q.mgr.set_rules(str(q.body.get("text", "")))})
        r("POST", "/api/rules/action", lambda q: {"rule": q.mgr.rule_action(str(q.body.get("action", "")), str(q.body.get("domain", "")))})
        r("POST", "/api/check", lambda q: q.mgr.check_host(str(q.body.get("name", ""))))
        r("POST", "/api/upstreams/test", lambda q: q.mgr.test_upstreams())
        r("POST", "/api/cache/clear", self.h_cache_clear)
        r("PUT", "/api/account", self.h_account)
        r("GET", r"/api/tools/(\w+)", self.h_tool)

    @staticmethod
    def _window(q: Req) -> str:
        w = q.arg("window", "24h")
        if w not in WINDOWS:
            raise HttpError(400, f"window must be one of {', '.join(WINDOWS)}")
        return w

    def h_session(self, q: Req) -> Any:
        return {"authenticated": bool(q.user), "username": q.user, "version": __version__}

    def h_login(self, q: Req) -> Any:
        wait = self.throttled(q.client)
        if wait:
            raise HttpError(429, f"too many failed attempts, try again in {wait} s", {"Retry-After": str(wait)})
        user, pw = str(q.body.get("username", "")), str(q.body.get("password", ""))
        if not q.mgr.verify_login(user, pw):
            self.note_fail(q.client)
            log.warning("failed login for %r from %s", user[:40], q.client)
            raise HttpError(401, "wrong username or password")
        tok = self.new_session(user)
        q.token = tok
        return {"ok": True, "username": user}

    def h_logout(self, q: Req) -> Any:
        self.drop_session(q.token)
        q.token = ""
        return {"ok": True}

    def h_stats(self, q: Req) -> Any:
        return q.mgr.qlog.summary(self._window(q), q.int_arg("top", 10, 1, 50))

    def h_querylog(self, q: Req) -> Any:
        status = q.arg("status", "all")
        if status not in ("all", "blocked", "allowed", "local", "cached", "upstream", "failed"):
            raise HttpError(400, "invalid status filter")
        return q.mgr.qlog.search(q.int_arg("limit", 100, 1, 500), q.int_arg("before", 0, 0, 2**62),
                                 q.arg("search")[:100], status, q.arg("client")[:64])

    def h_log_clear(self, q: Req) -> Any:
        q.mgr.qlog.clear()
        return {"ok": True}

    def h_protection(self, q: Req) -> Any:
        try:
            dur = int(q.body.get("duration", 0) or 0)
        except (TypeError, ValueError):
            raise HttpError(400, "duration must be a number of seconds") from None
        return q.mgr.set_protection(bool(q.body.get("enabled", True)), dur)

    def h_rewrite_delete(self, q: Req) -> Any:
        q.mgr.delete_rewrite(int(q.groups[0]))
        return {"ok": True}

    def h_filters(self, q: Req) -> Any:
        return {"filters": q.mgr.list_filters(), "presets": PRESET_LISTS}

    def h_filter_delete(self, q: Req) -> Any:
        q.mgr.delete_filter(int(q.groups[0]))
        return {"ok": True}

    def h_cache_clear(self, q: Req) -> Any:
        q.mgr.clear_cache()
        return {"ok": True}

    def h_account(self, q: Req) -> Any:
        b = q.body
        q.mgr.change_account(str(b.get("current_password", "")), b.get("username") or None, b.get("new_password") or None)
        self.drop_session(q.token, keep=True)
        return {"ok": True, "username": q.mgr.cfg["auth"]["username"]}

    def h_tool(self, q: Req) -> Any:
        fn = ROUTES.get("/" + q.groups[0])
        if fn is None or q.groups[0] in ("healthz", "probe"):
            raise HttpError(404, "unknown tool")
        if not self._tools_sem.acquire(blocking=False):
            raise HttpError(503, "too many diagnostics running, retry shortly")
        try:
            res = fn(self.tools_cfg, Params(q.qs))
        except ApiError as e:
            raise HttpError(e.status, e.message) from None
        finally:
            self._tools_sem.release()
        return res.body if isinstance(res, Raw) else res

    # ---- lifecycle ----
    def start(self) -> WebServer:
        self._thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self.httpd.serve_forever(poll_interval=0.2)

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(1)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _Server6(_Server):
    import socket as _s

    address_family = _s.AF_INET6


def _make_handler(web: WebServer) -> Any:
    class H(BaseHTTPRequestHandler):
        server_version = "dnslens"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("%s %s", self.address_string(), fmt % args)

        # ---- helpers ----
        def _headers(self, status: int, ctype: str, length: int, extra: Optional[Dict[str, str]] = None,
                     cookie: Optional[str] = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Cache-Control", "no-store" if ctype.startswith("application/json") else "no-cache")
            if web.tls:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()

        def _cookie_value(self) -> str:
            c: SimpleCookie = SimpleCookie()
            try:
                c.load(self.headers.get("Cookie", ""))
            except Exception:
                return ""
            m = c.get(COOKIE)
            return m.value if m else ""

        def _set_cookie(self, token: str) -> str:
            attrs = f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={web.session_seconds if token else 0}"
            return attrs + ("; Secure" if web.tls else "")

        def _client(self) -> str:
            return str(self.client_address[0]).split("%", 1)[0]

        def _respond_json(self, status: int, obj: Any, extra: Optional[Dict[str, str]] = None,
                          cookie: Optional[str] = None, head: bool = False) -> None:
            body = json.dumps(obj, default=str).encode()
            self._headers(status, "application/json; charset=utf-8", len(body), extra, cookie)
            if not head:
                self.wfile.write(body)

        # ---- dispatch ----
        def _handle(self, method: str) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            head = method == "HEAD"
            if head:
                method = "GET"
            try:
                if not path.startswith("/api/"):
                    if method != "GET":
                        raise HttpError(405, "method not allowed", {"Allow": "GET, HEAD"})
                    asset = web.assets.get(path)
                    if asset is None:
                        asset = web.assets["/"] if path.count(".") == 0 and path not in ("/api",) else None
                    if asset is None:
                        raise HttpError(404, "not found")
                    self._headers(200, asset[1], len(asset[0]))
                    if not head:
                        self.wfile.write(asset[0])
                    return
                self._api(method, path, parsed.query, head)
            except HttpError as e:
                self._respond_json(e.status, {"error": e.message}, e.headers, head=head)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                log.exception("unhandled error on %s", path)
                self._respond_json(500, {"error": "internal error"}, head=head)

        def _api(self, method: str, path: str, query: str, head: bool) -> None:
            matched = None
            allowed = set()
            for m, pat, fn, auth in web.routes:
                g = pat.match(path)
                if g:
                    allowed.add(m)
                    if m == method:
                        matched = (fn, auth, g.groups())
            if matched is None:
                if allowed:
                    raise HttpError(405, "method not allowed", {"Allow": ", ".join(sorted(allowed))})
                raise HttpError(404, "not found")
            fn, needs_auth, groups = matched
            token = self._cookie_value()
            user = web.session_user(token)
            if needs_auth and not user:
                raise HttpError(401, "authentication required")
            body: Dict[str, Any] = {}
            if method != "GET":
                if self.headers.get("X-Requested-With") != "dnslens":
                    raise HttpError(403, "missing X-Requested-With header")
                origin = self.headers.get("Origin")
                if origin and urlparse(origin).netloc != self.headers.get("Host", ""):
                    raise HttpError(403, "cross-origin request refused")
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY:
                    raise HttpError(413, "request body too large")
                if length:
                    raw = self.rfile.read(length)
                    try:
                        body = json.loads(raw)
                    except ValueError:
                        raise HttpError(400, "body must be valid JSON") from None
                    if not isinstance(body, dict):
                        raise HttpError(400, "body must be a JSON object")
            req = Req(web, method, path, parse_qs(query, keep_blank_values=True), body, groups, self._client(),
                      user or "", token)
            try:
                result = fn(req)
            except ValidationError as e:
                raise HttpError(400, str(e)) from None
            except KeyError:
                raise HttpError(404, "no such item") from None
            status = 200
            if isinstance(result, tuple):
                status, result = result
            cookie = None
            if req.token != token:
                cookie = self._set_cookie(req.token)
            self._respond_json(status, result, cookie=cookie, head=head)

        def do_GET(self) -> None:
            self._handle("GET")

        def do_HEAD(self) -> None:
            self._handle("HEAD")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_PUT(self) -> None:
            self._handle("PUT")

        def do_DELETE(self) -> None:
            self._handle("DELETE")

    return H
