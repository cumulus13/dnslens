# File: dnslens/tests/helpers.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:18 SE Asia Standard Time
# Description:
# License: GPL-3.0

"""Shared test helpers (HTTP client with cookies, tiny blocklist server)."""
import http.cookiejar
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

PW = "correct-horse-1"
LIST = "# test list\n0.0.0.0 ads.bad.test\n||tracker.bad.test^\n@@||ok.bad.test^\nplain.bad.test\n/regex/\n"


class Client:
    def __init__(self, base, ctx=None):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if ctx:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.op = urllib.request.build_opener(*handlers)

    def call(self, method, path, body=None, headers=None, csrf=True):
        h = dict(headers or {})
        if csrf and method != "GET":
            h["X-Requested-With"] = "dnslens"
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=h, method=method)
        try:
            with self.op.open(req, timeout=10) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw and "json" in r.headers.get("Content-Type", "") else raw), r.headers
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw), e.headers
            except ValueError:
                return e.code, raw, e.headers

    def login(self, pw=PW, user="admin"):
        return self.call("POST", "/api/login", {"username": user, "password": pw})


class ListServer:
    def __init__(self, text):
        outer = self
        outer.text = text

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = outer.text.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/list.txt"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
