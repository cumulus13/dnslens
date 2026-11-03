# File: ui/stack.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:19 SE Asia Standard Time
# Description:
# License: GPL-3.0

"""Starts a complete dnslens stack (fake upstream, DNS server, web UI) with sample traffic for UI tests."""
import os
import random
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import dns.message  # noqa: E402
import dns.query  # noqa: E402
from conftest import FakeDNS, zone_handler  # noqa: E402
from helpers import LIST, ListServer  # noqa: E402

from dnslens.manage import Manager  # noqa: E402
from dnslens.server import DNSHandler, DNSServer, ServerOptions, ZoneData  # noqa: E402
from dnslens.web import WebServer  # noqa: E402

PORT = int(os.environ.get("UI_PORT", "18080"))
PASSWORD = os.environ.get("UI_PASSWORD", "uitest-pass1")

names = ["example.test", "github.test", "cdn.test", "mail.test", "api.test"]
zone = {(n + ".", "A"): ["192.0.2." + str(i + 1)] for i, n in enumerate(names)}
zone[("ads.bad.test.", "A")] = ["203.0.113.66"]
zone[("tracker.bad.test.", "A")] = ["203.0.113.69"]
up = FakeDNS(zone_handler(zone, ttl=120, aa=False))
lists = ListServer(LIST)
handler = DNSHandler(ZoneData(), ServerOptions(upstream_timeout=1.0))
mgr = Manager(tempfile.mkdtemp(prefix="dnslens-ui-"), handler, ZoneData(), {"upstreams": [f"127.0.0.1#{up.port}"]},
              dns_addr="127.0.0.1:5353")
mgr.start(password=PASSWORD)
dns_srv = DNSServer(handler, "127.0.0.1", 0).start()
web = WebServer(mgr, "127.0.0.1", PORT, local_dns=f"127.0.0.1#{dns_srv.port}").start()
mgr.add_filter("Test list", lists.url)
mgr.add_rewrite({"name": "nas.home", "data": "10.0.0.7", "type": "AUTO"})
random.seed(1)
pool = names + ["ads.bad.test", "ads.bad.test", "tracker.bad.test", "nas.home", "nope.test"]
for _ in range(300):
    try:
        dns.query.udp(dns.message.make_query(random.choice(pool), random.choice(["A", "A", "A", "AAAA"])),
                      "127.0.0.1", timeout=2, port=dns_srv.port)
    except Exception:
        pass
try:  # a hostile name: the UI must show it as text, never as markup
    dns.query.udp(dns.message.make_query("<img/src=x/onerror=alert(1)>.xss.test", "A"), "127.0.0.1", timeout=2, port=dns_srv.port)
except Exception:
    pass
mgr.qlog.flush()


def traffic():  # steady background load so the live views always have something to show
    rnd = random.Random(2)
    while True:
        try:
            dns.query.udp(dns.message.make_query(rnd.choice(pool), "A"), "127.0.0.1", timeout=1, port=dns_srv.port)
        except Exception:
            pass
        time.sleep(0.05)


threading.Thread(target=traffic, daemon=True).start()
print("READY", flush=True)
while True:
    time.sleep(1)
