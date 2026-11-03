# File: dnslens/tests/conftest.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:18 SE Asia Standard Time
# Description:
# License: GPL-3.0

import socket
import threading
from typing import Callable, Dict, List, Optional, Tuple

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest
from helpers import LIST, PW, Client, ListServer

Handler = Callable[[dns.message.Message], Optional[dns.message.Message]]


class FakeDNS:
    """Tiny UDP DNS server on 127.0.0.1 driven by a handler callback."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except ConnectionResetError:  # Windows: ICMP unreachable from an earlier reply
                continue
            except OSError:
                return
            try:
                q = dns.message.from_wire(data)
                r = self.handler(q)
            except Exception:
                continue
            if r is not None:
                self.sock.sendto(r.to_wire(), addr)

    def close(self) -> None:
        self._stop.set()
        self.thread.join(1)
        self.sock.close()


def zone_handler(zone: Dict[Tuple[str, str], List[str]], ttl: int = 300, aa: bool = True) -> Handler:
    """zone maps (name, type) -> list of rdata text. Unknown names -> NXDOMAIN."""
    names = {n.lower() for n, _ in zone}

    def handle(q: dns.message.Message) -> dns.message.Message:
        r = dns.message.make_response(q)
        if aa:
            r.flags |= dns.flags.AA
        qn = q.question[0].name.to_text().lower()
        qt = dns.rdatatype.to_text(q.question[0].rdtype)
        data = zone.get((qn, qt))
        if data:
            r.answer.append(dns.rrset.from_text(qn, ttl, "IN", qt, *data))
        elif qn not in names:
            r.set_rcode(dns.rcode.NXDOMAIN)
        return r

    return handle


@pytest.fixture
def serve():
    servers: List[FakeDNS] = []

    def start(handler: Handler) -> FakeDNS:
        s = FakeDNS(handler)
        servers.append(s)
        return s

    yield start
    for s in servers:
        s.close()


@pytest.fixture
def stack(tmp_path, serve):
    up = serve(zone_handler({("example.test.", "A"): ["192.0.2.1"], ("ads.bad.test.", "A"): ["203.0.113.66"],
                             ("ok.bad.test.", "A"): ["203.0.113.67"], ("plain.bad.test.", "A"): ["203.0.113.68"],
                             ("tracker.bad.test.", "A"): ["203.0.113.69"]}, aa=False))
    from dnslens.manage import Manager
    from dnslens.server import DNSHandler, DNSServer, ServerOptions, ZoneData
    from dnslens.web import WebServer

    handler = DNSHandler(ZoneData(), ServerOptions(upstream_timeout=1.0))
    mgr = Manager(str(tmp_path / "data"), handler, ZoneData(), {"upstreams": [f"127.0.0.1#{up.port}"]}, dns_addr="127.0.0.1:0")
    mgr.start(password=PW)
    dnssrv = DNSServer(handler, "127.0.0.1", 0).start()
    web = WebServer(mgr, "127.0.0.1", 0, local_dns=f"127.0.0.1#{dnssrv.port}").start()
    lists = ListServer(LIST)

    class S:
        pass

    s = S()
    s.mgr, s.handler, s.dns, s.web, s.lists, s.up = mgr, handler, dnssrv, web, lists, up
    s.client = Client(f"http://127.0.0.1:{web.port}")
    s.client.login()

    def ask(name, rtype="A"):
        r = dns.query.udp(dns.message.make_query(name, rtype), "127.0.0.1", timeout=3, port=dnssrv.port)
        return r

    s.ask = ask
    yield s
    web.stop()
    dnssrv.stop()
    mgr.stop()
    lists.close()
