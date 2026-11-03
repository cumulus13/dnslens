# File: dnslens/tests/test_cli.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:19 SE Asia Standard Time
# Description:
# License: GPL-3.0

import json

from conftest import zone_handler

from dnslens.cli import main

ZONE = {("example.test.", "A"): ["192.0.2.1"]}


def run(capsys, *argv):
    rc = main(list(argv))
    return rc, capsys.readouterr()


def test_query_json(serve, capsys):
    s = serve(zone_handler(ZONE))
    rc, out = run(capsys, "query", "example.test", "-r", "127.0.0.1", "-p", str(s.port), "--json")
    assert rc == 0
    data = json.loads(out.out)
    assert data[0]["records"][0]["data"] == "192.0.2.1"


def test_query_short_and_nxdomain(serve, capsys):
    s = serve(zone_handler(ZONE))
    rc, out = run(capsys, "query", "example.test", "--short", "-r", "127.0.0.1", "-p", str(s.port))
    assert rc == 0 and out.out.strip() == "192.0.2.1"
    rc, _ = run(capsys, "query", "nope.test", "-r", "127.0.0.1", "-p", str(s.port))
    assert rc == 1


def test_propagate_cli(serve, capsys):
    s = serve(zone_handler(ZONE))
    base = ["-r", "a=127.0.0.1", "-r", "b=127.0.0.1", "-p", str(s.port)]
    rc, out = run(capsys, "propagate", "example.test", *base, "--expect", "192.0.2.1")
    assert rc == 0 and "expected answer" in out.out
    rc, _ = run(capsys, "propagate", "example.test", *base, "--expect", "192.0.2.7")
    assert rc == 1


def test_reverse_invalid(capsys):
    rc, out = run(capsys, "reverse", "not-an-ip")
    assert rc == 2


def test_audit_cli_json(serve, capsys):
    z = {("example.test.", "SOA"): ["ns1.example.test. a.example.test. 1 1 1 1 1"],
         ("example.test.", "NS"): ["ns1.example.test."], ("ns1.example.test.", "A"): ["127.0.0.1"]}
    s = serve(zone_handler(z))
    rc, out = run(capsys, "audit", "example.test", "-r", "127.0.0.1", "-p", str(s.port), "--json", "-t", "1", "--retries", "0")
    assert "findings" in json.loads(out.out)
