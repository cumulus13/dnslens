"""Filter rules: parsing (AdGuard / hosts / plain domains) and list subscriptions."""
from __future__ import annotations

import ipaddress
import os
import re
import tempfile
import threading
import time
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from . import __version__
from .server import norm_domain

MAX_LIST_BYTES = 64 * 1024 * 1024
_ABP_RE = re.compile(r"^(@@)?\|\|([^/^$*|]+)\^?(\$[\w,=|~-]+)?$")


@dataclass
class ParsedRules:
    blocks: Set[str]
    allows: Set[str]
    skipped: int = 0


def parse_rules(text: str) -> ParsedRules:
    """Understands: ``||domain^`` and ``@@||domain^`` (AdGuard/ABP, ``$important`` allowed),
    hosts lines (``0.0.0.0 domain``) and bare domains. Everything else is counted as skipped."""
    blocks: Set[str] = set()
    allows: Set[str] = set()
    skipped = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "!#[":
            continue
        tokens = line.split()
        first = tokens[0]
        try:
            ipaddress.ip_address(first)
            for t in tokens[1:]:
                if t.startswith("#"):
                    break
                d = norm_domain(t)
                if d and t.lower() not in ("localhost", "localhost.localdomain", "broadcasthost", "local"):
                    blocks.add(d)
            continue
        except ValueError:
            pass
        if len(tokens) != 1:
            skipped += 1
            continue
        m = _ABP_RE.match(first)
        if m:
            mods = m.group(3) or ""
            if mods and mods not in ("$important",):
                skipped += 1
                continue
            d = norm_domain(m.group(2))
            if d is None:
                skipped += 1
            else:
                (allows if m.group(1) else blocks).add(d)
            continue
        if first.startswith(("|", "/", "@@", "*")) or "$" in first or "#" in first or "/" in first:
            skipped += 1
            continue
        d = norm_domain(first)
        if d is None:
            skipped += 1
        else:
            blocks.add(d)
    return ParsedRules(blocks, allows, skipped)


@dataclass
class FilterList:
    id: int
    name: str
    url: str
    enabled: bool = True
    last_updated: float = 0.0
    rules: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


PRESET_LISTS = [
    {"name": "AdGuard DNS filter", "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
    {"name": "StevenBlack unified hosts", "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
    {"name": "Peter Lowe's ad servers",
     "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"},
]


def validate_url(url: str) -> str:
    u = urlparse(url.strip())
    if u.scheme not in ("http", "https") or not u.netloc:
        raise ValueError("URL must start with http:// or https://")
    return url.strip()


class FilterStore:
    """Downloads filter lists into ``<data>/filters`` and keeps the parsed rules in memory."""

    def __init__(self, directory: str) -> None:
        self.dir = directory
        os.makedirs(directory, exist_ok=True)
        self._parsed: Dict[int, ParsedRules] = {}
        self._lock = threading.Lock()

    def _path(self, fid: int) -> str:
        return os.path.join(self.dir, f"{fid}.txt")

    def fetch(self, flt: FilterList, timeout: float = 30.0) -> int:
        """Download and store a list; returns the rule count. Raises on failure."""
        req = urllib.request.Request(validate_url(flt.url), headers={"User-Agent": f"dnslens/{__version__}"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme validated)
            data = resp.read(MAX_LIST_BYTES + 1)
        if len(data) > MAX_LIST_BYTES:
            raise ValueError("list is larger than 64 MB")
        text = data.decode("utf-8", errors="replace")
        parsed = parse_rules(text)
        if not parsed.blocks and not parsed.allows:
            raise ValueError("no usable rules found in the downloaded list")
        fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, self._path(flt.id))
        with self._lock:
            self._parsed[flt.id] = parsed
        flt.last_updated = time.time()
        flt.rules = len(parsed.blocks) + len(parsed.allows)
        flt.error = ""
        return flt.rules

    def load_text(self, fid: int, text: str) -> ParsedRules:
        """Store list contents directly (used by tests and file-based lists)."""
        parsed = parse_rules(text)
        with open(self._path(fid), "w", encoding="utf-8") as fh:
            fh.write(text)
        with self._lock:
            self._parsed[fid] = parsed
        return parsed

    def get(self, fid: int) -> Optional[ParsedRules]:
        with self._lock:
            p = self._parsed.get(fid)
        if p is not None:
            return p
        try:
            with open(self._path(fid), encoding="utf-8", errors="replace") as fh:
                p = parse_rules(fh.read())
        except OSError:
            return None
        with self._lock:
            self._parsed[fid] = p
        return p

    def remove(self, fid: int) -> None:
        with self._lock:
            self._parsed.pop(fid, None)
        try:
            os.remove(self._path(fid))
        except OSError:
            pass


def rules_from_text(text: str) -> Tuple[Set[str], Set[str]]:
    p = parse_rules(text)
    return p.blocks, p.allows


def list_lines(text: str) -> List[str]:
    return [ln for ln in text.splitlines()]
