"""Runtime-managed configuration for the web UI: persisted settings, filters, rewrites, rules."""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

import dns.name

from . import __version__
from .core import QueryOpts, query
from .filters import FilterList, FilterStore, rules_from_text, validate_url
from .querylog import RETENTION_HOURS, QueryLog
from .server import ConfigError, DNSHandler, ZoneData, norm_domain

log = logging.getLogger("dnslens.manage")

PBKDF2_ITERATIONS = 240_000
_UPSTREAM_RE = re.compile(r"^[A-Za-z0-9_.:\-\[\]]+(#\d{1,5})?$")
REWRITE_TYPES = ("A", "AAAA", "CNAME", "TXT", "MX", "PTR", "NS", "SRV", "CAA")


class ValidationError(ValueError):
    pass


def hash_password(password: str, salt: Optional[bytes] = None, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), digest)
    except (ValueError, TypeError):
        return False


def default_config(seed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {
        "version": 1,
        "protection": {"enabled": True, "until": 0},
        "dns": {"upstreams": ["1.1.1.1", "9.9.9.9"], "upstream_timeout": 2.0, "forward": True,
                "cache_size": 10000, "max_ttl": 86400, "block_mode": "nxdomain"},
        "log": {"enabled": True, "retention_hours": 168, "anonymize": False},
        "filters_update_hours": 24,
        "filters": [], "rewrites": [], "custom_rules": "",
        "auth": {"username": "admin", "password_hash": ""},
        "next_id": 1,
    }
    for k, v in (seed or {}).items():
        if k in cfg["dns"]:
            cfg["dns"][k] = v
    return cfg


def default_data_dir() -> str:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "dnslens")
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "dnslens")


class Manager:
    def __init__(self, data_dir: str, handler: DNSHandler, static_zone: ZoneData,
                 seed: Optional[Dict[str, Any]] = None, dns_addr: str = "") -> None:
        self.data_dir = data_dir
        fresh = not os.path.isdir(data_dir)
        os.makedirs(data_dir, exist_ok=True)
        if fresh:
            try:
                os.chmod(data_dir, 0o700)  # holds client IPs, queried names and the password hash
            except OSError:
                pass
        self.path = os.path.join(data_dir, "config.json")
        self.handler = handler
        self.static = static_zone
        self.dns_addr = dns_addr
        self.lock = threading.RLock()
        self.store = FilterStore(os.path.join(data_dir, "filters"))
        self.cfg = self._load(seed)
        lg = self.cfg["log"]
        self.qlog = QueryLog(os.path.join(data_dir, "queries.db"), lg["retention_hours"], lg["enabled"], lg["anonymize"])
        self.handler.observers.append(self.qlog.record)
        self._stop = threading.Event()
        self._updater = threading.Thread(target=self._update_loop, name="dnslens-filter-updater", daemon=True)
        self.initial_password: Optional[str] = None

    # ---- persistence ----
    def _load(self, seed: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        base = default_config(seed)
        try:
            with open(self.path, encoding="utf-8") as fh:
                saved = json.load(fh)
            for k, v in saved.items():
                if isinstance(v, dict) and isinstance(base.get(k), dict):
                    base[k].update(v)
                else:
                    base[k] = v
        except FileNotFoundError:
            pass
        except (OSError, json.JSONDecodeError) as e:
            raise ConfigError(f"cannot read {self.path}: {e}") from e
        return base

    def save(self) -> None:
        with self.lock:
            fd, tmp = tempfile.mkstemp(dir=self.data_dir, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.cfg, fh, indent=2)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self.path)

    # ---- lifecycle ----
    def start(self, password: Optional[str] = None, username: Optional[str] = None) -> Manager:
        with self.lock:
            auth = self.cfg["auth"]
            if username:
                auth["username"] = username
            if password:
                auth["password_hash"] = hash_password(password)
            elif not auth["password_hash"]:
                self.initial_password = secrets.token_urlsafe(9)
                auth["password_hash"] = hash_password(self.initial_password)
            p = self.cfg["protection"]
            self.handler.protection = bool(p["enabled"])
            self.handler.protection_until = float(p["until"] or 0)
            self.save()
        self.qlog.start()
        self.rebuild()
        self._updater.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self.qlog.stop()

    def set_static(self, zone: ZoneData) -> None:
        with self.lock:
            self.static = zone
            self.rebuild()

    # ---- composing the live zone ----
    def rebuild(self) -> None:
        with self.lock:
            z = self.static.copy()
            cfg = self.cfg
            z.block_mode = cfg["dns"]["block_mode"]
            for rw in cfg["rewrites"]:
                if rw.get("enabled", True):
                    try:
                        z.add(rw["name"], rw["type"], rw["data"], int(rw.get("ttl", 300)))
                    except ConfigError as e:
                        log.warning("skipping rewrite %s: %s", rw.get("name"), e)
            for f in cfg["filters"]:
                if not f["enabled"]:
                    continue
                parsed = self.store.get(f["id"])
                if parsed is None:
                    continue
                for d in parsed.blocks:
                    z.block.setdefault(d, f["id"])
                for d in parsed.allows:
                    z.allow.setdefault(d, f["id"])
            blocks, allows = rules_from_text(cfg["custom_rules"])
            for d in blocks:
                z.block[d] = -1
                if z.allow.get(d, -1) != -1:
                    del z.allow[d]  # a custom block beats a list's allow rule for the same domain
            for d in allows:
                z.allow[d] = -1
            self.handler.set_zone(z)
            self._apply_dns()

    def _apply_dns(self) -> None:
        d, lg = self.cfg["dns"], self.cfg["log"]
        o = self.handler.opts
        o.upstreams, o.upstream_timeout, o.forward, o.max_ttl = list(d["upstreams"]), float(d["upstream_timeout"]), bool(d["forward"]), int(d["max_ttl"])
        self.handler.cache.size = int(d["cache_size"])
        self.qlog.enabled, self.qlog.retention_hours, self.qlog.anonymize_clients = bool(lg["enabled"]), int(lg["retention_hours"]), bool(lg["anonymize"])

    # ---- status ----
    def status(self) -> Dict[str, Any]:
        h = self.handler
        active = h.protection_active()
        c = self.cfg
        return {
            "version": __version__, "uptime": time.time() - h.started, "dns": self.dns_addr,
            "protection": {"enabled": active, "until": h.protection_until if not active else 0},
            "zone": h.zone.counts(), "cache_entries": len(h.cache), "counters": h.stats.snapshot(),
            "filters": {"total": len(c["filters"]), "enabled": sum(1 for f in c["filters"] if f["enabled"])},
            "rewrites": len(c["rewrites"]), "forward": c["dns"]["forward"], "log_enabled": c["log"]["enabled"],
            "username": c["auth"]["username"],
        }

    # ---- protection ----
    def set_protection(self, enabled: bool, duration: int = 0) -> Dict[str, Any]:
        if duration < 0 or duration > 30 * 86400:
            raise ValidationError("duration out of range")
        with self.lock:
            h = self.handler
            h.protection = enabled
            h.protection_until = (time.time() + duration) if (not enabled and duration) else 0.0
            self.cfg["protection"] = {"enabled": enabled, "until": h.protection_until}
            self.save()
        return self.status()["protection"]

    # ---- settings ----
    def get_settings(self) -> Dict[str, Any]:
        c = self.cfg
        return {"dns": dict(c["dns"]), "log": dict(c["log"]), "filters_update_hours": c["filters_update_hours"],
                "retention_options": list(RETENTION_HOURS)}

    def update_settings(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            new = copy.deepcopy(self.cfg)
            d = data.get("dns", {})
            if "upstreams" in d:
                ups = d["upstreams"]
                if not isinstance(ups, list) or not 1 <= len(ups) <= 10:
                    raise ValidationError("provide 1 to 10 upstream servers")
                clean = []
                for u in ups:
                    u = str(u).strip()
                    if not _UPSTREAM_RE.match(u) or ("#" in u and int(u.rsplit("#", 1)[1]) > 65535):
                        raise ValidationError(f"invalid upstream {u!r} (use IP, IP#PORT or hostname)")
                    clean.append(u)
                new["dns"]["upstreams"] = clean
            if "upstream_timeout" in d:
                v = float(d["upstream_timeout"])
                if not 0.5 <= v <= 10:
                    raise ValidationError("upstream timeout must be 0.5 to 10 seconds")
                new["dns"]["upstream_timeout"] = v
            if "cache_size" in d:
                v = int(d["cache_size"])
                if not 0 <= v <= 1_000_000:
                    raise ValidationError("cache size must be 0 to 1000000")
                new["dns"]["cache_size"] = v
            if "max_ttl" in d:
                v = int(d["max_ttl"])
                if not 60 <= v <= 604800:
                    raise ValidationError("max TTL must be 60 to 604800 seconds")
                new["dns"]["max_ttl"] = v
            if "block_mode" in d:
                if d["block_mode"] not in ("nxdomain", "null"):
                    raise ValidationError("block mode must be nxdomain or null")
                new["dns"]["block_mode"] = d["block_mode"]
            if "forward" in d:
                new["dns"]["forward"] = bool(d["forward"])
            lg = data.get("log", {})
            if "enabled" in lg:
                new["log"]["enabled"] = bool(lg["enabled"])
            if "anonymize" in lg:
                new["log"]["anonymize"] = bool(lg["anonymize"])
            if "retention_hours" in lg:
                v = int(lg["retention_hours"])
                if v not in RETENTION_HOURS:
                    raise ValidationError(f"retention must be one of {list(RETENTION_HOURS)} hours")
                new["log"]["retention_hours"] = v
            if "filters_update_hours" in data:
                v = int(data["filters_update_hours"])
                if v not in (0, 1, 12, 24, 72, 168):
                    raise ValidationError("filter update interval must be 0, 1, 12, 24, 72 or 168 hours")
                new["filters_update_hours"] = v
            self.cfg = new
            self.save()
            self.rebuild()
        return self.get_settings()

    # ---- rewrites ----
    def _next_id(self) -> int:
        n = int(self.cfg["next_id"])
        self.cfg["next_id"] = n + 1
        return n

    def _clean_rewrite(self, data: Dict[str, Any]) -> Dict[str, Any]:
        name = str(data.get("name", "")).strip().lower()
        value = str(data.get("data", "")).strip()
        rtype = str(data.get("type", "")).upper() or "A"
        if not name or not value:
            raise ValidationError("domain and answer are required")
        if rtype == "AUTO":
            rtype = "A" if re.match(r"^\d+\.\d+\.\d+\.\d+$", value) else "AAAA" if ":" in value else "CNAME"
        if rtype not in REWRITE_TYPES:
            raise ValidationError(f"type must be one of {', '.join(REWRITE_TYPES)}")
        try:
            ttl = int(data.get("ttl", 300))
        except (TypeError, ValueError):
            raise ValidationError("TTL must be a number") from None
        if not 0 <= ttl <= 86400 * 7:
            raise ValidationError("TTL out of range")
        try:
            ZoneData().add(name, rtype, value, ttl)
        except ConfigError as e:
            raise ValidationError(str(e)) from e
        return {"name": name, "type": rtype, "data": value, "ttl": ttl, "enabled": bool(data.get("enabled", True))}

    def list_rewrites(self) -> List[Dict[str, Any]]:
        return list(self.cfg["rewrites"])

    def add_rewrite(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            rw = self._clean_rewrite(data)
            rw["id"] = self._next_id()
            self.cfg["rewrites"].append(rw)
            self.save()
            self.rebuild()
            return rw

    def update_rewrite(self, rid: int, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            for i, old in enumerate(self.cfg["rewrites"]):
                if old["id"] == rid:
                    merged = {**old, **data}
                    rw = self._clean_rewrite(merged)
                    rw["id"] = rid
                    self.cfg["rewrites"][i] = rw
                    self.save()
                    self.rebuild()
                    return rw
        raise KeyError(rid)

    def delete_rewrite(self, rid: int) -> None:
        with self.lock:
            n = len(self.cfg["rewrites"])
            self.cfg["rewrites"] = [r for r in self.cfg["rewrites"] if r["id"] != rid]
            if len(self.cfg["rewrites"]) == n:
                raise KeyError(rid)
            self.save()
            self.rebuild()

    # ---- filter lists ----
    def list_filters(self) -> List[Dict[str, Any]]:
        return [dict(f) for f in self.cfg["filters"]]

    def add_filter(self, name: str, url: str, fetch: bool = True) -> Dict[str, Any]:
        try:
            url = validate_url(url)
        except ValueError as e:
            raise ValidationError(str(e)) from e
        name = name.strip() or url
        with self.lock:
            if any(f["url"] == url for f in self.cfg["filters"]):
                raise ValidationError("this list is already added")
            flt = FilterList(id=self._next_id(), name=name[:80], url=url)
        if fetch:
            try:
                self.store.fetch(flt)
            except Exception as e:
                raise ValidationError(f"could not download the list: {e}") from e
        with self.lock:
            self.cfg["filters"].append(flt.to_dict())
            self.save()
            self.rebuild()
        return flt.to_dict()

    def update_filter(self, fid: int, data: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            for f in self.cfg["filters"]:
                if f["id"] == fid:
                    if "enabled" in data:
                        f["enabled"] = bool(data["enabled"])
                    if "name" in data and str(data["name"]).strip():
                        f["name"] = str(data["name"]).strip()[:80]
                    self.save()
                    self.rebuild()
                    return dict(f)
        raise KeyError(fid)

    def delete_filter(self, fid: int) -> None:
        with self.lock:
            n = len(self.cfg["filters"])
            self.cfg["filters"] = [f for f in self.cfg["filters"] if f["id"] != fid]
            if len(self.cfg["filters"]) == n:
                raise KeyError(fid)
            self.store.remove(fid)
            self.save()
            self.rebuild()

    def refresh_filters(self, fid: Optional[int] = None) -> List[Dict[str, Any]]:
        with self.lock:
            targets = [f for f in self.cfg["filters"] if fid is None or f["id"] == fid]
        if fid is not None and not targets:
            raise KeyError(fid)
        results = []
        for f in targets:
            flt = FilterList(**f)
            try:
                self.store.fetch(flt)
            except Exception as e:
                flt.error = str(e)[:200]
            with self.lock:
                f.update(last_updated=flt.last_updated, rules=flt.rules, error=flt.error)
            results.append(dict(f))
        with self.lock:
            self.save()
            self.rebuild()
        return results

    def _update_loop(self) -> None:
        while not self._stop.wait(900):
            hours = int(self.cfg["filters_update_hours"])
            if not hours:
                continue
            due = [f["id"] for f in self.cfg["filters"]
                   if f["enabled"] and time.time() - f["last_updated"] > hours * 3600]
            for fid in due:
                try:
                    self.refresh_filters(fid)
                except KeyError:
                    pass

    # ---- custom rules ----
    def get_rules(self) -> str:
        return str(self.cfg["custom_rules"])

    def set_rules(self, text: str) -> int:
        if len(text) > 1_000_000:
            raise ValidationError("rules are too large")
        with self.lock:
            self.cfg["custom_rules"] = text
            self.save()
            self.rebuild()
        b, a = rules_from_text(text)
        return len(b) + len(a)

    def rule_action(self, action: str, domain: str) -> str:
        d = norm_domain(domain)
        if d is None:
            raise ValidationError("invalid domain")
        if action not in ("block", "allow"):
            raise ValidationError("action must be block or allow")
        block_line, allow_line = f"||{d}^", f"@@||{d}^"
        drop, add = (allow_line, block_line) if action == "block" else (block_line, allow_line)
        with self.lock:
            lines = [ln for ln in self.cfg["custom_rules"].splitlines() if ln.strip() != drop]
            if add not in [ln.strip() for ln in lines]:
                lines.append(add)
            self.cfg["custom_rules"] = "\n".join(lines) + "\n"
            self.save()
            self.rebuild()
        return add

    # ---- diagnostics ----
    def check_host(self, name: str) -> Dict[str, Any]:
        d = norm_domain(name)
        if d is None:
            raise ValidationError("invalid domain")
        z = self.handler.zone
        dn = dns.name.from_text(d)
        verdict = z.match(dn)
        lists = {f["id"]: f["name"] for f in self.cfg["filters"]}

        def src(i: int) -> str:
            return "custom rules" if i == -1 else "static configuration" if i == 0 else lists.get(i, f"list {i}")

        out: Dict[str, Any] = {"name": d, "protection": self.handler.protection_active(), "result": "processed",
                               "rule": "", "list": ""}
        if z.find(dn) is not None:
            out["result"] = "rewritten"
        elif verdict and verdict[0] == "block":
            out.update(result="blocked", rule=verdict[1], list=src(verdict[2]))
        elif verdict:
            out.update(result="allowed", rule=verdict[1], list=src(verdict[2]))
        return out

    def test_upstreams(self) -> List[Dict[str, Any]]:
        ups = list(self.cfg["dns"]["upstreams"])

        def one(u: str) -> Dict[str, Any]:
            a = query("example.com", "A", u, QueryOpts(timeout=2.0, retries=0))
            return {"upstream": u, "ok": a.responded, "ms": round(a.elapsed_ms, 1), "error": a.error or ("" if a.responded else a.rcode)}

        with ThreadPoolExecutor(max_workers=min(8, len(ups))) as ex:
            return list(ex.map(one, ups))

    def clear_cache(self) -> None:
        self.handler.cache.clear()

    # ---- account ----
    def verify_login(self, username: str, password: str) -> bool:
        auth = self.cfg["auth"]
        user_ok = hmac.compare_digest(username.encode(), auth["username"].encode())
        pw_ok = verify_password(password, auth["password_hash"])  # always evaluated: constant work
        return user_ok and pw_ok

    def change_account(self, current: str, username: Optional[str], new_password: Optional[str]) -> None:
        with self.lock:
            if not verify_password(current, self.cfg["auth"]["password_hash"]):
                raise ValidationError("current password is incorrect")
            if username:
                username = username.strip()
                if not re.match(r"^[\w.@-]{1,64}$", username):
                    raise ValidationError("username may contain letters, digits and . _ @ - (max 64)")
                self.cfg["auth"]["username"] = username
            if new_password:
                if len(new_password) < 8:
                    raise ValidationError("password must be at least 8 characters")
                self.cfg["auth"]["password_hash"] = hash_password(new_password)
            self.save()
