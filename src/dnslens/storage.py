# File: dnslens/src/dnslens/storage.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:18 SE Asia Standard Time
# Description:
# License: GPL-3.0

"""Where dnslens keeps its managed state: files in a data directory (default) or a SQL database."""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, Optional, Tuple

from .server import ConfigError


class FileStore:
    """``config.json`` + ``filters/N.txt`` inside the data directory (no extra dependencies)."""

    kind = "files"

    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        fresh = not os.path.isdir(data_dir)
        os.makedirs(data_dir, exist_ok=True)
        if fresh:
            try:
                os.chmod(data_dir, 0o700)  # holds client IPs, queried names and the password hash
            except OSError:
                pass
        self.path = os.path.join(data_dir, "config.json")
        self.lists_dir = os.path.join(data_dir, "filters")
        os.makedirs(self.lists_dir, exist_ok=True)

    def describe(self) -> str:
        return f"files in {self.data_dir}"

    def load(self) -> Optional[Dict[str, Any]]:
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as e:
            raise ConfigError(f"cannot read {self.path}: {e}") from e
        if not isinstance(data, dict):
            raise ConfigError(f"{self.path}: top level must be an object")
        return data

    def save(self, cfg: Dict[str, Any]) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.data_dir, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)

    def revision(self) -> int:
        try:
            return os.stat(self.path).st_mtime_ns
        except OSError:
            return 0

    def _list_path(self, fid: int) -> str:
        return os.path.join(self.lists_dir, f"{fid}.txt")

    def read_list(self, fid: int) -> Optional[str]:
        try:
            with open(self._list_path(fid), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def write_list(self, fid: int, text: str) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.lists_dir, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, self._list_path(fid))

    def remove_list(self, fid: int) -> None:
        try:
            os.remove(self._list_path(fid))
        except OSError:
            pass

    def close(self) -> None:
        pass


def sqlalchemy_missing() -> ConfigError:
    return ConfigError("database storage needs SQLAlchemy: pip install 'dnslens[sql]' "
                       "(or 'dnslens[postgres]' / 'dnslens[mysql]' to include a driver)")


def open_database(url: str) -> Tuple[Any, Any]:
    """Return ``(store, querylog)`` sharing one SQLAlchemy engine."""
    try:
        from .sqlstore import SqlBackend, SqlQueryLog, SqlStore
    except ImportError:
        raise sqlalchemy_missing() from None
    backend = SqlBackend(url)
    return SqlStore(backend), SqlQueryLog(backend)


def open_log_database(url: str) -> Any:
    try:
        from .sqlstore import SqlBackend, SqlQueryLog
    except ImportError:
        raise sqlalchemy_missing() from None
    return SqlQueryLog(SqlBackend(url))
