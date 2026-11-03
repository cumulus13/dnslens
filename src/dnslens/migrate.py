# File: dnslens/src/dnslens/migrate.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:18 SE Asia Standard Time
# Description:
# License: GPL-3.0

"""Move an existing file-based data directory (config, blocklists, query log) into a SQL database."""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, Optional

from .querylog import QueryLog
from .server import ConfigError
from .storage import FileStore, open_database


def migrate_files_to_db(from_dir: str, url: str, include_log: bool = True, force: bool = False,
                        progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    say = progress or (lambda m: None)
    if not os.path.isfile(os.path.join(from_dir, "config.json")):
        raise ConfigError(f"{from_dir} has no config.json: nothing to migrate")
    src = FileStore(from_dir)
    cfg = src.load()
    assert cfg is not None
    store, qlog = open_database(url)
    try:
        if store.load() is not None and not force:
            raise ConfigError("the database already holds a dnslens configuration; use --force to overwrite it")
        store.save(cfg)
        lists = 0
        for f in cfg.get("filters", []):
            text = src.read_list(f["id"])
            if text is not None:
                store.write_list(f["id"], text)
                lists += 1
        say(f"configuration and {lists} blocklist(s) copied")
        rows = 0
        db_path = os.path.join(from_dir, "queries.db")
        if include_log and os.path.isfile(db_path):
            old = QueryLog(db_path)
            for batch in old.iter_rows():
                qlog.insert_rows(batch)  # type: ignore[attr-defined]
                rows += len(batch)
                say(f"{rows} log rows copied")
        return {"config": True, "lists": lists, "log_rows": rows, "target": qlog.describe()}
    finally:
        qlog.close()
