"""
history_store.py
----------------
A small JSON-backed record of what this tool has previously observed for a
host, so the dashboard can show a hosting-history table (netblock owner /
IP / web server / certificate issuer over time).

Netcraft can show years of history because it crawls continuously; this
tool only knows what it has seen itself, so the history starts empty and
fills in as you re-scan a host. Consecutive identical observations are
collapsed into one row with a first_seen/last_seen window rather than
appended, which is what makes the table read as "changed on" history.

Storage is a single JSON file under reports/ -- deliberately dependency-free.
Concurrent writers can race; for a multi-worker deployment, swap this for a
real datastore.
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any, Dict, List

HISTORY_PATH = os.path.join(os.path.dirname(__file__), "reports", "history.json")

# Fields compared to decide whether a scan represents a change.
_TRACKED = ("ip", "netblock_owner", "hosting_country", "web_server", "tls_issuer")

MAX_ENTRIES_PER_HOST = 50
MAX_HOSTS = 200


def _now() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")


def _load(path: str) -> Dict[str, List[Dict[str, Any]]]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        # A corrupt or unreadable history file must never break a scan.
        return {}


def _save(path: str, data: Dict[str, List[Dict[str, Any]]]) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
    except OSError:
        pass  # history is a nicety, not worth failing a scan over


def load_history(hostname: str, path: str = HISTORY_PATH) -> List[Dict[str, Any]]:
    """Return stored observations for a host, oldest first."""
    return _load(path).get(hostname.lower(), [])


def record_observation(
    hostname: str,
    observation: Dict[str, Any],
    path: str = HISTORY_PATH,
) -> List[Dict[str, Any]]:
    """Merge an observation into the host's history and return the full list.

    If nothing tracked has changed since the last scan, the existing entry's
    last_seen is updated instead of adding a duplicate row.
    """
    hostname = hostname.lower()
    data = _load(path)
    entries = data.get(hostname, [])
    now = _now()

    unchanged = bool(entries) and all(
        entries[-1].get(field) == observation.get(field) for field in _TRACKED
    )

    if unchanged:
        entries[-1]["last_seen"] = now
        entries[-1]["scans"] = entries[-1].get("scans", 1) + 1
    else:
        entry = {field: observation.get(field) for field in _TRACKED}
        entry.update({"first_seen": now, "last_seen": now, "scans": 1})
        entries.append(entry)
        entries = entries[-MAX_ENTRIES_PER_HOST:]

    data[hostname] = entries

    if len(data) > MAX_HOSTS:
        # Drop the least recently touched hosts.
        ordered = sorted(data.items(), key=lambda kv: kv[1][-1].get("last_seen", ""))
        for stale_host, _ in ordered[: len(data) - MAX_HOSTS]:
            data.pop(stale_host, None)

    _save(path, data)
    return entries
