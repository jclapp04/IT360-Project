"""Reads Google Workspace activity logs, {"items": [ ... ]}."""

import json

from fte.models import Event
from fte.util import clean_ip, parse_ts


def read_gworkspace(path):
    """Reads a Google Workspace file and returns a list of events."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    events = []
    for act in data["items"]:
        actor = act.get("actor") or {}
        app = act["id"].get("applicationName", "")

        # one Google record can hold several events, so each one becomes
        # its own event and shares the record's time
        for ev in act.get("events", []):
            name = ev["name"]
            events.append(Event(
                ts=parse_ts(act["id"]["time"]),
                source="gworkspace",
                action=name,
                user=actor.get("email"),
                ip=clean_ip(act.get("ipAddress")),
                outcome="failure" if "fail" in name else "success",
                detail=app,
            ))
    return events
