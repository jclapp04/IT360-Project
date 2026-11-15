import json

from fte.models import Event
from fte.util import clean_ip, parse_ts


def read_gworkspace(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    events = []
    for act in data["items"]:
        actor = act.get("actor") or {}
        app = act["id"].get("applicationName", "")

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
