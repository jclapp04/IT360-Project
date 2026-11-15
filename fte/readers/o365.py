"""Reads Office 365 audit logs, a JSON list of records."""

import json

from fte.models import Event
from fte.util import clean_ip, parse_ts


def read_o365(path):
    """Reads an Office 365 file and returns a list of events."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    events = []
    for rec in data:
        # Purview exports wrap the real record as a JSON string
        if "AuditData" in rec:
            rec = json.loads(rec["AuditData"])

        # success or failure shows up in different ways, so check both
        status = str(rec.get("ResultStatus", ""))
        failed = status in ("Failed", "False") or "Failed" in rec.get("Operation", "")

        events.append(Event(
            ts=parse_ts(rec["CreationTime"]),   # no zone in the log, treated as UTC
            source="o365",
            action=rec["Operation"],
            user=rec.get("UserId"),
            ip=clean_ip(rec.get("ClientIP")),   # can come as ip:port
            target=rec.get("ObjectId"),
            outcome="failure" if failed else "success",
            detail=rec.get("Workload", ""),
        ))
    return events
