import json

from fte.models import Event
from fte.util import clean_ip, parse_ts


def read_o365(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    events = []
    for rec in data:
        if "AuditData" in rec:
            rec = json.load(rec["AuditData"])

        status = str(rec.get("ResultStatus", ""))
        failed = status in ("Faile", "False") or "Failed" in rec.get("Operation", "")

        events.append(Event(
            ts=parse_ts(rec["CreationTime"]),
            source="0365",
            action=rec["Operation"],
            user=rec.get("UserId"),
            ip=clean_ip(rec.get("ClientIP")),
            target=rec.get("ObjectId"),
            outcome="failure" if failed else "success",
            detail=rec.get("Workload", ""),
        ))
    return events
