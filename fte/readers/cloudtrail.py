import json

from fte.models import Event
from fte.util import clean_ip, parse_ts


def read_cloudtrail(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)


    events = []
    for rec in data["Records"]:
        ident = rec.get("userIdentity") or {}
        resp = rec.get("responseElements") or {}
        params = rec.get("requestParameters") or {}


        failed = "errorCode" in rec or resp.get("ConsoleLogin") == "Failure"
        target = params.get("bucketName") or params.get("userName") or params.get("name")

        events.append(Event(
            ts=parse_ts(rec["eventTime"]),
            source="aws_cloudtrail",
            action=rec["eventName"],
            user=ident.get("userName") or ident.get("arn"),
            ip=clean_ip(rec.get("sourceIPAddress")),
            target=target,
            outcome="failure" if failed else "success",
            detail=rec.get("eventSource", ""),
        ))
    return events
