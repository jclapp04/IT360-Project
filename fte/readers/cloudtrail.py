"""Reads AWS CloudTrail logs, {"Records": [ ... ]}."""

import json

from fte.models import Event
from fte.util import clean_ip, parse_ts


def read_cloudtrail(path):
    """Reads a CloudTrail file and returns a list of events."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    events = []
    for rec in data["Records"]:
        # some fields are missing or null, so default to {}
        ident = rec.get("userIdentity") or {}
        resp = rec.get("responseElements") or {}
        params = rec.get("requestParameters") or {}

        # a failure has an errorCode, or a failed console login
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
