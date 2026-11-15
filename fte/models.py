"""The Event structure every log source gets converted into."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Event:
    """One event. AWS, Office 365 and Google logs all become this."""

    ts: datetime          # when it happened, always UTC
    source: str           # "aws_cloudtrail", "o365" or "gworkspace"
    action: str           # what was done, like ConsoleLogin
    user: str = None      # account that did it
    ip: str = None        # source IP, port removed
    target: str = None    # what it was done to, if the log says
    outcome: str = None   # "success" or "failure"
    detail: str = ""      # extra context, e.g. the service name
    event_id: str = ""    # E0001, E0002, ... set after sorting in timeline.py
