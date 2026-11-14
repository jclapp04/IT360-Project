from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Event:
    ts: datetime
    source: str     #aws_cloudtrail o365 gworkspace
    action: str
    user: Optional[str] = None
    ip: Optional[str] = None
    target: Optional[str] = None
    outcome: Optional[str] = None   # "success", "failure", "None"
    detail: str = ""
    event_id: str = ""
