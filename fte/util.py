"""Helpers the log readers share."""

from datetime import datetime, timezone


def parse_ts(value):
    """Turns a timestamp into a UTC datetime.

    Z and offsets like -05:00 get converted to UTC. A timestamp with no zone
    (Office 365) is treated as UTC already, which is listed in the README.
    """
    dt = datetime.fromisoformat(str(value).strip())
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def clean_ip(value):
    """Returns just the IP and drops the :port if there is one.

    203.0.113.45:51822 becomes 203.0.113.45. IPv6 has lots of colons, so only
    a single colon counts as a port.
    """
    if not value:
        return None
    value = str(value).strip()
    if value.count(":") == 1:
        value = value.split(":")[0]
    return value or None
