from datetime import datetime, timezone



def parse_ts(value):
    """Turn a log timestamp into UTC datetime with a timezone"""
    dt = datetime.fromisoformat(str(value).strip())
    if dt.tzinfo is None:
        #No timezone in the log, assume it tis UTC
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)



def clean_ip(value):
    """203.0.113.45.51822 -> 203.0.113.45, leaves IPv6"""
    if not value:
        return None
    value = str(value).strip()
    if value.count(":") == 1:
        value = value.split(":")[0]
    return value or None
