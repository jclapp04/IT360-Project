import csv
from datetime import datetime, timezone
import sys

from fte.evidence import sha256_file
from fte.readers import read_file
from fte.timeline import build_timeline


def next_filename(base="timeline", ext=".csv"):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H:%M:%S")
    return f"{base}_{stamp}{ext}"


def main():
    paths = sys.argv[1:]
    if not paths:
        print("usage: python3 main.py FILE [FILE ...]")
        sys.exit(1)

    events = []
    for path in paths:
        digest = sha256_file(path)
        found = read_file(path)
        print(f"{path}: {len(found)} events, sha256 {digest[:16]}...")
        events.extend(found)

    timeline = build_timeline(events)

    out_name = next_filename()
    with open(out_name, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "time_utc", "source", "user", "ip", "action", "outcome", "target", "detail"])
        for e in timeline:
            writer.writerow([e.event_id, e.ts.isoformat(), e.source, e.user, e.ip,
                             e.action, e.outcome, e.target, e.detail])

    print(f"\n{len(timeline)} events written to {out_name}")


if __name__ == "__main__":
    main()
