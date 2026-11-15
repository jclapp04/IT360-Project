import csv
import json
from datetime import datetime, timezone
import sys

from fte.evidence import sha256_file
from fte.readers import read_file
from fte.report import build_report
from fte.timeline import build_timeline
from fte.summarize import analyze_all

def next_filename(base="timeline", ext=".csv"):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H:%M:%S")
    return f"{base}_{stamp}{ext}"


def main():
    use_ai = "--ai" in sys.argv[1:]
    paths = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not paths:
        print("usage: python3 main.py FILE [FILE ...]")
        sys.exit(1)

    events = []
    hashes = []
    for path in paths:
        digest = sha256_file(path)
        found = read_file(path)
        print(f"{path}: {len(found)} events, sha256 {digest[:16]}...")
        hashes.append((path, digest))
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
    results = None

    if use_ai:
        results = analyze_all(timeline)
        ai_name = out_name.replace("timeline", "ai", 1).replace(".csv", ".json")
        with open(ai_name, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        findings = [f for r in results for f in r["findings"]]
        good = sum(1 for f in findings if f["verified"])
        print(f"\nAI: {len(findings)} findings, {good} verified. Saved to {ai_name}")
        for r in results:
            if r["error"]:
                print(f"AI chunk {r['first_id']} to {r['last_id']} failed: {r['error']}")

    report_name = out_name.replace("timeline", "report", 1).replace(".csv", ".html")
    with open(report_name, "w", encoding="utf-8") as f:
        f.write(build_report("Cloud log investigation", timeline, hashes, results))
    print(f"Report saved to {report_name}")

if __name__ == "__main__":
    main()
