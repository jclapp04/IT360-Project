import csv


def write_review(path, results):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["finding", "risk", "type", "statement", "events", "verified", "verdict"])
        n = 0
        for r in results:
            for fd in r["findings"]:
                n += 1
                writer.writerow([n, fd.get("risk_score"), fd.get("anomaly_type"), fd.get("statement"),
                                 " ".join(fd.get("event_ids", [])), fd["verified"], ""])
    return n
