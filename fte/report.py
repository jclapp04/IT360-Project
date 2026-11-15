"""Builds the HTML report as one standalone file with the CSS inside it.

Log values can be controlled by an attacker, so every value goes through e()
first. That way something like <script> in a log shows as text and doesn't
run when the report is opened.
"""

import html
from collections import Counter

CSS = """
body{font-family:system-ui,Arial,sans-serif;margin:24px;color:#1b1f23}
h1{margin:0}
h2{border-bottom:2px solid #1f3864;padding-bottom:4px;margin-top:32px}
table{border-collapse:collapse;width:100%;font-size:.85em}
th{background:#1f3864;color:#fff;text-align:left;padding:6px}
td{border-bottom:1px solid #ddd;padding:5px 6px;vertical-align:top}
.fail td.o{color:#b00020;font-weight:600}
.high{border-left:5px solid #d93025;background:#fce8e6;padding:8px 12px;margin:8px 0}
.med{border-left:5px solid #e37400;background:#fef7e0;padding:8px 12px;margin:8px 0}
.low{border-left:5px solid #1e8e3e;background:#e6f4ea;padding:8px 12px;margin:8px 0}
.warn{background:#fef7e0;border:1px solid #e37400;padding:8px 12px}
.tag{font-size:.75em;border:1px solid #888;border-radius:3px;padding:0 4px;margin-left:4px}
code{font-family:monospace;font-size:.9em}
tr:target td{background:#fff3b0}
"""


def e(value):
    """Escapes a value for HTML. None becomes an empty string."""
    return html.escape("" if value is None else str(value), quote=True)


def when(dt):
    """Formats a time as YYYY-MM-DD HH:MM:SS."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def score_of(finding):
    """Risk score as a number. Missing or bad scores count as 0."""
    try:
        return int(finding.get("risk_score", 0))
    except (TypeError, ValueError):
        return 0


def finding_html(f):
    """HTML for one finding with its tags, score and links to its events."""
    # the model can return two types in one string, so show each as a tag
    tags = "".join(f'<span class="tag">{e(t.strip())}</span>' for t in str(f.get("anomaly_type", "")).split(","))
    links = ", ".join(f'<a href="#{e(i)}">{e(i)}</a>' for i in f.get("event_ids", []))
    status = "verified" if f["verified"] else "NOT verified: " + "; ".join(f["problems"])
    return (f'{e(f.get("statement"))} {tags}<br>'
            f'<small>risk {score_of(f)}/10, confidence {e(f.get("confidence"))}, '
            f'events: {links} ({e(status)})</small>')


def build_report(case, events, hashes, results):
    """Returns the whole report as one HTML string.

    case     name in the title
    events   the sorted timeline
    hashes   (file path, sha256) for each file, taken before reading it
    results  AI results from analyze_all(), or None without --ai
    """
    p = [f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
         f'<title>Forensic Timeline: {e(case)}</title><style>{CSS}</style></head><body>']
    p.append(f"<h1>Forensic Timeline Report: {e(case)}</h1>")
    p.append("<p>All times are UTC.</p>")

    # hashes taken before parsing
    p.append("<h2>Evidence files</h2><table><tr><th>File</th><th>SHA-256 (taken before parsing)</th></tr>")
    for path, digest in hashes:
        p.append(f"<tr><td>{e(path)}</td><td><code>{e(digest)}</code></td></tr>")
    p.append("</table>")

    # scope numbers come straight from the logs, no AI
    failures = sum(1 for ev in events if ev.outcome == "failure")
    p.append("<h2>Scope</h2>")
    if events:
        p.append(f"<p><strong>{len(events)}</strong> events, <strong>{failures}</strong> failed. "
                 f"First {when(events[0].ts)} UTC, last {when(events[-1].ts)} UTC.</p>")

    users, user_fail, ips, ip_fail = Counter(), Counter(), Counter(), Counter()
    for ev in events:
        bad = ev.outcome == "failure"
        if ev.user:
            users[ev.user] += 1
            user_fail[ev.user] += bad
        if ev.ip:
            ips[ev.ip] += 1
            ip_fail[ev.ip] += bad

    p.append("<h3>Affected accounts</h3><table><tr><th>Account</th><th>Events</th><th>Failed</th></tr>")
    for u, n in users.most_common():
        p.append(f"<tr><td>{e(u)}</td><td>{n}</td><td>{user_fail[u]}</td></tr>")
    p.append("</table><h3>IP addresses (indicators)</h3><table><tr><th>IP</th><th>Events</th><th>Failed</th></tr>")
    for ip, n in ips.most_common():
        p.append(f"<tr><td>{e(ip)}</td><td>{n}</td><td>{ip_fail[ip]}</td></tr>")
    p.append("</table>")

    # AI summary and findings grouped by severity
    p.append("<h2>AI analysis</h2>")
    if results is None:
        p.append("<p>AI analysis was not run for this report.</p>")
    else:
        p.append('<div class="warn"><strong>AI-generated, advisory only.</strong> '
                 "Check every statement against the timeline. Verified means only that the cited event IDs "
                 "exist and any IP addresses mentioned appear in those events.</div>")
        for r in results:
            if r["error"]:
                p.append(f'<p class="warn">Events {e(r["first_id"])} to {e(r["last_id"])}: AI failed: {e(r["error"])}</p>')
            elif r["summary"]:
                p.append(f"<p><strong>{e(r['first_id'])} to {e(r['last_id'])}:</strong> {e(r['summary'])}</p>")

        findings = sorted((f for r in results for f in r["findings"]), key=score_of, reverse=True)
        for label, css, low, high in (("High", "high", 7, 10), ("Medium", "med", 4, 6), ("Low", "low", 0, 3)):
            group = [f for f in findings if low <= score_of(f) <= high]
            p.append(f"<h3>{label} severity ({len(group)})</h3>")
            for f in group:
                p.append(f'<div class="{css}">{finding_html(f)}</div>')

    # full timeline, each row has an id so findings can link to it
    p.append(f"<h2>Timeline ({len(events)} events)</h2><table><tr><th>ID</th><th>Time (UTC)</th><th>Source</th>"
             "<th>User</th><th>IP</th><th>Action</th><th>Outcome</th><th>Target</th><th>Detail</th></tr>")
    for ev in events:
        cls = ' class="fail"' if ev.outcome == "failure" else ""
        p.append(f'<tr id="{e(ev.event_id)}"{cls}><td>{e(ev.event_id)}</td><td>{when(ev.ts)}</td>'
                 f"<td>{e(ev.source)}</td><td>{e(ev.user)}</td><td>{e(ev.ip)}</td><td>{e(ev.action)}</td>"
                 f'<td class="o">{e(ev.outcome)}</td><td>{e(ev.target)}</td><td>{e(ev.detail)}</td></tr>')
    p.append("</table></body></html>")
    return "".join(p)
