import glob
from fte.readers import read_file
from fte.summarize import check_findings
from fte.timeline import build_timeline

events = []
for path in glob.glob("samples/*.json"):
    events.extend(read_file(path))
timeline = build_timeline(events)

fake = {"findings": [
    {"statement": "Failed login then success from 203.0.113.45", "event_ids": ["E0003", "E0004"]},
    {"statement": "Something happened", "event_ids": ["E0099"]},
    {"statement": "Login from 198.51.100.9", "event_ids": ["E0006"]},
    {"statement": "No evidence given", "event_ids": []},
]}

for f in check_findings(fake, timeline)["findings"]:
    print("Verified" if f["verified"] else "NOT VERIFIED", "|", f["statement"], "|", f["problems"])
