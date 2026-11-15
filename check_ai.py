import glob
import json

from fte.readers import read_file
from fte.summarize import analyze
from fte.timeline import build_timeline

events = []
for path in glob.glob("samples/*.json"):
    events.extend(read_file(path))

result = analyze(build_timeline(events))
print(json.dumps(result, indent=2))
