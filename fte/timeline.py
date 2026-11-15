def build_timeline(events):
    ordered = sorted(events, key=lambda e: e.ts)
    for n, ev in enumerate(ordered, 1):
        ev.event_id = f"E{n:04d}"
    return ordered
