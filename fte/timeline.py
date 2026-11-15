"""Merges events from every source into one timeline."""


def build_timeline(events):
    """Sorts events by UTC time and gives each one an ID (E0001, E0002, ...).

    Sorting works across sources because the readers already converted every
    time to UTC. The AI and the report use the IDs to point at events, so
    they can't change after this.
    """
    ordered = sorted(events, key=lambda e: e.ts)
    for n, ev in enumerate(ordered, 1):
        ev.event_id = f"E{n:04d}"
    return ordered
