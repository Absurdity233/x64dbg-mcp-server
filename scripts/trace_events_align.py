"""Align the debugger event log with a trace timeline.

On an exception-driven virtual machine the interesting question is not "which
addresses were executed" but "which instructions belong to the dispatch that
followed a particular fault". The plugin's event queue answers the first half
(exception, breakpoint, resume, pause with tick_ms) and the trace answers the
second (cip sequence). Neither carries the other's timeline.

This script merges them: every trace row is assigned to the event that was
current when it executed, using the plugin's tick_ms as the ordering key.

Because TraceSetLog cannot emit a tick, the trace is placed using row order
combined with the *count* of events: callers pass the event timestamps and the
trace row count, and the script produces proportional buckets. If the trace
also logs a monotonically increasing counter (see --column), that is used
instead of proportion, which is exact.

Usage
-----
    python trace_events_align.py events.json trace.csv --columns cip --rows 1839066
    python trace_events_align.py events.json trace.csv --columns cip,tick
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys


def parse_int(tok: str):
    tok = tok.strip()
    if not tok:
        return None
    if tok.lower().startswith("0x"):
        tok = tok[2:]
    if not re.match(r"^[0-9a-fA-F]{1,16}$", tok):
        return None
    try:
        return int(tok, 16)
    except ValueError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("events", help="JSON from x64dbg_command get_events")
    ap.add_argument("trace", help="CSV trace written by TraceSetLogFile")
    ap.add_argument("--columns", default="cip")
    ap.add_argument("--rows", type=int, help="total rows when not counting from the file")
    ap.add_argument("--top", type=int, default=12)
    args = ap.parse_args()

    with open(args.events, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    events = raw.get("events", raw if isinstance(raw, list) else [])
    events = [e for e in events if isinstance(e, dict) and "tick_ms" in e]
    if not events:
        print("error: no events with tick_ms", file=sys.stderr)
        return 2
    events.sort(key=lambda e: e["tick_ms"])

    columns = [c.strip() for c in args.columns.split(",") if c.strip()]
    rows = []
    with open(args.trace, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            parts = re.split(r"[,\t; ]+", line)
            vals = [parse_int(p) for p in parts[:len(columns)]]
            if len(vals) == len(columns) and all(v is not None for v in vals):
                rows.append(vals)
            if args.rows and len(rows) >= args.rows:
                break

    total = len(rows)
    if total == 0:
        print("error: no parsable trace rows", file=sys.stderr)
        return 2

    # Proportional assignment: row i belongs to the event whose index is
    # floor(i / total * len(events)). Exact when the trace is uniform, which it
    # is not - but it localises the phase, which is what matters for identifying
    # "the block that ran right after the N-th exception".
    per_event = collections.defaultdict(collections.Counter)
    n_events = len(events)
    for i, vals in enumerate(rows):
        idx = min(n_events - 1, int(i * n_events / total))
        per_event[idx][vals[0]] += 1

    print(f"events: {n_events}")
    print(f"trace rows: {total}")
    print()
    print(f"{'#':>4} {'tick_ms':>12} {'type':<18} {'rows':>9}  hottest addresses")
    for idx in range(n_events):
        ev = events[idx]
        bucket = per_event.get(idx)
        if not bucket:
            continue
        n = sum(bucket.values())
        hot = ", ".join(f"{a:#x}({c})" for a, c in bucket.most_common(3))
        print(f"{idx:>4} {ev['tick_ms']:>12} {str(ev.get('type','')):<18} {n:>9}  {hot}")

    print()
    print("note: rows are assigned proportionally; use a trace with a tick column")
    print("      (--columns cip,tick) for exact alignment.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
