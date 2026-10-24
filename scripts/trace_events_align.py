"""Align the debugger event log with a trace timeline.

On an exception-driven virtual machine the interesting question is not "which
addresses were executed" but "which instructions belong to the dispatch that
followed a particular fault". The plugin's event queue answers the first half
(exception, breakpoint, resume, pause with tick_ms) and the trace answers the
second (cip sequence). Neither carries the other's timeline.

This script merges them: every trace row is assigned to the event that was
current when it executed, using the plugin's tick_ms as the ordering key.

Two modes:

  exact         the trace has a tick column ({GetTickCount()}, which the
                /api/trace/thread route appends and which x64dbg re-evaluates
                for every instruction). Each row is placed in the real event
                window it executed in.
  proportional  no tick column; rows are bucketed by row-position proportion.
                Kept as a fallback for traces captured with the plain
                TraceSetLog command, and clearly labelled as approximate.

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

    # Exact alignment: the plugin appends {GetTickCount()} to every trace row, so
    # when the trace carries a tick column we can place each row in the event
    # window it actually executed in. Without it we fall back to proportional
    # bucketing and say so.
    tick_idx = None
    for i, name in enumerate(columns):
        if name.lower() in ("tick", "ticks", "gettickcount"):
            tick_idx = i
            break

    per_event = collections.defaultdict(collections.Counter)
    exact = tick_idx is not None and len(rows[0]) > tick_idx

    if exact:
        # Events are sorted by tick_ms. For each row find the last event whose
        # tick_ms <= row tick - that is the event that was "current".
        ev_ticks = [e["tick_ms"] for e in events]
        import bisect
        for vals in rows:
            t = vals[tick_idx]
            idx = bisect.bisect_right(ev_ticks, t) - 1
            if idx < 0:
                idx = 0
            per_event[idx][vals[0]] += 1
    else:
        n_events = len(events)
        for i, vals in enumerate(rows):
            idx = min(n_events - 1, int(i * n_events / total))
            per_event[idx][vals[0]] += 1

    print(f"events: {len(events)}")
    print(f"trace rows: {total}")
    print(f"alignment: {'EXACT (tick column)' if exact else 'proportional (no tick column)'}")

    outside = 0
    if exact:
        # A run-trace ends the moment the debugger pauses, so a trace started
        # once and paused once covers only the first window. Say so explicitly:
        # otherwise the empty buckets below look like a bug in the aligner.
        lo = min(v[tick_idx] for v in rows)
        hi = max(v[tick_idx] for v in rows)
        outside = sum(1 for e in events if not (lo <= e["tick_ms"] <= hi))
        print(f"trace tick range: {lo}..{hi} "
              f"({hi - lo} ms)")
        if outside:
            print(f"events outside the trace window: {outside} "
                  f"(trace ended at the first pause)")

    print()
    print(f"{'#':>4} {'tick_ms':>12} {'type':<18} {'rows':>9}  hottest addresses")
    for idx in range(len(events)):
        ev = events[idx]
        bucket = per_event.get(idx)
        if not bucket:
            continue
        n = sum(bucket.values())
        hot = ", ".join(f"{a:#x}({c})" for a, c in bucket.most_common(3))
        print(f"{idx:>4} {ev['tick_ms']:>12} {str(ev.get('type','')):<18} {n:>9}  {hot}")

    if exact and outside:
        print()
        print(f"note: {outside} of {len(events)} events have no trace rows - the"
              " trace window closed before they happened.")
        print("      Re-start the trace after each resume, or trace with a"
              " break condition that does not require pausing.")

    if not exact:
        print()
        print("note: no tick column in the trace - rows were assigned proportionally.")
        print("      Re-run the trace via /api/trace/thread (it appends")
        print("      {GetTickCount()}) and pass --columns cip,<...,>tick.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
