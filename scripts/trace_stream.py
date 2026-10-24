"""Streaming trace analysis with segmentation support.

x64dbg's TraceSetLogFile grows without bound; a meaningful trace of a
virtualised target reaches gigabytes. Two things are needed:

  1. rotation - the debugger only knows one file at a time, so the caller
     stops/restarts into numbered segments (or an external splitter does it);
  2. streaming - parse each segment line by line and keep only aggregate
     counters, never the whole trace in memory.

This module is the analysis half. It accepts a glob of segments, reads them in
order, and emits the same handler statistics as trace_analyze.py plus a
timeline of "which module was executing at each point".

Usage
-----
    python trace_stream.py "F:/reverse1/.tools/trace_*.csv" --columns cip,rax,rcx
    python trace_stream.py trace.csv --timeline --module snarl
"""

from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import os
import re
import sys

HEX = re.compile(r"^[0-9a-fA-F]{4,16}$")


def parse_int(token: str):
    token = token.strip()
    if not token:
        return None
    if token.lower().startswith("0x"):
        token = token[2:]
    if not HEX.match(token):
        return None
    try:
        return int(token, 16)
    except ValueError:
        return None


def expand_input(pattern: str) -> list[str]:
    if os.path.isdir(pattern):
        pattern = os.path.join(pattern, "*.csv")
    files = sorted(glob.glob(pattern))
    if not files and os.path.exists(pattern):
        files = [pattern]
    # Numeric suffix ordering so trace_2 comes before trace_10.
    def key(p):
        m = re.search(r"(\d+)(?=\.[^.]+$)", os.path.basename(p))
        return (int(m.group(1)) if m else -1, p)
    return sorted(files, key=key)


def stream_rows(files: list[str], columns: list[str]):
    """Yield parsed rows without holding the file in memory."""
    for path in files:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p for p in re.split(r"[,\t; ]+", line) if p]
                if len(parts) < len(columns):
                    continue
                row = {}
                ok = True
                for name, tok in zip(columns, parts):
                    v = parse_int(tok)
                    if v is None:
                        ok = False
                        break
                    row[name] = v
                if ok:
                    yield row


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pattern", help="trace file, directory, or glob (trace_*.csv)")
    ap.add_argument("--columns", default="cip,rax,rcx")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--tid", help="only count rows whose last column matches this thread id (hex or decimal)")
    ap.add_argument("--tid-column", default="tid",
                    help="name of the thread-id column when passed via --columns (default tid)")
    ap.add_argument("--timeline", action="store_true",
                    help="print module residency over time (sampled)")
    ap.add_argument("--sample", type=int, default=1000,
                    help="timeline sampling interval in rows")
    ap.add_argument("--json", help="write aggregate result as JSON")
    ap.add_argument("--tick-column", default="tick",
                    help="name of the GetTickCount() column when passed via --columns (default tick)")
    args = ap.parse_args()

    columns = [c.strip() for c in args.columns.split(",") if c.strip()]
    files = expand_input(args.pattern)
    if not files:
        print(f"error: no files match {args.pattern}", file=sys.stderr)
        return 2

    print(f"segments: {len(files)}")
    for f in files:
        print(f"  {f}  ({os.path.getsize(f)/1e6:.1f} MB)")

    addr_hits = collections.Counter()
    seq_hashes = collections.Counter()
    segments_info = []
    total = 0
    prev = None
    cur_seq = []
    block_seen = set()
    MAX_BLOCK = 64
    timeline = []

    # When the trace carries GetTickCount(), group by real time instead of row
    # count: a virtualised dispatcher spends wildly different wall-clock time in
    # different handlers, so "rows per millisecond" is the number that separates
    # a hot dispatch path from a long memcpy. Rows between two tick values share
    # the same tick, so the granularity is the tick period (~15.6 ms).
    tick_buckets = collections.Counter()   # tick -> row count
    # Addresses seen in the tick currently being read. Flushed into
    # time_weight when the tick changes, so memory is bounded by one tick's
    # working set rather than by the whole trace.
    current_addrs = set()
    time_weight = collections.Counter()    # address -> ticks present in
    first_tick = None
    last_tick = None
    cur_tick = None
    have_tick = args.tick_column in columns

    for row in stream_rows(files, columns):
        # Thread filtering: the plugin appends {tid()} as the last column, so a
        # trace covering several threads can be narrowed to the one that did
        # the work without re-running it.
        if args.tid is not None:
            tid_val = row.get(args.tid_column)
            if tid_val is None and len(row) >= len(columns):
                tid_val = row[columns[-1]] if len(columns) > 1 else None
            if tid_val is None:
                continue
            try:
                want = int(args.tid, 0)
            except ValueError:
                print(f"error: --tid {args.tid!r} is not a number", file=sys.stderr)
                return 2
            if tid_val != want:
                continue

        cip = row[columns[0]]
        total += 1

        addr_hits[cip] += 1

        if have_tick:
            tick = row[args.tick_column]
            if first_tick is None:
                first_tick = tick
                cur_tick = tick
            elif tick != cur_tick:
                for a in current_addrs:
                    time_weight[a] += 1
                current_addrs.clear()
                cur_tick = tick
            last_tick = tick
            tick_buckets[tick] += 1
            current_addrs.add(cip)

        # Block segmentation: a "block" ends when control returns to an address
        # already seen in the current run (a loop) or after MAX_BLOCK rows.
        # Comparing cip != prev alone never brackets anything, which is why the
        # first version reported 0 blocks.
        if prev is None:
            cur_seq = [cip]
        else:
            if cip in block_seen or len(cur_seq) >= MAX_BLOCK:
                if len(cur_seq) >= 2:
                    h = hashlib.sha1(",".join(f"{a:X}" for a in cur_seq).encode()).hexdigest()[:12]
                    seq_hashes[h] += 1
                cur_seq = []
                block_seen.clear()
            cur_seq.append(cip)
            block_seen.add(cip)
        prev = cip

        if args.timeline and total % args.sample == 0:
            timeline.append({"row": total, "cip": f"0x{cip:X}"})

    if len(cur_seq) >= 2:
        h = hashlib.sha1(",".join(f"{a:X}" for a in cur_seq).encode()).hexdigest()[:12]
        seq_hashes[h] += 1
    block_seen.clear()
    for a in current_addrs:
        time_weight[a] += 1
    current_addrs.clear()

    print(f"\nrows: {total}")
    print(f"unique addresses: {len(addr_hits)}")
    print(f"distinct blocks: {len(seq_hashes)}")

    if have_tick and tick_buckets:
        span = (last_tick - first_tick) if last_tick is not None else 0
        ticks = len(tick_buckets)
        print(f"tick range: {first_tick}..{last_tick} ({span} ms, {ticks} distinct ticks)")
        if span > 0 and ticks > 1:
            print(f"throughput: {total/max(span,1):.1f} rows/ms over the trace window")

        # Time-weighted hot addresses: rank by how many ticks an address was
        # executing in, not by how many rows it produced. A tight loop can
        # dominate row count while occupying microseconds.
        print(f"\ntop {args.top} addresses by time residency (ticks present):")
        for addr, n in time_weight.most_common(args.top):
            pct = n / max(ticks, 1) * 100
            print(f"  {addr:#018x}  {n:>8} ticks  {pct:5.1f}% of window  "
                  f"{addr_hits[addr]:>9} rows")

    print(f"\ntop {args.top} hot addresses:")
    for addr, n in addr_hits.most_common(args.top):
        print(f"  {addr:#018x}  {n:>10}  {n/max(total,1)*100:5.1f}%")

    if args.timeline and timeline:
        print(f"\ntimeline (every {args.sample} rows):")
        for t in timeline[:40]:
            print(f"  row {t['row']:>12}  {t['cip']}")
        if len(timeline) > 40:
            print(f"  ... {len(timeline)-40} more samples")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "segments": files,
                "rows": total,
                "unique_addresses": len(addr_hits),
                "distinct_blocks": len(seq_hashes),
                "top_addresses": [[f"0x{a:X}", n] for a, n in addr_hits.most_common(args.top)],
                "timeline": timeline,
            }, fh, indent=2)
        print(f"\nresult -> {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
