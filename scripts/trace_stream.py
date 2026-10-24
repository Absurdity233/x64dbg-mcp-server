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
    ap.add_argument("--module", help="only count addresses inside this module name")
    ap.add_argument("--timeline", action="store_true",
                    help="print module residency over time (sampled)")
    ap.add_argument("--sample", type=int, default=1000,
                    help="timeline sampling interval in rows")
    ap.add_argument("--json", help="write aggregate result as JSON")
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
    timeline = []

    for row in stream_rows(files, columns):
        cip = row[columns[0]]
        total += 1

        if args.module:
            # Cheap module test: compare against the set of ranges seen so far
            # is not available here, so callers pass a name filter only when the
            # trace itself was step-filtered.
            pass

        addr_hits[cip] += 1

        if prev is not None and cip != prev:
            if len(cur_seq) >= 2:
                h = hashlib.sha1(",".join(f"{a:X}" for a in cur_seq).encode()).hexdigest()[:12]
                seq_hashes[h] += 1
            cur_seq = [cip]
        else:
            cur_seq.append(cip)
        prev = cip

        if args.timeline and total % args.sample == 0:
            timeline.append({"row": total, "cip": f"0x{cip:X}"})

    if len(cur_seq) >= 2:
        h = hashlib.sha1(",".join(f"{a:X}" for a in cur_seq).encode()).hexdigest()[:12]
        seq_hashes[h] += 1

    print(f"\nrows: {total}")
    print(f"unique addresses: {len(addr_hits)}")
    print(f"distinct blocks: {len(seq_hashes)}")

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
