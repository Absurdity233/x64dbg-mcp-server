#!/usr/bin/env python3
"""Analyse an x64dbg trace log to recover a virtual machine's structure.

The trace is whatever `TraceSetLog` wrote, e.g.

    TraceSetLogFile "trace.csv"
    TraceSetLog "{p:cip},{p:rax},{p:rcx}"
    TraceIntoConditional 0, 5000000

This script does the first four stages of docs/vm-analysis.md:

  1. normalise      parse hex, drop duplicates, keep order
  2. dispatcher     find the address the VM jumps back to between handlers
  3. segment        split the trace at each dispatcher hit
  4. cluster        hash each segment's address sequence into a handler id

Usage:
    python trace_analyze.py trace.csv --columns cip,rax,rcx
    python trace_analyze.py trace.csv --top 30 --json out.json
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import sys

HEX = re.compile(r"^[0-9a-fA-F]{4,16}$")


def parse_int(token: str) -> int | None:
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


def load_rows(path: str, columns: list[str]) -> list[dict[str, int]]:
    rows: list[dict[str, int]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p for p in re.split(r"[,\t; ]+", line) if p]
            if len(parts) < len(columns):
                continue
            row: dict[str, int] = {}
            ok = True
            for name, token in zip(columns, parts):
                value = parse_int(token)
                if value is None:
                    ok = False
                    break
                row[name] = value
            if ok:
                rows.append(row)
    return rows


def dedupe_consecutive(rows: list[dict[str, int]], key: str) -> list[dict[str, int]]:
    """x64dbg logs the same instruction more than once; collapse runs."""
    out: list[dict[str, int]] = []
    prev = None
    for row in rows:
        cur = row[key]
        if prev is not None and cur == prev:
            continue
        out.append(row)
        prev = cur
    return out


def find_dispatchers(rows: list[dict[str, int]], key: str, limit: int = 8):
    """Score addresses by 'how often control returns here'.

    A VM dispatcher is revisited constantly and is reached from many distinct
    predecessors while jumping to many distinct handlers. Frequency alone is a
    decent proxy; predecessor diversity breaks ties.
    """
    hits = collections.Counter(r[key] for r in rows)
    preds: dict[int, set[int]] = collections.defaultdict(set)
    succs: dict[int, set[int]] = collections.defaultdict(set)

    for prev, cur in zip(rows, rows[1:]):
        preds[cur[key]].add(prev[key])
        succs[prev[key]].add(cur[key])

    scored = []
    for addr, count in hits.most_common(limit * 8):
        fan_in = len(preds.get(addr, ()))
        fan_out = len(succs.get(addr, ()))
        # A dispatcher fans in from everywhere and fans out to many handlers.
        score = count * (1 + fan_in) * (1 + min(fan_out, 64))
        scored.append(
            {
                "address": f"0x{addr:X}",
                "hits": count,
                "predecessors": fan_in,
                "successors": fan_out,
                "score": score,
            }
        )
    scored.sort(key=lambda d: d["score"], reverse=True)
    return scored[:limit]


def segment(rows: list[dict[str, int]], key: str, dispatcher: int) -> list[list[int]]:
    """Split the trace into runs between dispatcher hits."""
    segments: list[list[int]] = []
    current: list[int] = []
    for row in rows:
        addr = row[key]
        if addr == dispatcher:
            if current:
                segments.append(current)
            current = []
            continue
        current.append(addr)
    if current:
        segments.append(current)
    return segments


def cluster(segments: list[list[int]], min_len: int = 2):
    """Group segments by the hash of their address sequence."""
    groups: dict[str, dict] = {}
    for seq in segments:
        if len(seq) < min_len:
            continue
        digest = hashlib.sha1(",".join(f"{a:X}" for a in seq).encode()).hexdigest()[:12]
        entry = groups.setdefault(
            digest,
            {
                "id": digest,
                "entry": f"0x{seq[0]:X}",
                "instructions": len(seq),
                "hits": 0,
                "addresses": set(),
            },
        )
        entry["hits"] += 1
        entry["addresses"].update(seq)

    out = []
    for entry in groups.values():
        out.append(
            {
                "id": entry["id"],
                "entry": entry["entry"],
                "instructions": entry["instructions"],
                "hits": entry["hits"],
                "distinct_addresses": len(entry["addresses"]),
            }
        )
    out.sort(key=lambda d: d["hits"], reverse=True)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("trace", help="path to the trace log")
    ap.add_argument("--columns", default="cip,rax,rcx",
                    help="comma-separated column names matching the TraceSetLog format")
    ap.add_argument("--dispatcher", help="skip detection and use this dispatcher address")
    ap.add_argument("--top", type=int, default=20, help="how many handlers to print")
    ap.add_argument("--json", help="write the full result as JSON")
    args = ap.parse_args()

    columns = [c.strip() for c in args.columns.split(",") if c.strip()]
    if not columns:
        print("error: --columns is empty", file=sys.stderr)
        return 2

    rows = load_rows(args.trace, columns)
    if not rows:
        print("error: no parsable rows (check --columns against the TraceSetLog format)", file=sys.stderr)
        return 2

    rows = dedupe_consecutive(rows, columns[0])
    dispatchers = find_dispatchers(rows, columns[0])

    if args.dispatcher:
        dispatcher = int(args.dispatcher, 16)
    elif dispatchers:
        dispatcher = int(dispatchers[0]["address"], 16)
    else:
        print("error: could not identify a dispatcher; pass --dispatcher", file=sys.stderr)
        return 2

    segments = segment(rows, columns[0], dispatcher)
    handlers = cluster(segments)

    result = {
        "trace": args.trace,
        "columns": columns,
        "steps": len(rows),
        "unique_addresses": len({r[columns[0]] for r in rows}),
        "dispatcher": f"0x{dispatcher:X}",
        "dispatcher_candidates": dispatchers,
        "segments": len(segments),
        "handlers": handlers,
    }

    print(f"trace            : {args.trace}")
    print(f"steps (deduped)  : {len(rows)}")
    print(f"unique addresses : {result['unique_addresses']}")
    print(f"dispatcher       : {result['dispatcher']}")
    print(f"segments         : {len(segments)}")
    print(f"distinct handlers: {len(handlers)}")
    print()
    print("dispatcher candidates:")
    for d in dispatchers[:5]:
        print(f"  {d['address']}  hits={d['hits']:<8} in={d['predecessors']:<4} out={d['successors']:<4} score={d['score']}")
    print()
    print(f"top {min(args.top, len(handlers))} handlers by hit count:")
    total = sum(h["hits"] for h in handlers) or 1
    print(f"  {'id':<14}{'entry':<16}{'insns':>6}{'hits':>10}{'share':>8}")
    for h in handlers[: args.top]:
        print(f"  {h['id']:<14}{h['entry']:<16}{h['instructions']:>6}{h['hits']:>10}{h['hits'] / total * 100:>7.1f}%")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"\nfull result -> {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
