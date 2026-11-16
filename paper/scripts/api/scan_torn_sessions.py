#!/usr/bin/env python
"""Is any banked session in the corpus torn, truncated or unparseable?"""

import argparse
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DATA = os.path.join(REPO, "paper", "data")


def session_logs(data):
    """Every banked session log under `data`, in either archive layout."""
    for root, dirs, names in os.walk(data):
        dirs.sort()
        for name in sorted(names):
            if name == "events.jsonl":
                yield os.path.join(root, name)
            elif (name.endswith(".jsonl")
                  and os.path.basename(root) == "events"):
                yield os.path.join(root, name)


def inspect(path):
    """(events, torn findings, is_empty) for one log. Opens for reading only."""
    findings = []
    with io.open(path, "rb") as fh:
        raw = fh.read()
    if not raw.strip():
        return 0, [], True
    if not raw.endswith(b"\n"):
        findings.append("unterminated (no trailing newline)")
    events = 0
    for n, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            json.loads(line)
            events += 1
        except ValueError as exc:
            findings.append("line %d unparseable: %s" % (n, str(exc)[:60]))
    if not events:
        findings.append("bytes on disk but no parseable event")
    return events, findings, False


def quarantined(path, data):
    """Is this log inside an archive `quarantine_unhooked.py` moved aside?"""
    rel = os.path.relpath(path, data).replace("\\", "/")
    return any(part.endswith(".unhooked") for part in rel.split("/"))


def corroborate(path):
    """(bucket, detail) for an empty log, read off the harness's own record."""
    rj = os.path.join(os.path.dirname(path), "result.json")
    if not os.path.exists(rj):
        # No per-session record: the flat API layout, or a nested session that
        # never wrote one. Either way nothing corroborates the silence.
        return "unexplained", "no result.json beside the log"
    try:
        with io.open(rj, encoding="utf-8", errors="replace") as fh:
            turns = json.load(fh).get("num_turns")
    except ValueError:
        return "unexplained", "result.json will not parse"
    if not isinstance(turns, int):
        return "unexplained", "result.json carries no num_turns"
    if turns > 1:
        return "contradicted", "result.json reports %d turns" % turns
    return "explained", "result.json reports %d turn(s)" % turns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    logs = list(session_logs(args.data))
    torn = []
    empty = {"explained": [], "contradicted": [], "quarantined": [],
             "unexplained": []}
    events = 0
    for path in logs:
        n, findings, is_empty = inspect(path)
        events += n
        if findings:
            torn.append((path, n, findings))
        elif is_empty:
            bucket, detail = corroborate(path)
            if bucket == "contradicted" and quarantined(path, args.data):
                bucket = "quarantined"
            empty[bucket].append((path, detail))

    n_empty = sum(len(v) for v in empty.values())
    print("")
    print("  scanned %d banked session log(s), %d event(s), under %s"
          % (len(logs), events, args.data))
    print("")
    if torn:
        print("  %d LOG(S) TORN - a write was interrupted" % len(torn))
        for path, n, findings in torn:
            print("    %s  (%d event(s))"
                  % (os.path.relpath(path, args.data), n))
            for f in (findings[:3] if args.quiet else findings):
                print("        %s" % f)
    else:
        print("  torn: 0. No log is unterminated, unparseable or partially")
        print("  written. The atomic bank() holds across the whole corpus.")
    print("")
    print("  empty (no events at all): %d of %d log(s)" % (n_empty, len(logs)))
    print("      %6d explained     result.json reports <= 1 turn - the agent"
          % len(empty["explained"]))
    print("                           made no guarded call. Not a failure.")
    print("      %6d quarantined   dead-guard signature, already moved to"
          % len(empty["quarantined"]))
    print("                           <archive>.unhooked/. Not a failure.")
    print("      %6d contradicted  result.json reports work this log never"
          % len(empty["contradicted"]))
    print("                           saw. THE GUARD WAS DOWN.")
    print("      %6d unexplained   no record corroborates the silence."
          % len(empty["unexplained"]))
    print("")
    # One machine-readable line, so a gate reads counts rather than re-deriving
    # them from prose that a later edit would reword.
    print("  summary: torn %d, empty %d, explained %d, quarantined %d, "
          "contradicted %d, unexplained %d"
          % (len(torn), n_empty, len(empty["explained"]),
             len(empty["quarantined"]), len(empty["contradicted"]),
             len(empty["unexplained"])))
    print("")

    bad = empty["contradicted"] + empty["unexplained"]
    if bad:
        print("  %d EMPTY LOG(S) THAT NO RECORD EXPLAINS" % len(bad))
        for path, detail in (bad[:20] if args.quiet else bad):
            print("    %s" % os.path.relpath(path, args.data))
            print("        %s" % detail)
        if args.quiet and len(bad) > 20:
            print("    ... %d more" % (len(bad) - 20))
        print("")
    if torn:
        return 1
    if bad:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
