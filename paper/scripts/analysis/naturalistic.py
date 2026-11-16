#!/usr/bin/env python
"""The in-the-wild corpus: what the guard saw during ordinary use of this repo."""

import argparse
import collections
import glob
import io
import json
import os
import sys
import uuid

LOG = os.path.join(".sentinel", "events.jsonl")
REPO_KEY = r"/home/author/Documents/GitHub/repo"
TRANSCRIPTS = os.path.expanduser(
    "~/.claude/projects/home-author-Documents-GitHub-repo")

# crates/sentinel-events/src/lib.rs::RUN_NAMESPACE
RUN_NAMESPACE = uuid.UUID(bytes=bytes([
    0x8f, 0x1c, 0x4a, 0x2e, 0x9b, 0x74, 0x4d, 0x3a,
    0xb6, 0x05, 0x1e, 0xd8, 0x7c, 0x33, 0x90, 0x21]))

BURST_CALLS = 40      # more than this many tool calls...
BURST_RATE = 5.0      # ...at more than this many per minute, with no messages


def run_id(repo, session):
    return str(uuid.uuid5(RUN_NAMESPACE, "%s\x00%s" % (repo, session)))


def load_sessions(path):
    runs = collections.defaultdict(
        lambda: {"calls": 0, "msgs": 0, "deny": 0, "over": 0,
                 "first": None, "last": None,
                 "rules": collections.Counter(),
                 "tools": collections.Counter(), "model": None})
    for line in io.open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        r = runs[e.get("run_id")]
        kind = e.get("kind")
        if kind == "tool_call":
            r["calls"] += 1
            r["tools"][e.get("tool")] += 1
        elif kind == "agent_message":
            r["msgs"] += 1
            tool = e.get("tool") or ""
            if tool.startswith("claude"):
                r["model"] = tool
        elif kind == "guard_decision":
            meta = e.get("meta") or {}
            verdict = meta.get("verdict")
            if verdict == "deny":
                r["deny"] += 1
                r["rules"][meta.get("rule")] += 1
            elif verdict == "overridden":
                r["over"] += 1
        ts = e.get("ts")
        if ts:
            r["first"] = min(r["first"] or ts, ts)
            r["last"] = max(r["last"] or ts, ts)
    return runs


def minutes(r):
    if not (r["first"] and r["last"]):
        return 0.0
    import datetime

    def parse(t):
        t = t[:19]
        return datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%S")
    return max((parse(r["last"]) - parse(r["first"])).total_seconds() / 60.0,
               0.0001)


def is_burst(r):
    return (r["msgs"] == 0 and r["calls"] > BURST_CALLS
            and r["calls"] / minutes(r) > BURST_RATE)


def attribute(runs):
    """Exact model attribution by recomputing run_id from each transcript."""
    model_of = {}
    for f in glob.glob(os.path.join(TRANSCRIPTS, "*.jsonl")):
        sid = os.path.basename(f)[:-len(".jsonl")]
        seen = collections.Counter()
        for line in io.open(f, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                m = json.loads(line)
            except ValueError:
                continue
            model = (m.get("message") or {}).get("model")
            if model and model != "<synthetic>":
                seen[model] += 1
        if seen:
            model_of[run_id(REPO_KEY, sid)] = seen.most_common(1)[0][0]
    hits = 0
    for rid, r in runs.items():
        if not r["model"] and rid in model_of:
            r["model"] = model_of[rid]
            hits += 1
    return hits, len(model_of)


def report(runs, label):
    sessions = len(runs)
    calls = sum(r["calls"] for r in runs.values())
    deny = sum(r["deny"] for r in runs.values())
    over = sum(r["over"] for r in runs.values())
    total = deny + over
    print("  %-22s %6d %8d %7d %8d  %s"
          % (label, sessions, calls, deny, over,
             "%.1f%%" % (100.0 * over / total) if total else "---"))
    return total, over


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default=LOG)
    ap.add_argument("--keep-bursts", action="store_true",
                    help="do not exclude machine-paced sessions; reproduces "
                         "the unfiltered figure so the filter's effect is "
                         "checkable rather than asserted")
    args = ap.parse_args()

    if not os.path.exists(args.log):
        print("\n  no naturalistic log at %s\n" % args.log)
        return 1

    runs = load_sessions(args.log)
    hits, n_transcripts = attribute(runs)
    bursts = {k: v for k, v in runs.items() if is_burst(v)}
    kept = {k: v for k, v in runs.items() if k not in bursts}

    print("")
    print("  IN-THE-WILD CORPUS - ordinary use of this repository")
    print("  %-22s %6s %8s %7s %8s  %s"
          % ("", "sess", "calls", "deny", "overrode", "override"))
    report(runs, "everything")
    report(bursts, "machine-paced bursts")
    total, over = report(kept, "HUMAN-PACED (reported)")

    if bursts:
        print("")
        print("  Excluded as machine-paced (>%d calls at >%.0f/min, no agent"
              % (BURST_CALLS, BURST_RATE))
        print("  messages). These are harness runs, not sessions:")
        for rid, r in sorted(bursts.items(), key=lambda kv: -kv[1]["deny"]):
            print("    %s  %4d calls in %5.1f min, %3d denials"
                  % (rid[:8], r["calls"], minutes(r), r["deny"]))
        share = sum(r["deny"] for r in bursts.values())
        alld = sum(r["deny"] for r in runs.values())
        print("    -> %d of %d denials, %.0f%% of the corpus"
              % (share, alld, 100.0 * share / alld if alld else 0))

    print("")
    print("  MODEL ATTRIBUTION (exact, by recomputed run_id)")
    print("    transcripts read           %d" % n_transcripts)
    print("    sessions newly attributed  %d" % hits)
    by = collections.Counter()
    dec = collections.Counter()
    for r in kept.values():
        key = r["model"] or "(no surviving transcript)"
        by[key] += 1
        dec[key] += r["deny"] + r["over"]
    for m, c in by.most_common():
        print("    %-34s %3d session(s), %3d decision(s)" % (m, c, dec[m]))

    print("")
    print("  WHICH RULES FIRED IN ORDINARY USE")
    rules = collections.Counter()
    for r in kept.values():
        rules.update(r["rules"])
    for rule, c in rules.most_common(10):
        print("    %-28s %d" % (rule, c))

    print("")
    print("  This is a CASE STUDY: one user, one repository, one project, and")
    print("  the user wrote the ruleset. It establishes that guard decisions")
    print("  arise in ordinary unscripted work. It does not establish a rate")
    print("  that generalizes, and the write-up must not imply one - %d"
          % total)
    print("  decisions is far too few for that.")
    print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
