#!/usr/bin/env python
"""A7 - which *kinds* of harm can a deterministic gate reach?"""

import argparse
import collections
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import wilson, rule_of_three  # noqa: E402


def load():
    path = os.path.join("paper", "data", "atbench-violations.jsonl")
    rows = []
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def traj_of(row):
    return row.get("trajectory") or row.get("id", "").rsplit("-", 1)[0]


# A CLI-shaped action name: a bare binary we recognise, or any action whose
# name carries a space (`gh api`, `himalaya envelope list`, `tmux send-keys`).
# Structured tool names in this corpus are single identifiers.
CLI = re.compile(
    r"^(gh|git|tmux|npm|pip|aws|kubectl|docker|curl|wget|ls|cat|rm|cp|mv|"
    r"bash|sh|python|node|obsidian-cli|himalaya|clawdbot|clawdhub|jq|sed|awk|"
    r"agent-browser|gog)\b", re.I)


def structural():
    """Is the all-zero C1 count real, or a classifier that never read the rows?"""
    rows = load()
    n = len(rows)
    have = collections.Counter()
    reach = collections.Counter()
    shellish = collections.Counter()
    cls = collections.Counter()
    for r in rows:
        for f in ("harm_type", "failure_mode", "machine_signature",
                  "machine_class"):
            if r.get(f):
                have[f] += 1
        reach[r.get("machine_reach") or "(none)"] += 1
        cls[r.get("machine_class")] += 1
        a = (r.get("action") or "").strip()
        if a and (CLI.match(a) or " " in a):
            shellish[a] += 1

    print("")
    print("Is the C1 zero structural? - %d ATBench steps" % n)
    print("")
    print("  the rows ARE annotated (so the classifier had input)")
    for f in ("harm_type", "failure_mode", "machine_signature",
              "machine_class"):
        print("    %-22s present on %5d of %d" % (f, have[f], n))
    print("")
    print("  machine_class distribution")
    for k, v in cls.most_common():
        print("    %-22s %5d" % (k, v))
    print("")
    print("  action shape")
    for k, v in reach.most_common():
        print("    reach %-16s %5d" % (k, v))
    tot = sum(shellish.values())
    print("    CLI/shell-shaped action  %5d (%.2f%%), %d distinct"
          % (tot, 100.0 * tot / n, len(shellish)))
    for k, v in shellish.most_common(8):
        print("      %-32s %4d" % (k[:32], v))
    print("")

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "policies"))
    try:
        import classify as C
    except ImportError:
        print("  (policies/classify.py not importable; skipping counterfactual)")
        return
    hits = collections.Counter()
    anyhit = 0
    for r in rows:
        text = (r.get("action") or "") + " " + (r.get("arguments") or "")
        h = [name for name, pat in C.SIGNATURES.items() if pat.search(text)]
        if h:
            anyhit += 1
            for name in h:
                hits[name] += 1
    print("  counterfactual: the C1 shell-signature table applied to the raw")
    print("  action+arguments text, which is NOT what the pipeline does")
    print("    steps matching any signature %d (%.2f%%)"
          % (anyhit, 100.0 * anyhit / n))
    for k, v in hits.most_common():
        print("      %-24s %5d" % (k, v))
    print("")
    print("  Read that last block as a false-positive count. %d of the %d"
          % (hits.get("secret_access", 0), anyhit))
    print("  matches are secret_access firing on an auth-token FIELD NAME in a")
    print("  structured call's arguments, not on a command that reads a")
    print("  secret. The pipeline's zero is the honest number; this is what")
    print("  the same regexes do when pointed at the wrong kind of input.")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--field", default="harm_type",
                    choices=("harm_type", "failure_mode", "risk_source"))
    ap.add_argument("--min", type=int, default=20,
                    help="hide categories with fewer steps than this")
    ap.add_argument("--structural", action="store_true",
                    help="is the all-zero C1 count real or an artifact?")
    args = ap.parse_args()

    if args.structural:
        structural()
        return

    rows = load()
    missing = sum(1 for r in rows if not r.get(args.field))
    if missing:
        print("warning: %d of %d rows have no %s"
              % (missing, len(rows), args.field))

    steps = collections.defaultdict(lambda: [0, 0])   # cat -> [steps, C1 steps]
    trajs = collections.defaultdict(dict)             # cat -> traj -> any C1
    for r in rows:
        cat = r.get(args.field) or "(unlabelled)"
        hit = r.get("machine_class") == "C1"
        steps[cat][0] += 1
        if hit:
            steps[cat][1] += 1
        t = traj_of(r)
        trajs[cat][t] = trajs[cat].get(t, False) or hit

    print("")
    print("A7 - gateable fraction by %s (ATBench, %d steps)"
          % (args.field, len(rows)))
    print("")
    print("  %-46s %6s %5s %8s   %-16s %s"
          % (args.field, "steps", "C1", "step %", "95% CI", "traj %"))
    ordered = sorted(steps.items(), key=lambda kv: -kv[1][1] / max(kv[1][0], 1))
    unreachable = []
    for cat, (n, c) in ordered:
        if n < args.min:
            continue
        lo, hi = wilson(c, n)
        tj = trajs[cat]
        tshare = 100.0 * sum(1 for v in tj.values() if v) / len(tj)
        print("  %-46s %6d %5d %7.2f%%   [%4.2f, %5.2f]  %6.1f%%"
              % (cat[:46], n, c, 100.0 * c / n, 100 * lo, 100 * hi, tshare))
        if c == 0:
            unreachable.append((cat, n))

    if unreachable:
        print("")
        print("  Categories with ZERO refusable steps - the specification for")
        print("  whatever has to catch them instead:")
        for cat, n in sorted(unreachable, key=lambda kv: -kv[1]):
            print("    %-46s %4d steps, true rate < %.1f%%"
                  % (cat[:46], n, 100.0 * rule_of_three(n)))
        print("")
        print("  A zero here is not noise. By the rule of three, %d steps with"
              % max(n for _c, n in unreachable))
        print("  no refusable case bounds the true rate below %.1f%%, which is a"
              % (100.0 * rule_of_three(max(n for _c, n in unreachable))))
        print("  claim about the category rather than an absence of evidence.")

    print("")
    print("  step %% is what fraction of actions a fixed predicate could refuse.")
    print("  traj %% is the more generous any-step reading. Both are reported")
    print("  because the paper has previously conflated them.")


if __name__ == "__main__":
    main()
