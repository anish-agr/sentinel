#!/usr/bin/env python
"""What happened AFTER a rewrite: did the reroute escape the policy or not?"""

import argparse
import collections
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from stats import wilson  # noqa: E402
from archive import require_nested  # noqa: E402
import responses  # noqa: E402


def measure(archive=None):
    archive = archive or os.path.join("paper", "data", "denials")
    require_nested(archive, "rewrite_outcome.py (post-denial reach)")
    rows = responses.denials_in(archive)

    # Highest denial ordinal reached in each session. A denial at a later
    # ordinal means the ruleset still had jurisdiction after this event.
    last = {}
    for r in rows:
        s = r["session"]
        last[s] = max(last.get(s, 0), r["ordinal"])

    by_response = collections.defaultdict(lambda: {"n": 0, "followed": 0})
    for r in rows:
        cell = by_response[r["response"]]
        cell["n"] += 1
        if r["ordinal"] < last[r["session"]]:
            cell["followed"] += 1

    out = {"total": len(rows), "sessions": len(last), "by_response": {}}
    for key, cell in by_response.items():
        n, k = cell["n"], cell["followed"]
        lo, hi = wilson(k, n) if n else (0.0, 0.0)
        out["by_response"][key] = {
            "n": n, "followed": k, "escaped": n - k,
            "pct_followed": 100.0 * k / n if n else 0.0,
            "pct_escaped": 100.0 * (n - k) / n if n else 0.0,
            "lo": 100 * lo, "hi": 100 * hi}
    return out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--archive", default=os.path.join("paper", "data", "denials"))
    ap.add_argument("--ablation-arms", action="store_true",
                    help="pool the four arms that offer no override affordance")
    args = ap.parse_args()

    if args.ablation_arms:
        base = os.path.join("paper", "data")
        arms = ["denials-terse", "denials-explain", "denials-padded",
                "denials-defer"]
        tot = ref = 0
        print("")
        print("  REWRITE OUTCOME over the four arms with no override "
              "affordance")
        print("  the population the improvisation bound is stated over\n")
        for a in arms:
            path = os.path.join(base, a)
            if not os.path.isdir(path):
                print("    %-18s archive missing" % a)
                continue
            mm = measure(path)
            cell = mm["by_response"].get("Rewrote", {"n": 0, "followed": 0})
            n, k = cell["n"], cell["followed"]
            tot += n
            ref += k
            print("    %-18s %3d rewrites, %3d refused again, "
                  "%5.1f%% never refused again"
                  % (a.replace("denials-", ""), n, k,
                     100.0 * (n - k) / n if n else 0.0))
        if tot:
            lo, hi = wilson(tot - ref, tot)
            print("\n    pooled            %d rewrites, %d (%.1f%% "
                  "[%.1f, %.1f]) never refused again"
                  % (tot, tot - ref, 100.0 * (tot - ref) / tot,
                     100 * lo, 100 * hi))
            print("\n  An UPPER BOUND on escape, not an estimate: a rewrite "
                  "that never trips\n  a rule again is more often a safer "
                  "command than an unmonitored harm,\n  and guard events "
                  "cannot separate the two.")
        print("")
        return 0

    if not os.path.isdir(args.archive):
        print("  archive missing: %s" % args.archive)
        return 1

    m = measure(args.archive)
    print("")
    print("  AFTER THE REWRITE - did the reroute stay inside policy reach?")
    print("  %d denial events across %d sessions" % (m["total"], m["sessions"]))
    print("")
    print("  %-24s %6s %10s %11s   %s"
          % ("outcome of the denial", "n", "refused", "no further", "95% CI on"))
    print("  %-24s %6s %10s %11s   %s"
          % ("", "", "again", "denial", "'refused again'"))
    for key in responses.ORDER:
        c = m["by_response"].get(key)
        if not c:
            continue
        print("  %-24s %6d %10d %11d   %5.1f%% [%.1f, %.1f]"
              % (responses.LABEL[key][:24], c["n"], c["followed"],
                 c["escaped"], c["pct_followed"], c["lo"], c["hi"]))

    rw = m["by_response"].get("Rewrote")
    ov = m["by_response"].get("Overrode")
    if rw:
        print("")
        print("  Of %d rewrites, %d (%.1f%% [%.1f, %.1f]) were followed by another"
              % (rw["n"], rw["followed"], rw["pct_followed"], rw["lo"], rw["hi"]))
        print("  denial in the same session, so the reroute did not leave the")
        print("  ruleset's reach. The remaining %.1f%% is an UPPER BOUND on how"
              % rw["pct_escaped"])
        print("  often the oracle effect could have carried an agent out of")
        print("  jurisdiction - an upper bound, because a rewrite that never")
        print("  trips a rule again is far more often a safer command than an")
        print("  unmonitored harm, and our events cannot separate the two.")
    if rw and ov:
        print("")
        print("  For contrast, %.1f%% of overrides are followed by a further"
              % ov["pct_followed"])
        print("  denial. Rewriting and overriding therefore leave the agent in")
        print("  a similar relation to the guard, which is the argument against")
        print("  reading rewriting as escape and overriding as compliance.")
    print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
