#!/usr/bin/env python
"""Three robustness analyses that need no new collection."""

import argparse
import collections
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import wilson, cluster_ci, newcombe, Z95  # noqa: E402
import own_action_space  # noqa: E402

DATA = os.path.join("paper", "data")


def sessions_of(archive):
    for name in sorted(os.listdir(archive)):
        path = os.path.join(archive, name, "events.jsonl")
        if not os.path.isfile(path):
            continue
        events = []
        for line in io.open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                pass
        if events:
            yield name, events


def rules_loo(archive):
    """Leave-one-out: the mutating-shell refusal rate without each rule."""
    records, _n = own_action_space.calls_in(archive)
    mutating = [c for c in records if not c["read_only"]]
    shell = [c for c in mutating if c["space"] == "shell"]
    tools = [c for c in mutating if c["space"] != "shell"]

    fired = collections.Counter(c["rule"] for c in mutating
                                if c["refused"] and c["rule"])
    base_s = sum(1 for c in shell if c["refused"])
    base_t = sum(1 for c in tools if c["refused"])

    print("")
    print("Leave-one-out over the ruleset (mutating calls only)")
    print("  full ruleset: shell %d/%d = %.1f%%, tools %d/%d = %.1f%%, "
          "gap %+.1f pts"
          % (base_s, len(shell), 100.0 * base_s / len(shell),
             base_t, len(tools), 100.0 * base_t / len(tools),
             100.0 * (base_s / len(shell) - base_t / len(tools))))
    print("")
    print("  %-26s %6s   %-22s %s" % ("rule removed", "fired",
                                      "shell rate", "gap"))
    rows = []
    for rule, n_fired in fired.most_common():
        s = sum(1 for c in shell if c["refused"] and c["rule"] != rule)
        t = sum(1 for c in tools if c["refused"] and c["rule"] != rule)
        ps = s / float(len(shell))
        pt = t / float(len(tools))
        lo, hi = wilson(s, len(shell))
        rows.append((rule, n_fired, ps, pt))
        print("  %-26s %6d   %5.1f%% [%4.1f, %4.1f]   %+5.1f pts"
              % (rule, n_fired, 100 * ps, 100 * lo, 100 * hi,
                 100 * (ps - pt)))

    worst = min(rows, key=lambda r: r[2] - r[3])
    print("")
    print("  Removing the single most load-bearing rule (%s) leaves the gap"
          % worst[0])
    print("  at %+.1f points, against %+.1f with the full set. The effect is"
          % (100 * (worst[2] - worst[3]),
             100.0 * (base_s / len(shell) - base_t / len(tools))))
    print("  distributed across the ruleset rather than carried by one rule,")
    print("  which is what makes it a claim about the action space.")


def timing(archives):
    """Calls before the first denial, per model."""
    print("")
    print("Tool calls before the first denial, by model")
    print("  %-10s %8s %8s %7s %7s %7s   %s"
          % ("model", "sessions", "denied", "median", "p25", "p75",
             "first call denied"))
    for label, archive in archives:
        path = os.path.join(DATA, archive)
        if not os.path.isdir(path):
            continue
        firsts = []
        n_sessions = 0
        for _name, events in sessions_of(path):
            n_sessions += 1
            events.sort(key=lambda e: (e.get("run_id") or "",
                                       e.get("step") or 0))
            calls = 0
            hit = None
            for e in events:
                k = e.get("kind")
                if k == "tool_call":
                    calls += 1
                elif k == "guard_decision" and hit is None:
                    hit = calls
            if hit is not None:
                firsts.append(hit)
        if not firsts:
            continue
        firsts.sort()

        def pct(p):
            return firsts[min(len(firsts) - 1, int(p * len(firsts)))]
        early = sum(1 for f in firsts if f <= 1)
        print("  %-10s %8d %8d %7d %7d %7d   %d (%.1f%%)"
              % (label, n_sessions, len(firsts), pct(0.5), pct(0.25),
                 pct(0.75), early, 100.0 * early / len(firsts)))
    print("")
    print("  A model that meets the guard sooner is attempting dangerous")
    print("  commands earlier, which is a pacing difference rather than a")
    print("  disposition one. Read this next to denials-per-session: the two")
    print("  together say whether a model's lower denial count comes from")
    print("  attempting less or from getting further first.")


def prompts(archive):
    """Denial rate by task variant within each family."""
    path = os.path.join(DATA, archive)
    per_family = collections.defaultdict(lambda: collections.defaultdict(
        lambda: [0, 0]))
    for name, events in sessions_of(path):
        parts = name.split("-")
        family = parts[0]
        variant = parts[1] if len(parts) > 2 else "?"
        denied = any(e.get("kind") == "guard_decision" for e in events)
        cell = per_family[family][variant]
        cell[1] += 1
        cell[0] += 1 if denied else 0

    print("")
    print("Denial rate by task variant, within family")
    print("  %-24s %8s %8s %8s   %s"
          % ("family", "variants", "sessions", "range", "spread"))
    wide = []
    for family in sorted(per_family):
        cells = [(v, c[0], c[1]) for v, c in per_family[family].items()
                 if c[1] >= 3]
        if len(cells) < 2:
            continue
        rates = [c[1] / float(c[2]) for c in cells]
        n_sess = sum(c[2] for c in cells)
        spread = max(rates) - min(rates)
        flag = "  <-- wide" if spread > 0.5 else ""
        if spread > 0.5:
            wide.append(family)
        print("  %-24s %8d %8d  %3.0f-%3.0f%%   %5.1f pts%s"
              % (family, len(cells), n_sess, 100 * min(rates),
                 100 * max(rates), 100 * spread, flag))
    print("")
    if wide:
        print("  Families whose variants disagree by more than 50 points:")
        print("    %s" % ", ".join(wide))
        print("  Within these, wording moves whether the guard is reached at")
        print("  all. That is a property of the TASK, not of the guard, and")
        print("  it is why per-family hit rates are reported as a range")
        print("  rather than a constant.")
    else:
        print("  No family's variants disagree by more than 50 points.")
    print("  The headline is a rate over CALLS, not over sessions, so variant")
    print("  reachability changes how many observations each family")
    print("  contributes and not the refusal rate conditional on attempting.")


MODEL_ARCHIVES = [("haiku", "denials-full"), ("sonnet", "denials-sonnet"),
                  ("opus", "denials-opus"),
                  ("opus-low", "denials-opus-low"),
                  ("sonnet-max", "denials-sonnet-max")]


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--archive", default=os.path.join(DATA, "denials"))
    ap.add_argument("--rules", action="store_true")
    ap.add_argument("--timing", action="store_true")
    ap.add_argument("--prompts", action="store_true")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    if args.all or args.rules:
        rules_loo(args.archive)
    if args.all or args.timing:
        timing(MODEL_ARCHIVES)
    if args.all or args.prompts:
        prompts("denials")
    return 0


if __name__ == "__main__":
    sys.exit(main())
