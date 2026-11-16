#!/usr/bin/env python
"""A5 + A8 - how much does the ceiling depend on choices I made by hand?"""

import collections
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import wilson  # noqa: E402

DATA = os.path.join("paper", "data")

ARGUABLE = ["send", "create", "update", "add", "email", "message", "post",
            "upload", "set", "sms", "write", "transfer", "patch", "store",
            "insert", "push"]


def load(name):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return []
    out = []
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def traj_of(row):
    return row.get("trajectory") or row.get("id", "").rsplit("-", 1)[0]


def rates(rows, c1_signatures=None):
    """(step C1 count, step total, trajectory-any-C1 count, trajectory total)."""
    steps = len(rows)
    c1 = 0
    by_traj = collections.defaultdict(bool)
    for r in rows:
        if c1_signatures is None:
            hit = r.get("machine_class") == "C1"
        else:
            hit = (r.get("machine_class") == "C1"
                   or r.get("machine_signature") in c1_signatures)
        if hit:
            c1 += 1
        by_traj[traj_of(r)] = by_traj[traj_of(r)] or hit
    return c1, steps, sum(1 for v in by_traj.values() if v), len(by_traj)


def reach_by_class(name):
    """(grid, total rows, rows carrying no reach label), for the 2x2."""
    rows = load(name)
    grid = collections.Counter()
    unlabelled = 0
    for r in rows:
        reach = r.get("machine_reach")
        if reach not in ("Local", "External"):
            unlabelled += 1
            continue
        grid[(reach, r.get("machine_class") or "?")] += 1
    return grid, len(rows), unlabelled


def step_and_trajectory_rates():
    """Per-corpus C1 share at both levels, for the composition table."""
    out = []
    for name, label in (("violations.jsonl", "StepShield"),
                        ("atbench-violations.jsonl", "ATBench (pooled)"),
                        ("rjudge-violations.jsonl", "R-Judge")):
        rows = load(name)
        if not rows:
            continue
        c1, steps, tr_c1, trajs = rates(rows)
        out.append((label, steps, c1, trajs, tr_c1))
    return out


def main():
    rows = load("atbench-violations.jsonl")
    if not rows:
        print("  no atbench-violations.jsonl: this analysis has nothing to")
        print("  read and would report zero. Refusing rather than printing it.")
        return 1

    # ---------------------------------------------------------------- A5 ----
    print("")
    print("A5 - verb-table sensitivity on ATBench (%d steps)" % len(rows))
    print("")
    base_c1, steps, base_tr, trajs = rates(rows)
    lo, hi = wilson(base_c1, steps)
    print("  as published        step %5.2f%% [%.2f, %.2f]   trajectory %5.2f%%"
          % (100.0 * base_c1 / steps, 100 * lo, 100 * hi,
             100.0 * base_tr / trajs))
    print("")
    print("  moving one verb from C2 to C1:")
    print("  %-12s %6s   %-22s %-14s" % ("verb", "rows", "step-level", "trajectory"))

    envelope = []
    counts = collections.Counter(r.get("machine_signature") for r in rows
                                 if r.get("machine_class") == "C2")
    for verb in ARGUABLE:
        n = counts.get(verb, 0)
        if not n:
            continue
        c1, st, tr, tt = rates(rows, {verb})
        envelope.append((100.0 * c1 / st, verb))
        print("  %-12s %6d   %5.2f%%  (%+.2f)      %5.2f%%  (%+.2f)"
              % (verb, n, 100.0 * c1 / st, 100.0 * (c1 - base_c1) / st,
                 100.0 * tr / tt, 100.0 * (tr - base_tr) / tt))

    all_c1, st, all_tr, tt = rates(rows, set(ARGUABLE))
    all_rows = sum(1 for r in rows
                   if r.get("machine_class") == "C2"
                   and r.get("machine_signature") in set(ARGUABLE))
    print("")
    print("  ALL of them at once %5d   step %5.2f%%   trajectory %5.2f%%"
          % (all_rows, 100.0 * all_c1 / st, 100.0 * all_tr / tt))
    if envelope:
        worst = max(envelope)
        print("")
        print("  Envelope: the step-level ceiling sits between %.2f%% and %.2f%%"
              % (100.0 * base_c1 / steps, worst[0]))
        print("  under any single verb reassignment, and reaches %.2f%% if every"
              % (100.0 * all_c1 / st))
        print("  arguable verb is moved. The largest single lever is `%s`."
              % worst[1])
        print("")
        print("  This is the honest answer to \"your taxonomy is arbitrary\", and")
        print("  the answer is bad for the cross-corpus comparison: moving every")
        print("  arguable verb takes the step-level ceiling from %.2f%% to %.2f%%,"
              % (100.0 * base_c1 / steps, 100.0 * all_c1 / st))
        print("  which is the same order as the shell rate rather than far below")
        print("  it. Result 1 is therefore sensitive to a judgement call, and no")
        print("  amount of arguing about verbs settles it.")
        print("")
        print("  What survives untouched is Result 1b. The controlled")
        print("  within-session measurement asks whether a ruleset written before")
        print("  the campaign actually fired, so it uses no verb table, no")
        print("  taxonomy, and no judgement of mine. That is now the load-bearing")
        print("  result, and this sensitivity is the strongest argument for why.")

    by_id = {r.get("id"): r for r in rows}
    for name, label in (("atbench-violations.jsonl.labels-consensus.jsonl",
                         "development"),
                        ("atbench-violations.jsonl.labels-holdout.jsonl",
                         "held-out")):
        panel = load(name)
        if not panel:
            continue
        hit = [p for p in panel
               if (by_id.get(p.get("id")) or {}).get("machine_class") == "C2"
               and (by_id.get(p.get("id")) or {}).get("machine_signature")
               in set(ARGUABLE)]
        got = collections.Counter(p.get("consensus") for p in hit)
        resolved = sum(v for k, v in got.items() if k)
        print("")
        print("  %s panel on arguable-verb items: %d rated, %d resolved, "
              "C2 %d, C1 %d, C3 %d"
              % (label, len(hit), resolved, got.get("C2", 0),
                 got.get("C1", 0), got.get("C3", 0)))

    # ---------------------------------------------------------------- A8 ----
    for name, label in (("atbench-violations.jsonl", "ATBench"),
                        ("rjudge-violations.jsonl", "R-Judge"),
                        ("violations.jsonl", "StepShield")):
        rs = load(name)
        if not rs:
            continue
        if not any(r.get("machine_reach") for r in rs):
            print("\nA8 - %s carries no reach column; skipped" % label)
            continue
        print("")
        print("A8 - reversibility x decidability, %s (%d steps)" % (label, len(rs)))
        grid = collections.Counter((r.get("machine_reach") or "?",
                                    r.get("machine_class") or "?") for r in rs)
        reaches = sorted(set(k[0] for k in grid))
        classes = sorted(set(k[1] for k in grid))
        print("  %-12s" % "" + "".join("%9s" % c for c in classes))
        for reach in reaches:
            line = "  %-12s" % reach
            for c in classes:
                line += "%9d" % grid[(reach, c)]
            print(line)
        n = len(rs)
        residual = sum(v for (reach, c), v in grid.items()
                       if reach == "External" and c in ("C2", "C3"))
        rlo, rhi = wilson(residual, n)
        print("  residual (External and not C1): %d/%d = %.1f%% [%.1f, %.1f]"
              % (residual, n, 100.0 * residual / n, 100 * rlo, 100 * rhi))
        if len(reaches) == 1:
            print("  NOTE: every step is %s, so this is a 1xN table, not a 2x2."
                  % reaches[0])
            print("  A local-checkpoint column does not exist for this corpus and")
            print("  the paper must not draw one.")


if __name__ == "__main__":
    # sys.exit, not a bare call: `main` returns 1 when the corpus it
    # reads is absent, and a bare call throws that away.
    sys.exit(main())
