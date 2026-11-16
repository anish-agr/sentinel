#!/usr/bin/env python
"""B1/B2/B3 and the paired reanalysis: the headline rates, with the"""

import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import (wilson, cluster_ci, cluster_diff_paired, tango,
                   Z95, Z99)  # noqa: E402
import own_action_space  # noqa: E402
import responses  # noqa: E402

DATA = os.path.join("paper", "data")
SEED = 20260816


def boot_ci(per_session, stat, reps, seed=SEED, levels=(0.95, 0.99)):
    """Cluster bootstrap: resample sessions with replacement, recompute stat."""
    import random
    r = random.Random(seed)
    idx = lambda: [r.randrange(len(per_session))
                   for _ in range(len(per_session))]
    vals, dropped = [], 0
    for _ in range(reps):
        draw = [per_session[i] for i in idx()]
        v = stat(draw)
        if v is None:
            dropped += 1
        else:
            vals.append(v)
    vals.sort()
    out = {}
    for lv in levels:
        a = (1.0 - lv) / 2.0
        lo = vals[int(a * len(vals))]
        hi = vals[min(len(vals) - 1, int((1.0 - a) * len(vals)))]
        out[lv] = (lo, hi)
    return out, dropped


def action_space(archive, reps):
    records, n_sessions = own_action_space.calls_in(archive)

    # Per-session mutating counts: (shell_refused, shell_calls,
    #                               tool_refused, tool_calls)
    per = collections.defaultdict(lambda: [0, 0, 0, 0])
    for c in records:
        if c["read_only"]:
            continue
        s = per[c["session"]]
        if c["space"] == "shell":
            s[1] += 1
            s[0] += 1 if c["refused"] else 0
        else:
            s[3] += 1
            s[2] += 1 if c["refused"] else 0
    rows = list(per.values())

    ks = sum(r[0] for r in rows)
    ns = sum(r[1] for r in rows)
    kt = sum(r[2] for r in rows)
    nt = sum(r[3] for r in rows)

    print("")
    print("Result 1b - mutating calls, %s (%d sessions, %d with a mutating call)"
          % (archive, n_sessions, len(rows)))
    print("  raw: shell %d/%d = %.1f%%   tools %d/%d = %.1f%%   gap %+.1f pts"
          % (ks, ns, 100.0 * ks / ns, kt, nt, 100.0 * kt / nt,
             100.0 * (ks / float(ns) - kt / float(nt))))

    for label, k, n, sel in (
            ("shell", ks, ns, lambda r: (r[0], r[1])),
            ("tools", kt, nt, lambda r: (r[2], r[3]))):
        l95, u95 = wilson(k, n)
        l99, u99 = wilson(k, n, Z99)
        p, cl, cu, deff, K, _M = cluster_ci([sel(r) for r in rows])
        _p, cl99, cu99, _d, _K, _M2 = cluster_ci([sel(r) for r in rows], Z99)

        def rate(draw, s=sel):
            m = sum(s(r)[1] for r in draw)
            return 100.0 * sum(s(r)[0] for r in draw) / m if m else None
        bt, dropped = boot_ci(rows, rate, reps)
        print("  %-6s Wilson95 [%4.1f, %4.1f]  Wilson99 [%4.1f, %4.1f]"
              % (label, 100 * l95, 100 * u95, 100 * l99, 100 * u99))
        print("         clustered95 [%4.1f, %4.1f] deff %.2f (K=%d)"
              "  clustered99 [%4.1f, %4.1f]"
              % (100 * cl, 100 * cu, deff, K, 100 * cl99, 100 * cu99))
        print("         boot95 [%4.1f, %4.1f]  boot99 [%4.1f, %4.1f]%s"
              % (bt[0.95][0], bt[0.95][1], bt[0.99][0], bt[0.99][1],
                 "  (%d degenerate draws dropped)" % dropped if dropped else ""))

    # The paired difference - the primary interval for the paper.
    p1, p2, d, lo, hi, K = cluster_diff_paired([tuple(r) for r in rows])
    _1, _2, _d, lo99, hi99, _K = cluster_diff_paired(
        [tuple(r) for r in rows], Z99)

    def gap(draw):
        m1 = sum(r[1] for r in draw)
        m2 = sum(r[3] for r in draw)
        if not m1 or not m2:
            return None
        return 100.0 * (sum(r[0] for r in draw) / float(m1)
                        - sum(r[2] for r in draw) / float(m2))
    bt, dropped = boot_ci(rows, gap, reps)
    print("  gap    paired-clustered95 [%+5.1f, %+5.1f]"
          "  paired-clustered99 [%+5.1f, %+5.1f]  (K=%d)"
          % (100 * lo, 100 * hi, 100 * lo99, 100 * hi99, K))
    print("         boot95 [%+5.1f, %+5.1f]  boot99 [%+5.1f, %+5.1f]%s"
          % (bt[0.95][0], bt[0.95][1], bt[0.99][0], bt[0.99][1],
             "  (%d degenerate draws dropped)" % dropped if dropped else ""))

    both = [r for r in rows if r[1] > 0 and r[3] > 0]
    b = sum(1 for r in both if r[0] > 0 and r[2] == 0)
    c = sum(1 for r in both if r[0] == 0 and r[2] > 0)
    n_pairs = len(both)
    t95 = tango(b, c, n_pairs)
    t99 = tango(b, c, n_pairs, Z99)
    print("  session-level any-refusal pairs: n=%d, shell-only %d,"
          " tools-only %d" % (n_pairs, b, c))
    print("         Tango95 [%+5.1f, %+5.1f]  Tango99 [%+5.1f, %+5.1f]"
          % (100 * t95[0], 100 * t95[1], 100 * t99[0], 100 * t99[1]))


def post_denial(archive, reps):
    rows = responses.denials_in(os.path.join(DATA, archive))
    per = collections.defaultdict(list)
    for r in rows:
        per[r["session"]].append(r["response"])
    sess = list(per.values())
    n = len(rows)

    print("")
    print("Result 3 - post-denial distribution, %s (%d events, %d sessions)"
          % (archive, n, len(sess)))
    print("  %-30s %-22s %-22s %-22s %s"
          % ("", "Wilson95", "clustered95 (deff)", "boot95", "Wilson99"))
    for key in responses.ORDER:
        k = sum(1 for r in rows if r["response"] == key)
        l95, u95 = wilson(k, n)
        l99, u99 = wilson(k, n, Z99)
        cc = [(sum(1 for x in s if x == key), len(s)) for s in sess]
        p, cl, cu, deff, K, _M = cluster_ci(cc)

        def share(draw, kk=key):
            m = sum(len(s) for s in draw)
            return (100.0 * sum(1 for s in draw for x in s if x == kk) / m
                    if m else None)
        bt, _dropped = boot_ci(sess, share, reps)
        print("  %-30s %4.1f [%4.1f, %4.1f]    [%4.1f, %4.1f] (%.2f)"
              "    [%4.1f, %4.1f]    [%4.1f, %4.1f]"
              % (responses.LABEL[key], 100.0 * k / n, 100 * l95, 100 * u95,
                 100 * cl, 100 * cu, deff,
                 bt[0.95][0], bt[0.95][1], 100 * l99, 100 * u99))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--archive", default=os.path.join("paper", "data",
                                                      "denials"))
    ap.add_argument("--reps", type=int, default=10000)
    args = ap.parse_args()

    action_space(args.archive, args.reps)
    post_denial("denials", args.reps)

    print("")
    print("For the paper: the paired-clustered interval is the primary form")
    print("for the action-space gap (it is the estimand the within-session")
    print("design measures); Wilson stays in tables for comparability, and")
    print("the bootstrap is the robustness footnote. Where deff <= 1.1 the")
    print("published widths were approximately right and say so.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
