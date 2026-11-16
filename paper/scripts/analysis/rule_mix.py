#!/usr/bin/env python
"""Does the model-disposition result survive the rule-mix confound?"""

import collections
import glob
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from stats import wilson  # noqa: E402

DATA = os.path.join("paper", "data")
ARMS = [("haiku", "denials-full"),
        ("sonnet", "denials-sonnet"),
        ("opus", "denials-opus")]

# A stratum this thin cannot carry a rate; standardizing over it manufactures
# precision. Reported separately rather than silently pooled.
MIN_STRATUM = 5


def decisions(archive):
    """(rule, overrode, session) per guard DECISION in one arm, and orphans."""
    out, orphans = [], 0
    base = os.path.join(DATA, archive)
    for f in sorted(glob.glob(os.path.join(base, "**", "events.jsonl"),
                              recursive=True)):
        sess = os.path.basename(os.path.dirname(f))
        pending = []                # indices into `out`, denials unmatched
        for line in io.open(f, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("kind") != "guard_decision":
                continue
            m = e.get("meta") or {}
            v = m.get("verdict")
            command = str(m.get("command") or "") or str(
                e.get("args_summary") or "")
            if v == "deny":
                pending.append(len(out))
                out.append([m.get("rule"), False, sess, command])
            elif v == "overridden":
                hit = None
                for k in range(len(pending) - 1, -1, -1):
                    if out[pending[k]][3] == command:
                        hit = k
                        break
                if hit is None:
                    orphans += 1
                    continue
                out[pending.pop(hit)][1] = True
    return [(r[0], r[1], r[2]) for r in out], orphans


def main():
    per, orphaned = {}, {}
    for model, archive in ARMS:
        if not os.path.isdir(os.path.join(DATA, archive)):
            print("  %s: archive missing (%s)" % (model, archive))
            return 1
        per[model], orphaned[model] = decisions(archive)

    pooled = collections.Counter()
    for rows in per.values():
        for rule, _o, _s in rows:
            pooled[rule] += 1
    total = sum(pooled.values())

    print("")
    print("  RULE-MIX CONFOUND: does the disposition result survive?")
    print("  %d decisions over %d models" % (total, len(per)))
    print("  A decision is a denial. The override that reverses one is the")
    print("  same decision going the other way, not a second decision.")
    if sum(orphaned.values()):
        print("  ORPHANED OVERRIDES (no denial to attach to): %s"
              % ", ".join("%s %d" % (m, n) for m, n in orphaned.items() if n))
    print("")

    # Crude rates first, which is what the paper currently reports.
    print("  %-8s %8s %9s %10s" % ("model", "events", "overrode", "crude"))
    crude = {}
    for model, _a in ARMS:
        rows = per[model]
        n = len(rows)
        k = sum(1 for _r, o, _s in rows if o)
        crude[model] = (k, n)
        lo, hi = wilson(k, n)
        print("  %-8s %8d %9d %9.1f%%  [%.1f, %.1f]"
              % (model, n, k, 100.0 * k / n if n else 0, 100 * lo, 100 * hi))

    # Which strata are usable in every arm. Standardizing over a rule some
    # model never met would invent a number for a cell that has no data.
    usable = [r for r in pooled
              if all(sum(1 for x, _o, _s in per[m] if x == r) >= MIN_STRATUM
                     for m, _a in ARMS)]
    usable.sort(key=lambda r: -pooled[r])
    covered = sum(pooled[r] for r in usable)

    print("")
    print("  Common strata: %d of %d rules, %d of %d decisions (%.0f%%)"
          % (len(usable), len(pooled), covered, total,
             100.0 * covered / total if total else 0))
    print("  A rule is usable only when every model met it at least %d times."
          % MIN_STRATUM)
    print("")

    print("  Per-rule override rate, and each model's exposure to that rule")
    print("  (* = outside the common strata, exposure only)")
    print("  %-26s %-18s %-18s %-18s" % ("rule", "haiku", "sonnet", "opus"))
    for r in sorted(pooled, key=lambda x: (x not in usable, -pooled[x])):
        cells = []
        for model, _a in ARMS:
            rows = [x for x in per[model] if x[0] == r]
            k = sum(1 for _r, o, _s in rows if o)
            n = len(rows)
            share = 100.0 * n / len(per[model]) if per[model] else 0
            cells.append("%5.1f%% (n=%-3d %4.1f%%)"
                         % (100.0 * k / n if n else 0, n, share))
        print("  %-26s %s" % (r if r in usable else r + " *",
                              " ".join(cells)))

    # Direct standardization to the pooled distribution over common strata.
    print("")
    print("  %-8s %12s %12s %10s"
          % ("model", "crude", "standardized", "shift"))
    results = {}
    for model, _a in ARMS:
        num = den = 0.0
        for r in usable:
            rows = [x for x in per[model] if x[0] == r]
            if not rows:
                continue
            rate = sum(1 for _r, o, _s in rows if o) / float(len(rows))
            w = pooled[r]
            num += w * rate
            den += w
        std = num / den if den else 0.0
        k, n = crude[model]
        c = k / float(n) if n else 0.0
        # Crude restricted to the same strata, so the shift is attributable to
        # reweighting rather than to changing which decisions are counted.
        sub = [x for x in per[model] if x[0] in set(usable)]
        ck = sum(1 for _r, o, _s in sub if o)
        cn = len(sub)
        crestr = ck / float(cn) if cn else 0.0
        results[model] = std
        print("  %-8s %11.1f%% %11.1f%% %+9.1f  (crude on common strata %.1f%%)"
              % (model, 100 * c, 100 * std, 100 * (std - crestr), 100 * crestr))

    print("")
    order_crude = sorted(crude, key=lambda m: -crude[m][0] / float(crude[m][1]))
    order_std = sorted(results, key=lambda m: -results[m])
    print("  ordering, crude        : %s" % " > ".join(order_crude))
    print("  ordering, standardized : %s" % " > ".join(order_std))
    print("")
    if order_crude == order_std:
        print("  THE ORDERING SURVIVES. The disposition claim is not an artifact")
        print("  of which rules each model happened to meet: reweighting every")
        print("  model onto a common rule distribution leaves the order intact.")
    else:
        print("  THE ORDERING DOES NOT SURVIVE. Result 7 as written attributes")
        print("  to the model what is partly attributable to rule exposure, and")
        print("  must be rewritten. Report the standardized figures.")
    print("")
    print("  Caveat that travels with this: standardization equalizes the rule")
    print("  mix, not the reason the mix differed. A model that avoids a rule")
    print("  by behaving cautiously earlier is different from one that never")
    print("  had the chance, and this cannot distinguish them.")
    print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
