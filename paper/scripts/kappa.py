#!/usr/bin/env python
"""Agreement between our classifier and independent raters."""

import argparse
import collections
import io
import json
import os
import sys

DATA = os.path.join("paper", "data")
CORPUS = os.path.join(DATA, "atbench-violations.jsonl")
RATERS = [
    ("gemini", os.path.join(DATA, "atbench-violations.jsonl.labels-gemini.jsonl"),
     "gemini_class"),
    ("operator", os.path.join(DATA, "atbench-violations.jsonl.labels.jsonl"),
     "human_class"),
]

# The operator's tool records A/B/C/D; the corpus records C0..C3.
LETTER = {"A": "C1", "B": "C2", "C": "C3", "D": "C0"}


def load(path):
    out = []
    if not os.path.exists(path):
        return out
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def normalise(v):
    if not v:
        return None
    v = str(v).strip().upper()
    if v in LETTER:
        return LETTER[v]
    return v if v in ("C0", "C1", "C2", "C3") else None


def kappa(pairs):
    """Cohen's kappa. Returns (kappa, raw agreement, n)."""
    n = len(pairs)
    if not n:
        return 0.0, 0.0, 0
    labels = sorted({a for a, _ in pairs} | {b for _, b in pairs})
    agree = sum(1 for a, b in pairs if a == b)
    po = agree / float(n)
    ca = collections.Counter(a for a, _ in pairs)
    cb = collections.Counter(b for _, b in pairs)
    pe = sum((ca[l] / float(n)) * (cb[l] / float(n)) for l in labels)
    k = (po - pe) / (1 - pe) if pe < 1 else 1.0
    return k, po, n


def gwet_ac1(pairs):
    """Gwet's AC1 (Gwet 2008). Returns (ac1, raw agreement, n)."""
    n = len(pairs)
    if not n:
        return 0.0, 0.0, 0
    labels = sorted({a for a, _ in pairs} | {b for _, b in pairs})
    po = sum(1 for a, b in pairs if a == b) / float(n)
    ca = collections.Counter(a for a, _ in pairs)
    cb = collections.Counter(b for _, b in pairs)
    pe = sum(
        ((ca[l] + cb[l]) / (2.0 * n)) * (1.0 - (ca[l] + cb[l]) / (2.0 * n))
        for l in labels
    ) / max(1, len(labels) - 1)
    return ((po - pe) / (1.0 - pe) if pe < 1 else 1.0, po, n)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--show-all", action="store_true",
                    help="print every disagreement, not the first 25")
    args = ap.parse_args()

    ours = {}
    for r in load(CORPUS):
        rid = r.get("id")
        if rid:
            ours[rid] = (r.get("machine_class"), r)

    any_rater = False
    for name, path, field in RATERS:
        rows = load(path)
        if not rows:
            print("")
            print("  %-9s no labels at %s" % (name, path))
            continue
        any_rater = True

        pairs, disagreements = [], []
        for r in rows:
            rid = r.get("id")
            if rid not in ours:
                continue
            mine = normalise(ours[rid][0])
            theirs = normalise(r.get(field))
            if not mine or not theirs:
                continue
            pairs.append((mine, theirs))
            if mine != theirs:
                disagreements.append((rid, mine, theirs, r, ours[rid][1]))

        k, po, n = kappa(pairs)
        ac1, _po1, _n1 = gwet_ac1(pairs)
        print("")
        print("=" * 74)
        print("  %s vs our classifier" % name)
        print("  n = %d   raw agreement %.1f%%   Gwet's AC1 %.3f  (%s)"
              % (n, 100 * po, ac1, interpret(ac1)))
        print("  Cohen's kappa %.3f (%s) - secondary; see gwet_ac1 docstring"
              % (k, interpret(k)))

        print("")
        print("  confusion (rows = ours, cols = %s)" % name)
        labels = sorted({a for a, _ in pairs} | {b for _, b in pairs})
        grid = collections.Counter(pairs)
        print("      " + "".join("%7s" % l for l in labels))
        for a in labels:
            print("  %-4s" % a + "".join("%7d" % grid[(a, b)] for b in labels))

        print("")
        print("  per class (ours -> agreement)")
        for l in labels:
            sub = [(a, b) for a, b in pairs if a == l]
            if sub:
                ag = sum(1 for a, b in sub if a == b)
                print("    %-4s n=%4d  agreed %5.1f%%" % (l, len(sub), 100.0 * ag / len(sub)))

        if disagreements:
            print("")
            print("  %d disagreement(s). These are what you adjudicate - a"
                  % len(disagreements))
            print("  kappa without them read is a number, not a validation.")
            print("")
            show = disagreements if args.show_all else disagreements[:25]
            for rid, mine, theirs, rrow, crow in show:
                print("  %s" % rid)
                print("    ours %-3s   %s %-3s   %s"
                      % (mine, name, theirs, (rrow.get("reason") or "")[:80]))
                print("    step: %s" % (str(crow.get("args_summary") or "")[:110]))
            if not args.show_all and len(disagreements) > 25:
                print("  ... %d more, --show-all for the rest"
                      % (len(disagreements) - 25))

    if not any_rater:
        print("")
        print("No independent labels yet. Produce them with:")
        print("  python paper/scripts/gemini_label.py --n 120")
        return 0

    print("")
    print("=" * 74)
    print("  What this can and cannot claim.")
    print("")
    print("  CAN: our classifier agrees with an independent rater that did not")
    print("  write it, at the kappa above, on a stratified sample.")
    print("")
    print("  CANNOT: that the classifier is correct. Two raters can share a")
    print("  misreading of the rubric. The disagreements are the evidence that")
    print("  matters, and a human adjudicating them is what turns this from a")
    print("  statistic into a validation.")
    return 0


def interpret(k):
    if k < 0.0:
        return "worse than chance"
    if k < 0.20:
        return "slight"
    if k < 0.40:
        return "fair"
    if k < 0.60:
        return "moderate"
    if k < 0.80:
        return "substantial"
    return "almost perfect"


if __name__ == "__main__":
    sys.exit(main())
