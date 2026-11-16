#!/usr/bin/env python
"""The operating point: base rate, recall, false-positive rate, precision."""

import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from stats import wilson  # noqa: E402

FIGURES = os.path.join("paper", "figures")

# The two runs the paper quotes: the whole corpus, and the split StepShield's
# own headline is measured on.
RUNS = [("full corpus", "ceiling-full.txt"),
        ("held-out split", "ceiling-holdout.txt")]

# The hypothetical deployment prevalences the paper argues over. The measured
# rate of the corpus in hand is prepended to these, not typed into them.
HYPOTHETICAL = (0.02, 0.005, 0.001)


class Malformed(Exception):
    """The run record is not the shape this arithmetic assumes."""


def parse(path):
    """Every count the operating point needs, out of one run's record."""
    text = io.open(path, encoding="utf-8").read()

    census = re.search(
        r"(\d+) trajectories \((\d+) rogue, (\d+) benign\)", text)
    if not census:
        raise Malformed("no 'N trajectories (R rogue, B benign)' census")
    total, rogue, benign = (int(g) for g in census.groups())

    # `  C1   deterministic (a predicate exists)    139   18.6%   caught 73`
    classes = [(m.group(1), int(m.group(2)), int(m.group(3)))
               for m in re.finditer(
                   r"^\s+(C\d)\s+.+?\s{2,}(\d+)\s+[\d.]+%\s+caught (\d+)\s*$",
                   text, re.M)]
    if not classes:
        raise Malformed("no enforceability composition block")

    reach = re.search(r"refused\s+(\d+) of (\d+)\s+\(", text)
    if not reach:
        raise Malformed("no 'refused K of N' line")
    ceiling_caught, ceiling_n = int(reach.group(1)), int(reach.group(2))
    stray = re.search(r"refusals outside the reachable class\s+(\d+)", text)
    outside = int(stray.group(1)) if stray else 0

    fp = re.search(
        r"(\d+) of (\d+) benign trajectories had something refused", text)
    if not fp:
        raise Malformed("no false-positive line")
    fp_num, fp_den = int(fp.group(1)), int(fp.group(2))

    # THREE CROSS-CHECKS, because this file is parsed rather than computed and
    # a partial parse is the failure mode that would go unnoticed.
    if sum(n for _c, n, _k in classes) != rogue:
        raise Malformed("class counts sum to %d, census says %d rogue"
                        % (sum(n for _c, n, _k in classes), rogue))
    caught = sum(k for _c, _n, k in classes)
    if ceiling_caught + outside != caught:
        raise Malformed(
            "%d C1 catches + %d outside != %d catches over all classes"
            % (ceiling_caught, outside, caught))
    if fp_den != benign:
        raise Malformed("false-positive denominator %d, census says %d benign"
                        % (fp_den, benign))
    c1 = dict((c, n) for c, n, _k in classes).get("C1")
    if c1 != ceiling_n:
        raise Malformed("C1 count %s, ceiling denominator %d"
                        % (c1, ceiling_n))

    return {"total": total, "rogue": rogue, "benign": benign,
            "classes": classes, "caught": caught,
            "ceiling_n": ceiling_n, "ceiling_caught": ceiling_caught,
            "fp_num": fp_num, "fp_den": fp_den}


def precision_at(base, recall, fpr):
    tp = base * recall
    fp = (1.0 - base) * fpr
    return tp / (tp + fp) if tp + fp else 0.0


def report(label, path, run):
    total, rogue, benign = run["total"], run["rogue"], run["benign"]
    base = rogue / float(total)
    recall = run["caught"] / float(rogue)
    fpr = run["fp_num"] / float(run["fp_den"])
    blo, bhi = wilson(rogue, total)
    rlo, rhi = wilson(run["caught"], rogue)
    flo, fhi = wilson(run["fp_num"], run["fp_den"])

    print("")
    print("  %s  (%s)" % (label.upper(), path))
    print("  %s" % ("-" * (len(label) + len(path) + 4)))
    print("  trajectories  %d  =  %d rogue + %d benign"
          % (total, rogue, benign))
    print("  base rate     %.1f%%  [%.1f, %.1f]   (%d/%d)"
          % (100 * base, 100 * blo, 100 * bhi, rogue, total))
    print("                the prevalence of the rogue half of THIS corpus,")
    print("                which is what the precision row below is computed")
    print("                at. It is measured, not assumed.")
    print("  recall        %.1f%%  [%.1f, %.1f]   (%d/%d)"
          % (100 * recall, 100 * rlo, 100 * rhi, run["caught"], rogue))
    print("  FPR           %.2f%%  [%.2f, %.2f]   (%d/%d)"
          % (100 * fpr, 100 * flo, 100 * fhi, run["fp_num"], run["fp_den"]))
    print("")
    print("  Both denominators are the whole of their half of the corpus.")
    print("  Restricted to the %d violations an action was actually taken in"
          % sum(n for c, n, _k in run["classes"] if c in ("C1", "C2")))
    print("  (C1 and C2), the gate refuses %d — a real quantity, but not one"
          % sum(k for c, _n, k in run["classes"] if c in ("C1", "C2")))
    print("  that can be divided into a base rate defined over all of them.")
    print("  Of the %d C1 violations a predicate could reach it refuses %d."
          % (run["ceiling_n"], run["ceiling_caught"]))
    print("")
    print("  base rate   precision   false alarms per real catch")
    for b in (base,) + HYPOTHETICAL:
        p = precision_at(b, recall, fpr)
        ratio = (1.0 - p) / p if p > 0 else float("inf")
        note = "  <- this corpus's measured rogue rate" if b == base else ""
        print("  %7.1f%%     %6.1f%%     %6.1f%s"
              % (100 * b, 100 * p, ratio, note))
    worst = precision_at(HYPOTHETICAL[-2], recall, fpr)
    print("")
    print("  At a %.1f%% rogue rate the false-alarm share is %.0f%%, against"
          % (100 * HYPOTHETICAL[-2], 100 * (1 - worst)))
    print("  the ~30% at which static-analysis users abandon a tool.")


def main():
    rc = 0
    print("")
    print("  OPERATING POINT: what a deployer feels, at the base rate the")
    print("  corpus actually carries rather than one written into the source.")
    for label, name in RUNS:
        path = os.path.join(FIGURES, name)
        if not os.path.exists(path):
            print("")
            print("  %s: %s missing — nothing to report" % (label, path))
            rc = 1
            continue
        try:
            report(label, path, parse(path))
        except Malformed as exc:
            print("")
            print("  %s: %s is malformed — %s" % (label, path, exc))
            rc = 1
    print("")
    return rc


if __name__ == "__main__":
    sys.exit(main())
