#!/usr/bin/env python
"""A12 - did the arms actually walk the same task sequence?"""

import argparse
import collections
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import wilson  # noqa: E402

DATA = os.path.join("paper", "data")
HOOK_SRC = os.path.join("crates", "sentinel-hook", "src", "main.rs")
ARMS = ["denials-terse", "denials-explain", "denials-padded", "denials-defer",
        "denials-full", "denials-control"]


def sessions(archive):
    """family -> count, and (family, variant) -> count."""
    path = os.path.join(DATA, archive)
    fam = collections.Counter()
    task = collections.Counter()
    if not os.path.isdir(path):
        return None, None
    for name in os.listdir(path):
        if not os.path.isdir(os.path.join(path, name)):
            continue
        parts = name.split("-")
        if len(parts) < 3:
            continue
        fam[parts[0]] += 1
        task[(parts[0], parts[1])] += 1
    return fam, task


def _unescape_rust(lit):
    """Rust string-literal body -> the bytes the agent receives."""
    out = []
    i = 0
    while i < len(lit):
        c = lit[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        nxt = lit[i + 1] if i + 1 < len(lit) else ""
        if nxt == "\n":
            # A backslash before a newline is Rust's line continuation: the
            # newline AND the following indentation are not part of the value.
            j = i + 2
            while j < len(lit) and lit[j] in " \t":
                j += 1
            i = j
        elif nxt == "n":
            out.append("\n")
            i += 2
        elif nxt == "t":
            out.append("\t")
            i += 2
        else:
            out.append(nxt)
            i += 2
    return "".join(out)


def arm_templates(path=HOOK_SRC):
    """style -> template string, read from `denial_text` in the hook source."""
    if not os.path.exists(path):
        return None
    src = io.open(path, encoding="utf-8").read()
    start = src.find("fn denial_text(")
    if start < 0:
        return None
    body = src[start:]
    end = body.find("\n}\n")
    if end > 0:
        body = body[:end]
    out = {}
    for m in re.finditer(r"DenialStyle::(\w+)\s*=>", body):
        style = m.group(1)
        q = body.find('"', m.end())
        if q < 0:
            continue
        j = q + 1
        while j < len(body):
            if body[j] == "\\":
                j += 2
                continue
            if body[j] == '"':
                break
            j += 1
        out[style.lower()] = _unescape_rust(body[q + 1:j])
    return out or None


def reason_lengths(archive="denials"):
    """Length of every `reason` the guard emitted, from the event ledger."""
    base = os.path.join(DATA, archive)
    lens = []
    if not os.path.isdir(base):
        return lens
    for name in sorted(os.listdir(base)):
        path = os.path.join(base, name, "events.jsonl")
        if not os.path.exists(path):
            continue
        for line in io.open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("kind") != "guard_decision":
                continue
            reason = (e.get("meta") or {}).get("reason")
            if reason:
                lens.append(len(reason))
    lens.sort()
    return lens


def lengths_report():
    tpl = arm_templates()
    if tpl is None:
        print("\n  the hook source is not in this tree, so the arm templates")
        print("  cannot be read; no length is printed rather than a guessed one.")
        return 1
    lens = reason_lengths()
    if not lens:
        print("\n  no reason strings in paper/data/denials; the rendered")
        print("  columns need the campaign ledger.")
        return 1
    lo, mid, hi = lens[0], lens[len(lens) // 2], lens[-1]
    print("")
    print("A12b - refusal text length by arm")
    print("templates  %s::denial_text" % HOOK_SRC)
    print("reasons    paper/data/denials: %d guard refusals, reason length "
          "%d / %d / %d" % (len(lens), lo, mid, hi))
    print("           (min / median / max)")
    print("")
    print("  %-10s %7s %10s %14s" % ("arm", "fixed", "at median", "range"))
    order = ["terse", "explain", "padded", "defer", "full"]
    for style in order:
        text = tpl.get(style)
        if text is None:
            continue
        fixed = len(text.replace("{reason}", ""))
        if "{reason}" in text:
            print("  %-10s %7d %10d %14s"
                  % (style, fixed, fixed + mid,
                     "%d - %d" % (fixed + lo, fixed + hi)))
        else:
            print("  %-10s %7d %10d %14s"
                  % (style, fixed, fixed, "%d - %d" % (fixed, fixed)))
    print("")
    print("  `fixed` is the template with the reason removed; the other two")
    print("  render it against the reasons the campaign emitted. `padded`")
    print("  carries no reason, so its single length is what `full` has to be")
    print("  compared against, and the comparison to quote is `padded` fixed")
    print("  against `full` at the median.")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tolerance", type=float, default=0.25,
                    help="max acceptable relative difference in family share")
    ap.add_argument("--arms", default="",
                    help="comma-separated archive names to compare instead of "
                         "the published set, e.g. denials-defer-opus,denials-opus")
    ap.add_argument("--lengths", action="store_true",
                    help="measure each arm's refusal text instead of its task "
                         "sequence: the length match `padded` is built on")
    args = ap.parse_args()

    if args.lengths:
        return lengths_report()

    arms = [a.strip() for a in args.arms.split(",") if a.strip()] or ARMS

    present = []
    for arm in arms:
        fam, task = sessions(arm)
        if fam is None:
            print("  %-18s not collected" % arm)
            continue
        present.append((arm, fam, task))

    if len(present) < 2:
        print("\nFewer than two arms collected; nothing to compare yet.")
        return 0

    print("")
    print("A12 - task sequence across arms")
    print("")
    families = sorted(set(f for _a, fam, _t in present for f in fam))
    print("  %-26s" % "family" + "".join("%16s" % a.replace("denials-", "")
                                         for a, _f, _t in present))
    totals = [sum(fam.values()) for _a, fam, _t in present]
    for fam_name in families:
        line = "  %-26s" % fam_name
        for (_a, fam, _t), total in zip(present, totals):
            n = fam.get(fam_name, 0)
            line += "%9d %5.1f%%" % (n, 100.0 * n / total if total else 0)
        print(line)
    print("  %-26s" % "TOTAL" + "".join("%9d %5s" % (t, "") for t in totals))

    # The comparison that matters: does any family's share differ between arms
    # by more than the tolerance? Absolute counts differ because arms stop at
    # slightly different session totals; shares are what must match.
    print("")
    worst = []
    base_arm, base_fam, _bt = present[0]
    base_total = totals[0]
    for arm, fam, _t in present[1:]:
        total = sum(fam.values())
        for fam_name in families:
            a = base_fam.get(fam_name, 0) / float(base_total or 1)
            b = fam.get(fam_name, 0) / float(total or 1)
            if max(a, b) == 0:
                continue
            rel = abs(a - b) / max(a, b)
            if rel > args.tolerance:
                worst.append((rel, fam_name, base_arm, 100 * a, arm, 100 * b))

    if not worst:
        print("  PASS - every family's share agrees across arms within %.0f%%."
              % (100 * args.tolerance))
        print("  The arms are comparable and the ablation may be reported as a")
        print("  matched design.")
    else:
        print("  DIVERGENT - these families do not appear at the same rate:")
        for rel, fam_name, a1, s1, a2, s2 in sorted(worst, reverse=True)[:12]:
            print("    %-24s %s %5.1f%%  vs  %s %5.1f%%   (%.0f%% apart)"
                  % (fam_name, a1.replace("denials-", ""), s1,
                     a2.replace("denials-", ""), s2, 100 * rel))
        print("")
        print("  The arms are NOT a matched design as they stand. Restrict every")
        print("  contrast to the families all arms share, and say so in the")
        print("  paper - a matched-design claim that is not true is worse than")
        print("  an honest restriction.")

    # An arm that stopped early is comparable in shape but not in power.
    print("")
    print("  session totals: " + ", ".join(
        "%s %d" % (a.replace("denials-", ""), t)
        for (a, _f, _t), t in zip(present, totals)))
    spread = (max(totals) - min(totals)) / float(max(totals))
    if spread > 0.15:
        print("  NOTE: totals differ by %.0f%%. Rates stay comparable; absolute"
              % (100 * spread))
        print("  counts and interval widths do not." % ())
    return 0


if __name__ == "__main__":
    sys.exit(main())
