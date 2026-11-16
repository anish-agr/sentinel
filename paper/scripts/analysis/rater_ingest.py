#!/usr/bin/env python
"""Take rater sheets in, and report what they say about the classifiers."""

import argparse
import collections
import io
import itertools
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DATA = os.path.join(REPO, "paper", "data")
KEYS = os.path.join(DATA, "labelkit", "_keys")

TASK1 = set(["C0", "C1", "C2", "C3", "UNSURE"])
TASK2 = set(["A", "B", "C", "D", "UNSURE"])
POLICY_MAP = {"A": "C1", "B": "C2", "C": "C3", "D": "C0"}

LINE = re.compile(r"^\s*(\d+)\s+([A-Za-z0-9]+)")


def read_sheet(path, valid):
    """-> {item number: class}. Silent about junk; a sheet is a human artifact."""
    out = {}
    for line in io.open(path, encoding="utf-8", errors="replace"):
        m = LINE.match(line)
        if not m:
            continue
        cls = m.group(2).upper()
        if cls in valid:
            out[int(m.group(1))] = cls
    return out


def ac1(a, b, keys):
    """Gwet's AC1: chance agreement from the marginals, not from their product."""
    n = len(keys)
    if not n:
        return float("nan")
    pa = sum(1 for k in keys if a[k] == b[k]) / float(n)
    cats = set(a[k] for k in keys) | set(b[k] for k in keys)
    if len(cats) < 2:
        return 1.0
    pe = 0.0
    for c in cats:
        pi = (sum(1 for k in keys if a[k] == c) / float(n)
              + sum(1 for k in keys if b[k] == c) / float(n)) / 2.0
        pe += pi * (1 - pi)
    pe /= (len(cats) - 1)
    return (pa - pe) / (1 - pe) if pe < 1 else 1.0


def majority(sheets, raters, item):
    votes = [sheets[r][item] for r in raters if item in sheets[r]]
    if not votes:
        return None
    top, k = collections.Counter(votes).most_common(1)[0]
    return top if k > len(votes) / 2.0 else None


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0, 0.0
    p = float(k) / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def machine_labels(task, items, key):
    """The classifier's answer for each rated item, in the raters' vocabulary."""
    out = {}
    if task == 1:
        corpus = {}
        for name in ("atbench-violations-v2.jsonl", "atbench-violations.jsonl"):
            p = os.path.join(DATA, name)
            if os.path.isfile(p):
                for line in io.open(p, encoding="utf-8"):
                    if line.strip():
                        d = json.loads(line)
                        corpus[d.get("id") or d.get("uid")] = d
                break
        for i in items:
            rid = key.get(str(i))
            if rid in corpus:
                out[i] = corpus[rid]["machine_class"]
    else:
        sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "policies"))
        import classify as C
        for i in items:
            rec = key.get(str(i))
            if rec:
                cls = C.classify(rec["statement"])[0]
                # U is the matcher declining to answer, not a rater category.
                # Scoring it as C2 is the conservative reading: it counts as a
                # miss wherever the panel found something enforceable.
                out[i] = cls if cls != "U" else "C2"
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", type=int, required=True, choices=(1, 2))
    ap.add_argument("--sheets", required=True,
                    help="folder holding the returned sheets")
    ap.add_argument("--key", help="override the key file")
    ap.add_argument("--write", action="store_true",
                    help="write the consensus alongside the corpus")
    args = ap.parse_args()

    valid = TASK1 if args.task == 1 else TASK2
    keyfile = args.key or os.path.join(
        KEYS, "key-holdout.json" if args.task == 1 else "key-holdout-policy.json")
    key = json.load(io.open(keyfile, encoding="utf-8"))

    want = "task%d" % args.task
    files = sorted(f for f in os.listdir(args.sheets)
                   if want in f.lower().replace("-", "").replace("_", "")
                   and f.lower().endswith((".txt", ".tsv", ".csv")))
    if not files:
        print("no task %d sheets in %s" % (args.task, args.sheets))
        return 1

    sheets = {}
    for f in files:
        stem = os.path.splitext(f)[0].lower().replace("-", "").replace("_", "")
        rater = stem.split(want)[-1] or f
        sheets[rater] = read_sheet(os.path.join(args.sheets, f), valid)

    raters = sorted(sheets)
    shared = sorted(set.intersection(*[set(s) for s in sheets.values()]))
    print("")
    print("  TASK %d - %d sheets, %d items answered by all of them"
          % (args.task, len(raters), len(shared)))
    print("")
    for r in raters:
        c = collections.Counter(sheets[r].values())
        print("   %-10s %5d answered   %s"
              % (r, len(sheets[r]),
                 "  ".join("%s=%d" % kv for kv in sorted(c.items()))))

    print("")
    print("   pairwise AC1")
    per = collections.defaultdict(list)
    for x, y in itertools.combinations(raters, 2):
        v = ac1(sheets[x], sheets[y], shared)
        per[x].append(v)
        per[y].append(v)
        print("     %-9s %-9s %.3f" % (x, y, v))
    print("   each rater against the others")
    for r in raters:
        mean = sum(per[r]) / len(per[r])
        flag = "   <- below the 0.75 bar" if mean < 0.75 else ""
        print("     %-10s %.3f%s" % (r, mean, flag))

    every = sorted(set().union(*[set(s) for s in sheets.values()]))
    cons = {}
    for i in every:
        m = majority(sheets, raters, i)
        if m and m != "UNSURE":
            cons[i] = m
    print("")
    print("   consensus on %d of %d items" % (len(cons), len(every)))
    dist = collections.Counter(cons.values())
    print("   %s" % "  ".join("%s=%d" % kv for kv in sorted(dist.items())))

    head = "C1" if args.task == 1 else "A"
    k = dist.get(head, 0)
    p, lo, hi = wilson(k, len(cons))
    print("   %s rate  %.2f%%  [%.2f, %.2f]" % (head, 100 * p, 100 * lo, 100 * hi))
    parts = []
    for r in raters:
        sub = [x for x in raters if x != r]
        c2 = {}
        for i in every:
            m = majority(sheets, sub, i)
            if m and m != "UNSURE":
                c2[i] = m
        rate = 100.0 * collections.Counter(c2.values()).get(head, 0) / max(1, len(c2))
        parts.append("-%s %.2f%%" % (r, rate))
    print("   leave one out:  %s" % "   ".join(parts))

    mach = machine_labels(args.task, list(cons), key)
    both = [i for i in cons if i in mach]
    if both:
        human = dict((i, cons[i] if args.task == 1 else POLICY_MAP[cons[i]])
                     for i in both)
        agree = sum(1 for i in both if mach[i] == human[i])
        print("")
        print("   CLASSIFIER vs this consensus")
        print("     agreement          %.1f%%  (%d/%d)"
              % (100.0 * agree / len(both), agree, len(both)))
        tp = sum(1 for i in both if mach[i] == "C1" and human[i] == "C1")
        fp = sum(1 for i in both if mach[i] == "C1" and human[i] != "C1")
        fn = sum(1 for i in both if mach[i] != "C1" and human[i] == "C1")
        print("     action-local:      %d found, %d missed, %d over-called"
              % (tp, fn, fp))
        conf = collections.Counter((mach[i], human[i]) for i in both)
        print("     predicted -> panel")
        for kk in sorted(conf):
            print("       %-4s -> %-4s  %5d%s"
                  % (kk[0], kk[1], conf[kk], "" if kk[0] == kk[1] else "   <-"))

    if args.write:
        stem = ("atbench-violations.jsonl.labels-holdout.jsonl" if args.task == 1
                else "policy-statements.labels-holdout.jsonl")
        out = os.path.join(DATA, stem)
        with io.open(out, "w", encoding="utf-8", newline="\n") as fh:
            for i in every:
                rec = {"item": i, "consensus": cons.get(i),
                       "votes": dict((r, sheets[r].get(i)) for r in raters)}
                if args.task == 1:
                    rec["id"] = key.get(str(i))
                fh.write(json.dumps(rec) + "\n")
        print("")
        print("   wrote %s" % os.path.relpath(out, REPO))
    return 0


if __name__ == "__main__":
    sys.exit(main())
