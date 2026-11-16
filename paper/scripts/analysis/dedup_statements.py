#!/usr/bin/env python
"""A10 - is the policy inversion a real regularity or copied boilerplate?"""

import argparse
import collections
import hashlib
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import wilson  # noqa: E402

DATA = os.path.join("paper", "data")
CORPORA = [
    ("this paper", "policy-statements.jsonl"),
    ("AIWare", "aiware-statements.jsonl"),
    ("Agent READMEs", "readmes-statements.jsonl"),
]

MARKDOWN = re.compile(r"[*_`#>\[\]()~-]+")
NONWORD = re.compile(r"[^a-z0-9 ]+")
SPACES = re.compile(r"\s+")


def normalise(text):
    """Strip the things that differ between copies of the same rule."""
    t = (text or "").lower()
    t = MARKDOWN.sub(" ", t)
    t = NONWORD.sub(" ", t)
    return SPACES.sub(" ", t).strip()


def simhash(tokens):
    """64-bit simhash over 3-token shingles."""
    if not tokens:
        return 0
    bits = [0] * 64
    shingles = ([" ".join(tokens[i:i + 3]) for i in range(len(tokens) - 2)]
                or [" ".join(tokens)])
    for sh in shingles:
        h = int(hashlib.md5(sh.encode("utf-8")).hexdigest()[:16], 16)
        for b in range(64):
            bits[b] += 1 if (h >> b) & 1 else -1
    out = 0
    for b in range(64):
        if bits[b] > 0:
            out |= 1 << b
    return out


def exact_pass(rows):
    """The statements that survive verbatim-duplicate collapse, in order."""
    seen = set()
    kept = []
    for r in rows:
        key = hashlib.md5(
            normalise(r.get("statement")).encode("utf-8")).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        kept.append(r)
    return kept


_BAND_BITS = 16
_BANDS = 4
_MASK = (1 << _BAND_BITS) - 1


def near_duplicates(kept, max_distance=3):
    """How many of `kept` are near-duplicates of an earlier retained statement."""
    buckets = collections.defaultdict(list)
    for r in kept:
        toks = normalise(r.get("statement")).split()
        buckets[min(len(toks) // 5, 40)].append(simhash(toks))
    near = 0
    for _band, hashes in buckets.items():
        index = [{} for _ in range(_BANDS)]
        for h in hashes:
            cands = set()
            for i in range(_BANDS):
                cands |= index[i].get((h >> (_BAND_BITS * i)) & _MASK, set())
            if any(bin(h ^ g).count("1") <= max_distance for g in cands):
                near += 1
            else:
                for i in range(_BANDS):
                    index[i].setdefault(
                        (h >> (_BAND_BITS * i)) & _MASK, set()).add(h)
    return near


def load(name):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return None
    rows = []
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    return rows


def shares(rows):
    n = len(rows)
    if not n:
        return {}
    c = collections.Counter(r.get("machine_class") for r in rows)
    matched = n - c.get("U", 0)
    return {
        "n": n,
        "C1": c.get("C1", 0),
        "matched": matched,
        "c1_share": 100.0 * c.get("C1", 0) / n,
        "c1_given_matched": (100.0 * c.get("C1", 0) / matched) if matched else 0.0,
    }


FILETYPE_ROWS = [
    "agents.md",
    "copilot-instructions.md",
    "skill.md",
    "claude.md",
    ".cursorrules",
    "github-actions-ci-cd-best-practices.instructions.md",
]


def by_file_facts(name="aiware-statements.jsonl"):
    """Per-row facts behind tab:app-filetype, including the real denominator."""
    rows = load(name)
    if rows is None:
        return None, None
    per = collections.Counter()
    c1 = collections.Counter()
    texts = collections.defaultdict(collections.Counter)
    cls = collections.defaultdict(dict)
    repos = collections.defaultdict(set)
    for r in rows:
        key = (r.get("filename") or "").strip().lower()
        per[key] += 1
        if r.get("machine_class") == "C1":
            c1[key] += 1
        t = (r.get("statement") or "").strip()
        texts[key][t] += 1
        cls[key].setdefault(t, r.get("machine_class"))
        repos[key].add(r.get("repo"))

    out = []
    for key in FILETYPE_ROWS:
        n = per.get(key, 0)
        if not n:
            out.append({"key": key, "n": 0})
            continue
        mult = set(texts[key].values())
        rep = mult.pop() if len(mult) == 1 else None
        if rep is not None and rep < 2:
            rep = None
        nd = len(texts[key])
        kd = sum(1 for v in cls[key].values() if v == "C1")
        out.append({
            "key": key, "n": n, "k": c1.get(key, 0),
            "distinct_n": nd, "distinct_k": kd,
            "repos": len(repos[key]),
            "replication": rep,
            "ci_n": nd if rep else n,
            "ci_k": kd if rep else c1.get(key, 0),
        })
    return out, len(rows)


def by_file_report(name="aiware-statements.jsonl"):
    """tab:app-filetype's rows, plus the denominator its caption quotes."""
    facts, corpus_n = by_file_facts(name)
    if facts is None:
        print("")
        print("  %s is not in %s. REFUSING to report a residual over"
              % (name, os.path.abspath(DATA)))
        print("  a corpus that is not here.")
        return 2

    rows = load(name)
    filenames = len({(r.get("filename") or "").strip().lower() for r in rows})

    print("")
    print("  tab:app-filetype - C1 share by instruction-file type")
    print("  corpus %s, %d statements in %d distinct filenames"
          % (name, corpus_n, filenames))
    print("")
    print("  %-52s %8s %6s %8s %s"
          % ("file", "n", "C1", "share", "95% CI (published)"))
    named = 0
    present = [f for f in facts if f["n"]]
    for f in facts:
        if not f["n"]:
            print("  %-52s %8s   (absent from this corpus)" % (f["key"], "-"))
            continue
        named += f["n"]
        lo, hi = wilson(f["ci_k"], f["ci_n"])
        note = "" if f["ci_n"] == f["n"] else "   over %d distinct" % f["ci_n"]
        print("  %-52s %8d %6d %7.2f%% [%.2f, %.2f]%s"
              % (f["key"], f["n"], f["k"], 100.0 * f["k"] / f["n"],
                 100 * lo, 100 * hi, note))

    # ---- exact-duplication census, per row. See by_file_facts' docstring for
    # why `replication` is the strict predicate and not a multiplicity cutoff.
    print("")
    print("  EXACT DUPLICATION WITHIN EACH ROW - the interval's real "
          "denominator")
    print("  %-52s %8s %8s %6s %6s %s"
          % ("file", "n", "distinct", "mult", "repos", "exact replication?"))
    for f in present:
        mult = f["n"] / float(f["distinct_n"])
        print("  %-52s %8d %8d %5.2fx %6d %s"
              % (f["key"], f["n"], f["distinct_n"], mult, f["repos"],
                 ("YES, every text exactly %dx" % f["replication"])
                 if f["replication"] else "no (ragged)"))
    for f in present:
        if not f["replication"]:
            continue
        lo, hi = wilson(f["k"], f["n"])
        dlo, dhi = wilson(f["distinct_k"], f["distinct_n"])
        print("")
        print("  %s IS NOT %d OBSERVATIONS." % (f["key"].upper(), f["n"]))
        print("  Every one of its %d distinct statement texts appears exactly"
              % f["distinct_n"])
        print("  %d times, across %d repositories: the file is vendored"
              % (f["replication"], f["repos"]))
        print("  verbatim. The point estimate is unaffected (%.2f%% either way,"
              % (100.0 * f["k"] / f["n"]))
        print("  because the replication is exact); the interval is not.")
        print("  Wilson over %d: [%.2f, %.2f], width %.2f pts."
              % (f["n"], 100 * lo, 100 * hi, 100 * (hi - lo)))
        print("  Wilson over %d: [%.2f, %.2f], width %.2f pts.  <-- PUBLISH THIS"
              % (f["distinct_n"], 100 * dlo, 100 * dhi, 100 * (dhi - dlo)))
        print("  tab:app-dedup's corpus-wide collapse (max shift 0.19 points)")
        print("  is a fact about the corpus and does not defend this row,")
        print("  which is 100% verbatim duplicate.")
    tail = corpus_n - named
    print("")
    print("  rows above                            %8d" % named)
    print("  long tail (%d other filenames)        %8d"
          % (filenames - len(present), tail))
    print("  corpus                                %8d" % corpus_n)
    print("")
    print("  The rows are a SUBSET. Quote %d as the table's own"
          % named)
    print("  denominator and %d as the corpus it is drawn from; the"
          % corpus_n)
    print("  caption has to carry both or it contradicts its rows.")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--near", action="store_true")
    ap.add_argument("--by-file", action="store_true",
                    help="tab:app-filetype's rows and the residual under them")
    args = ap.parse_args()

    if args.by_file:
        return by_file_report()

    print("")
    print("A10 - duplicate collapse across the three policy corpora")
    print("")
    print("  INPUT: %s" % os.path.abspath(DATA))
    for _label, name in CORPORA:
        path = os.path.join(DATA, name)
        print("         %-28s %s" % (name, "present" if os.path.exists(path)
                                     else "MISSING"))
    print("")

    grand_before = grand_after = 0
    for label, name in CORPORA:
        rows = load(name)
        if rows is None:
            print("  %-16s missing (%s)" % (label, name))
            continue

        kept = exact_pass(rows)

        removed = len(rows) - len(kept)
        pct = 100.0 * removed / len(rows) if rows else 0.0
        before, after = shares(rows), shares(kept)
        grand_before += len(rows)
        grand_after += len(kept)

        print("  %s" % label)
        print("    statements      %6d -> %6d   (%d exact duplicates, %.1f%%)"
              % (len(rows), len(kept), removed, pct))
        blo, bhi = wilson(before["C1"], before["n"])
        alo, ahi = wilson(after["C1"], after["n"])
        print("    C1 share        %6.2f%% [%.2f, %.2f]  ->  %6.2f%% [%.2f, %.2f]"
              % (before["c1_share"], 100 * blo, 100 * bhi,
                 after["c1_share"], 100 * alo, 100 * ahi))
        print("    C1 given matched %5.1f%%              ->  %6.1f%%"
              % (before["c1_given_matched"], after["c1_given_matched"]))

        if args.near and len(kept) < 60000:
            near = near_duplicates(kept)
            print("    near-duplicates %6d more in %d (%.1f%% of what "
                  "survived exact)"
                  % (near, len(kept), 100.0 * near / max(len(kept), 1)))
        print("")

    if grand_before:
        print("  pooled            %d -> %d statements (%.1f%% removed)"
              % (grand_before, grand_after,
                 100.0 * (grand_before - grand_after) / grand_before))
    print("")
    print("  Read the C1 shares, not the removal counts. If the share barely")
    print("  moves, the corpora agree because developers face the same problem,")
    print("  and the inversion stands. If it moves a lot, they agree because")
    print("  they copied each other, and the invariance claim has to go.")


if __name__ == "__main__":
    main()
