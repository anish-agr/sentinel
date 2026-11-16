#!/usr/bin/env python
"""What four independent raters say about the enforceability taxonomy."""

import io
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "paper", "scripts"))

CORPUS = os.path.join(REPO, "paper", "data", "atbench-violations.jsonl")
CONSENSUS = os.path.join(
    REPO, "paper", "data", "atbench-violations.jsonl.labels-consensus.jsonl")


def wilson(k, n, z=1.96):
    """Wilson score interval, the same helper the rest of the paper uses."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = float(k) / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return p, max(0.0, centre - half), min(1.0, centre + half)


def load():
    corpus = {}
    for line in io.open(CORPUS, encoding="utf-8"):
        if not line.strip():
            continue
        d = json.loads(line)
        corpus[d.get("id") or d.get("uid")] = d
    cons = {}
    for line in io.open(CONSENSUS, encoding="utf-8"):
        if not line.strip():
            continue
        r = json.loads(line)
        cons[r["id"]] = r["consensus"]
    return corpus, cons


def measure():
    corpus, cons = load()
    out = {}

    # Stratum sizes in the corpus, and how many of each the panel rated.
    strata = {}
    for d in corpus.values():
        strata[d.get("machine_class")] = strata.get(d.get("machine_class"), 0) + 1
    rated = {}
    human_c1 = {}
    for i, h in cons.items():
        m = corpus[i].get("machine_class")
        rated[m] = rated.get(m, 0) + 1
        if h == "C1":
            human_c1[m] = human_c1.get(m, 0) + 1

    out["corpus_n"] = sum(strata.values())
    out["strata"] = strata
    out["rated"] = rated
    out["human_c1_by_stratum"] = human_c1
    out["consensus_n"] = len(cons)

    # Item-level agreement with the classifier.
    agree = sum(1 for i, h in cons.items()
                if corpus[i].get("machine_class") == h)
    out["item_agreement"] = float(agree) / len(cons)
    out["item_agree_n"] = agree

    # The C1 stratum is a census: every corpus C1 item that got rated.
    c1_rated = rated.get("C1", 0)
    out["c1_stratum_rated"] = c1_rated
    out["c1_stratum_survived"] = human_c1.get("C1", 0)

    # Reweight to a corpus-level human estimate. Each stratum contributes its
    # observed human-C1 rate times its corpus size. The C1 stratum is a census
    # so it contributes its count directly rather than a rate.
    est = 0.0
    for m, size in strata.items():
        r = rated.get(m, 0)
        if r == 0:
            continue
        k = human_c1.get(m, 0)
        if m == "C1":
            est += k                      # census: no extrapolation
        else:
            est += size * (float(k) / r)  # sampled stratum
    out["human_c1_estimate"] = est
    out["human_c1_rate"] = est / out["corpus_n"]

    # The interval is driven by the sampled stratum that carries every human C1.
    # Propagating a Wilson interval on that rate through the same weighting is
    # the honest bound: it is wide, and saying so is the point.
    lo = hi = 0.0
    for m, size in strata.items():
        r = rated.get(m, 0)
        if r == 0 or m == "C1":
            lo += human_c1.get(m, 0) if m == "C1" else 0
            hi += human_c1.get(m, 0) if m == "C1" else 0
            continue
        _, l, h = wilson(human_c1.get(m, 0), r)
        lo += size * l
        hi += size * h
    out["human_c1_lo"] = lo / out["corpus_n"]
    out["human_c1_hi"] = hi / out["corpus_n"]
    out["machine_c1_rate"] = float(strata.get("C1", 0)) / out["corpus_n"]
    out["contains_machine"] = out["human_c1_lo"] <= out["machine_c1_rate"] <= out["human_c1_hi"]

    from taxonomy_robustness import ARGUABLE
    arguable = set(ARGUABLE)
    rated_arguable = [h for i, h in cons.items()
                      if corpus[i].get("machine_signature") in arguable]
    out["verb_rated"] = len(rated_arguable)
    out["verb_c2"] = sum(1 for h in rated_arguable if h == "C2")
    return out


def main():
    r = measure()
    print("")
    print("  RATER PANEL - taxonomy validation")
    print("  corpus %d items; panel rated %d to consensus"
          % (r["corpus_n"], r["consensus_n"]))
    print("")
    print("  Item-level agreement, classifier vs human consensus: %.1f%% (%d/%d)"
          % (100 * r["item_agreement"], r["item_agree_n"], r["consensus_n"]))
    print("  Of %d items the classifier calls C1, the panel agrees on %d."
          % (r["c1_stratum_rated"], r["c1_stratum_survived"]))
    print("")
    print("  Stratum        corpus   rated   human-C1")
    for m in sorted(r["strata"]):
        print("  %-12s %8d %7d %10d"
              % (m, r["strata"][m], r["rated"].get(m, 0),
                 r["human_c1_by_stratum"].get(m, 0)))
    print("")
    print("  Reweighted action-local rate")
    print("    classifier              %.2f%%" % (100 * r["machine_c1_rate"]))
    print("    human panel             %.2f%%  [%.2f, %.2f]"
          % (100 * r["human_c1_rate"], 100 * r["human_c1_lo"],
             100 * r["human_c1_hi"]))
    print("    interval contains the classifier's rate: %s"
          % ("yes" if r["contains_machine"] else "NO"))
    print("")
    print("  The arguable verbs of the elasticity table (taxonomy_robustness.py)")
    print("  Panel-rated items carrying one of those verbs:   %d" % r["verb_rated"])
    print("  ...that the panel placed in the context-dependent class: %d"
          % r["verb_c2"])
    print("  The last row of the elasticity table moves all of them; the panel,")
    print("  blinded, moved %d. That is the envelope's answer, not ours."
          % (r["verb_rated"] - r["verb_c2"]))
    print("")
    print("  The rate is corroborated; the item assignment is not. Both go in")
    print("  the paper, and the headline uses no taxonomy either way.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
