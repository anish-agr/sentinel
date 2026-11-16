#!/usr/bin/env python
"""The oracle effect against its own placebo."""

import io
import os
import re
import sys
from math import sqrt
from statistics import NormalDist

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
TABLE = os.path.join(REPO, "paper", "figures", "tab-ablation.tex")

# Column order in tab-ablation.tex, after the arm label.
EVENTS, OVERRODE, REWROTE = 0, 1, 2


def arms(path=TABLE):
    """{arm: (n, rewrote_k)} from the committed ablation table."""
    if not os.path.exists(path):
        raise SystemExit("  %s is absent; nothing to read." % path)
    text = io.open(path, encoding="utf-8").read()
    if "not collected" in text:
        raise SystemExit("  tab-ablation.tex is the interim placeholder: the "
                         "arms have not collected on this machine.")
    out = {}
    for line in text.splitlines():
        if "&" not in line or line.lstrip().startswith("%"):
            continue
        cells = [c.strip() for c in line.replace("\\\\", "").split("&")]
        label = cells[0]
        m = re.match(r"([A-Za-z]+)", label)
        if not m or len(cells) < 4:
            continue
        arm = m.group(1).lower()
        if label.startswith("Full,"):
            arm = "control"
        try:
            n = int(re.sub(r"[^0-9]", "", cells[1 + EVENTS]))
            pct = float(re.sub(r"[^0-9.]", "", cells[1 + REWROTE]))
        except ValueError:
            continue
        k = int(round(pct / 100.0 * n))
        if abs(round(100.0 * k / n, 1) - pct) > 0.051:
            raise SystemExit(
                "  %s: no integer count reproduces %.1f%% of %d (nearest is "
                "%d -> %.1f%%). The table's precision cannot recover it."
                % (arm, pct, n, k, 100.0 * k / n))
        out[arm] = (n, k)
    return out


def newcombe(k1, n1, k2, n2, z):
    """Newcombe difference interval, arm2 minus arm1, at the given z."""
    def w(k, n):
        p = k / float(n)
        d = 1 + z * z / n
        c = (p + z * z / (2 * n)) / d
        h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
        return c - h, c + h
    l1, u1 = w(k1, n1)
    l2, u2 = w(k2, n2)
    p1, p2 = k1 / float(n1), k2 / float(n2)
    d = p2 - p1
    lo = d - sqrt((p2 - l2) ** 2 + (u1 - p1) ** 2)
    hi = d + sqrt((u2 - p2) ** 2 + (p1 - l1) ** 2)
    return 100 * d, 100 * lo, 100 * hi


def z_for(k_tests, alpha=0.05):
    return NormalDist().inv_cdf(1.0 - (alpha / float(k_tests)) / 2.0)


def main():
    a = arms()
    need = ("terse", "explain", "padded", "defer")
    missing = [x for x in need if x not in a]
    if missing:
        raise SystemExit("  missing arm(s) in the table: %s" % ", ".join(missing))

    print("")
    print("  REWRITING BY ARM (from the committed tab-ablation.tex)")
    print("")
    for arm in ("terse", "explain", "padded", "defer", "full", "control"):
        if arm in a:
            n, k = a[arm]
            print("    %-9s %3d/%3d = %5.1f%%" % (arm, k, n, 100.0 * k / n))

    tn, tk = a["terse"]
    en, ek = a["explain"]
    pn, pk = a["padded"]
    dn, dk = a["defer"]

    head, _, _ = newcombe(tk, tn, ek, en, z_for(1))
    leng, _, _ = newcombe(tk, tn, pk, pn, z_for(1))
    share = 100.0 * leng / head if head else 0.0

    print("")
    print("  DECOMPOSITION OF THE ORACLE EFFECT")
    print("")
    print("    terse -> explain   (headline)          %+5.1f points" % head)
    print("    terse -> padded    (LENGTH alone)      %+5.1f points"
          " = %.0f%% of it" % (leng, share))
    print("    padded -> explain  (CONTENT alone)     %+5.1f points"
          % (head - leng))
    print("")
    print("  `padded` carries full's length and none of its content, so the")
    print("  length row is the placebo the ablation was built to provide and")
    print("  the content row is the oracle estimand.")

    print("")
    print("  THE CONTENT CONTRAST UNDER EACH CORRECTION THE PAPER USES")
    print("")
    for label, kt in (("uncorrected 95%", 1),
                      ("Holm/Bonferroni k=3", 3),
                      ("Bonferroni k=6 (as app:multiplicity)", 6)):
        d, lo, hi = newcombe(pk, pn, ek, en, z_for(kt))
        mark = "  <-- includes 0" if lo <= 0 <= hi else ""
        print("    %-38s %+5.1f [%+.1f, %+.1f]%s" % (label, d, lo, hi, mark))

    print("")
    print("  THE ARM THAT CARRIES THE REASON AND DOES NOT LIFT")
    print("")
    d, lo, hi = newcombe(tk, tn, dk, dn, z_for(1))
    print("    terse -> defer                         %+5.1f [%+.1f, %+.1f]"
          % (d, lo, hi))
    print("    `defer` states the reason in full and adds a stop. It rewrites")
    print("    at %.1f%% against terse's %.1f%% and BELOW the contentless"
          % (100.0 * dk / dn, 100.0 * tk / tn))
    print("    placebo's %.1f%%, so a reason alone does not produce the lift."
          % (100.0 * pk / pn))
    print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
