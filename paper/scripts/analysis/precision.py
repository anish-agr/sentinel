#!/usr/bin/env python
"""How much more data would each interval width cost?"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import Z95, Z99  # noqa: E402

# Measured 2026-08-16 by rigor.py on paper/data/denials.
MEASURED = [
    # label,            point, clustered 95% half-width, clusters K
    ("shell refusal rate", 19.3, (22.5 - 16.2) / 2.0, 410),
    ("tool refusal rate", 6.3, (9.6 - 2.9) / 2.0, 163),
    ("action-space gap", 13.1, (17.6 - 8.6) / 2.0, 454),
    ("override share", 39.9, (45.5 - 34.2) / 2.0, 235),
]

# Calibration: 92 sessions is 5.2% of a weekly usage limit (measured over 166
# sessions = 39.8M tokens = 6% of a limit).
SESSIONS_PER_WEEKLY_LIMIT = 92 / 0.052


def main():
    print("")
    print("What each target half-width costs, in sessions")
    print("=" * 78)
    print("Half-width scales as 1/sqrt(sessions). The 99% column is the 95%")
    print("one widened by %.3f (the z ratio), and cost scales as the SQUARE"
          % (Z99 / Z95))
    print("of that, so a 99% target costs ~1.7x the same target at 95%.")
    print("")
    print("  %-20s %6s %8s %8s   %s" % ("quantity", "point", "95% h/w",
                                        "99% h/w", "sessions for 99% +/-1.0"))
    for label, point, h95, K in MEASURED:
        h99 = h95 * Z99 / Z95
        # h99 ~ c/sqrt(K)  =>  K_target = K * (h99 / target)^2
        need = K * (h99 / 1.0) ** 2
        # K counts sessions that CONTRIBUTE to this quantity; scale to total
        # campaign sessions by the observed contribution rate (K / 644).
        total = need * 644.0 / K
        print("  %-20s %5.1f%% %7.2f  %7.2f   %8.0f contributing (%.0f total, "
              "%.1f weekly limits)"
              % (label, point, h95, h99, need, total,
                 total / SESSIONS_PER_WEEKLY_LIMIT))

    print("")
    print("Reading, before anyone buys this:")
    print("")
    print("  * The precision we have already answers the question the paper")
    print("    asks. The gap is +13.1 points with a 99% interval of")
    print("    [+7.2, +19.0]; the claim is 'large and real', and it is made")
    print("    at 99% under clustering, bootstrap and a paired score interval")
    print("    alike. Nothing about that claim improves at +/-1.")
    print("")
    print("  * +/-1 would be FALSE precision. These rates are conditional on")
    print("    this task corpus, this ruleset and this model - the paper says")
    print("    so explicitly. Reporting 19.3% +/- 1.0 implies a constant that")
    print("    transfers; it does not, and a reviewer who reads the")
    print("    limitations section will say so.")
    print("")
    print("  * Where more data DOES change a conclusion: the arms that")
    print("    currently cannot resolve their contrast at all. Opus")
    print("    default-vs-max is uncomputable (two rungs missing). Sonnet's")
    print("    is [-1.9, +17.3] with an 11.2-point MDD. The cross-vendor")
    print("    cells sit at 8-39 of 40. Those are the sessions worth buying.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
