#!/usr/bin/env python
"""How many sessions buy how much precision - measured, not guessed."""

import io
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from archive import session_files, read_log  # noqa: E402
from archive import require_sessions  # noqa: E402
from cross_vendor import admits  # noqa: E402

DATA = os.path.join("paper", "data")

# Measured in the paper: session-clustered (GEE sandwich) intervals against the
# per-event ones. 2.69 is the largest observed; using the largest is the
# conservative choice and the right one for planning.
DESIGN_EFFECT = 2.69

Z = {90: 1.6449, 95: 1.9600, 99: 2.5758}


def observed_yield(arm="full"):
    """Denials per session, and the override rate, from what is on disk."""
    sessions = denials = overrides = 0
    for name in sorted(os.listdir(DATA)):
        if admits(name, arm) is None:
            continue
        path = os.path.join(DATA, name)
        require_sessions(path, "sample_size.py (observed yield)")
        for _s, log in session_files(path):
            events, _bad = read_log(log)
            if not events:
                continue
            sessions += 1
            for e in events:
                if e.get("kind") != "guard_decision":
                    continue
                verdict = ((e.get("meta") or {}).get("verdict") or "")
                if verdict == "deny":
                    denials += 1
                elif verdict == "overridden":
                    overrides += 1
    return sessions, denials, overrides


def needed(p, halfwidth_pts, conf, deff):
    """Events required for a half-width, then sessions, with clustering."""
    z = Z[conf]
    e = halfwidth_pts / 100.0
    n_events = (z * z * p * (1 - p)) / (e * e) * deff
    return int(math.ceil(n_events))


def main():
    sessions, denials, overrides = observed_yield()
    total = denials + overrides
    if not sessions:
        print("\n  no agy archives found\n")
        return 1
    per_session = float(total) / sessions
    p = float(overrides) / total if total else 0.0

    print("")
    print("  MEASURED FROM THE ARCHIVES ON DISK")
    print("    sessions with events          %6d" % sessions)
    print("    guard decisions               %6d  (%d deny, %d overridden)"
          % (total, denials, overrides))
    print("    decisions per session         %6.2f" % per_session)
    print("    override rate                 %6.1f%%" % (100 * p))
    print("    design effect applied         %6.2f  (session clustering)"
          % DESIGN_EFFECT)
    print("")
    print("  WHAT EACH PRECISION TARGET COSTS")
    print("  %-12s %10s %12s %14s" %
          ("half-width", "conf", "events", "sessions"))
    for conf in (95, 99):
        for hw in (5.0, 3.0, 2.0, 1.0, 0.5):
            ev = needed(p, hw, conf, DESIGN_EFFECT)
            ss = int(math.ceil(ev / per_session)) if per_session else 0
            print("  +/- %-8.1f %10d%% %12s %14s"
                  % (hw, conf, "{:,}".format(ev), "{:,}".format(ss)))
    print("")
    print("  READ THIS BEFORE PICKING A TARGET.")
    print("  The session column is what has to be COLLECTED. At the rate the")
    print("  API harness runs, a session is on the order of a minute, so")
    print("  divide by 60 for rough hours on one process - then divide again")
    print("  by however many run in parallel.")
    print("")
    print("  Precision below about a point stops being the binding constraint")
    print("  on whether a reviewer believes the result. At that width the")
    print("  question is no longer sampling error but whether the ESTIMAND is")
    print("  right - the tasks, the ruleset, the harness. Those are answered")
    print("  by replication across cells, not by more sessions in one cell.")
    print("")
    return 0


if __name__ == "__main__":
    _rc = main()
    import archive as _archive
    _archive.report_read_losses("sample_size.py")
    sys.exit(_rc)
