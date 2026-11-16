#!/usr/bin/env python3
"""Run B, achieved against target: the report `run-b-declaration.md` promises."""

import argparse
import glob
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
for _p in (HERE, os.path.join(REPO, "paper", "scripts", "api")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import stats                                    # noqa: E402
import archive as arch                          # noqa: E402
import accrual_monitor as am                    # noqa: E402

CONFIRMATORY = ("defer", "full")


def achieved(data=None):
    """(events, sessions, target) as the STOPPING RULE counted them."""
    baseline = am.baseline_set(am.BASELINE)
    events, sessions = am.denial_events(data or am.DATA, baseline=baseline)
    return events, sessions, am.EVENT_TARGET


def clean_counts(data=None):
    """Per arm: (overrides, denial events, sessions), off-instrument excluded."""
    data = data or am.DATA
    base = am.baseline_set(am.BASELINE)
    if base is None:
        raise RuntimeError(
            "\n\n"
            "  THE RUN B BASELINE CENSUS COULD NOT BE READ, so no reader can\n"
            "  say which sessions predate the confirmatory run.\n"
            "\n"
            "  Spellings tried:\n"
            "    %s\n"
            "    %s\n"
            "\n"
            "  Refusing rather than counting the 631-session exploratory\n"
            "  pilot toward a confirmatory target. Excluding it, defer is 787\n"
            "  events and defer -> full is +14.77 points; pooling it silently\n"
            "  gives 812 and +14.90, which is what the release printed while\n"
            "  the paper said otherwise.\n"
            % (am.BASELINE_WORKING, am.BASELINE_SHIPPED))
    contam = set(arch.contaminated_sessions())
    out = {}
    for arm in am.ARMS:
        over = deny = sess = 0
        for name in sorted(os.listdir(data)):
            if am.arm_of(name) != arm:
                continue
            for path in glob.glob(os.path.join(data, name, "events",
                                                "*.jsonl")):
                rel = os.path.relpath(path, data).replace(os.sep, "/")
                if rel in base or rel in contam:
                    continue
                sess += 1
                try:
                    fh = io.open(path, encoding="utf-8", errors="replace")
                except (IOError, OSError):
                    continue
                with fh:
                    for line in fh:
                        if '"guard_decision"' not in line:
                            continue
                        try:
                            e = json.loads(line)
                        except ValueError:
                            continue
                        v = (e.get("meta") or {}).get("verdict")
                        if v == "deny":
                            deny += 1
                        elif v == "overridden":
                            over += 1
        out[arm] = (over, deny + over, sess)
    return out


def mde_for(events, sessions, arms=CONFIRMATORY, deff=1.0):
    """Achieved MDE in percentage points for one contrast."""
    a, b = arms
    n1, n2 = sessions.get(a, 0), sessions.get(b, 0)
    k1, k2 = events.get(a, 0), events.get(b, 0)
    if not n1 or not n2:
        return None
    p_bar = float(k1 + k2) / float(n1 + n2)
    # deff scales the variance, so the half-width scales with its square root;
    # mdd is linear in that, so scaling the effective n by deff is equivalent
    # and keeps the arithmetic in one place.
    return 100.0 * stats.mdd(n1 / deff, n2 / deff, p_bar)


def report(out=sys.stdout, data=None, deff=1.0):
    events, sessions, target = achieved(data)
    should_stop, reason, detail = am.verdict(data or am.DATA)

    out.write("\n  RUN B, ACHIEVED AGAINST TARGET\n")
    out.write("  the report run-b-declaration.md commits to, "
              "and nothing more\n\n")
    out.write("  %-9s %9s %9s %9s %9s\n"
              % ("arm", "events", "target", "short", "sessions"))
    short_arms = []
    for arm in am.ARMS:
        k, n = events.get(arm, 0), sessions.get(arm, 0)
        gap = max(0, target - k)
        if gap:
            short_arms.append((arm, gap))
        out.write("  %-9s %9d %9d %9s %9d\n"
                  % (arm, k, target, gap or "-", n))

    out.write("\n  stop rule that binds: %s\n" % (reason or "none yet"))
    if isinstance(detail, dict):
        out.write("    spend %s of %s, deadline %s\n"
                  % (("$%.2f" % detail["usd"]) if "usd" in detail else "?",
                     "$%.2f" % am.BUDGET_USD, am.DEADLINE))
    elif detail:
        out.write("    %s\n" % detail)

    clean = clean_counts(data)
    out.write("\n  PRE-REGISTERED OUTCOME - override rate, "
              "overridden/(deny+overridden)\n")
    out.write("  off-instrument sessions excluded, as every published "
              "figure must be\n\n")
    for arm in am.ARMS:
        k, n, sess = clean[arm]
        lo, hi = stats.wilson(k, n)
        out.write("    %-9s %5d / %-5d = %6.2f%%  [%5.2f, %5.2f]  "
                  "%d sessions\n"
                  % (arm, k, n, 100.0 * k / n if n else 0.0,
                     100 * lo, 100 * hi, sess))

    a, b = CONFIRMATORY
    k1, n1, _ = clean[a]
    k2, n2, _ = clean[b]
    if n1 and n2:
        lo, hi = stats.newcombe(k2, n2, k1, n1)
        d = 100.0 * k2 / n2 - 100.0 * k1 / n1
        out.write("\n  CONFIRMATORY  %s -> %s   %+.2f points  "
                  "[%+.2f, %+.2f]  Newcombe 95%%\n" % (a, b, d, 100 * lo,
                                                       100 * hi))
        out.write("    the interval %s zero\n"
                  % ("excludes" if lo > 0 or hi < 0 else "includes"))
        p_bar = float(k1 + k2) / float(n1 + n2)
        # On EVENTS, which is the unit of the proportion, and at the Holm
        # step level for a family of three - not at a bare 0.05.
        m = 100.0 * stats.mdd(n1 / deff, n2 / deff, p_bar, alpha=0.05 / 3.0)
        out.write("    achieved MDE %.2f points at the Holm k=3 step level "
                  "(deff %.2f)\n" % (m, deff))

    invariant_k = sum(clean[x][0] for x in am.ARMS if x != b)
    invariant_n = sum(clean[x][1] for x in am.ARMS if x != b)
    out.write("\n  THE INVARIANT: %d override(s) in %d events across the "
              "%d arms\n  that never mention one\n"
              % (invariant_k, invariant_n, len(am.ARMS) - 1))

    if short_arms:
        out.write("\n  SHORTFALL, reported and not absorbed:\n")
        for arm, gap in short_arms:
            out.write("    %-9s %d event(s) short of %d\n"
                      % (arm, gap, target))
    else:
        out.write("\n  every arm reached the criterion ON THE ACCRUAL COUNT\n")
    # AND THE ACCRUAL COUNT IS NOT THE CORPUS COUNT. Said here rather than
    # left for a reader to derive, because the difference decided when the
    # run stopped.
    gap = [(a, am.EVENT_TARGET - clean[a][1]) for a in am.ARMS
           if clean[a][1] < am.EVENT_TARGET]
    if gap:
        out.write("\n  ON THE CORPUS, off-instrument sessions excluded, "
                  "it did not:\n")
        for arm, g in gap:
            out.write("    %-9s %d event(s) short of %d\n"
                      % (arm, g, am.EVENT_TARGET))
        out.write("    The criterion fired at 05:45Z on counts that include a\n"
                  "    window quarantined at 05:46Z. accrual_monitor never\n"
                  "    applied the exclusion; the corpus figures above do.\n")
    out.write("\n")
    return 0


def selftest():
    """Prove the three promised quantities move with the data."""
    ok = True

    ev = {"defer": 500, "full": 900, "terse": 800, "explain": 800,
          "padded": 800}
    se = dict.fromkeys(ev, 2000)
    m_small = mde_for(ev, se)
    m_big = mde_for(ev, {k: 8000 for k in se})
    print("  MDE at n=2000 per arm   %.3f points" % m_small)
    print("  MDE at n=8000 per arm   %.3f points" % m_big)
    if not (m_big < m_small):
        print("  FAIL  MDE did not shrink when the sample grew")
        ok = False
    else:
        print("  ok    MDE shrinks as the sample grows")

    buf = io.StringIO()
    short_seen = "SHORTFALL" in _render(buf, ev, se)
    full = {k: 999 for k in ev}
    none_seen = "every arm reached the criterion" in _render(
        io.StringIO(), full, se)
    print("  ok    a short arm is reported" if short_seen
          else "  FAIL  a short arm was not reported")
    print("  ok    a complete run says so" if none_seen
          else "  FAIL  a complete run did not say so")
    ok = ok and short_seen and none_seen

    print("  PASS" if ok else "  FAIL")
    return 0 if ok else 1


def _render(buf, events, sessions):
    """The report body over supplied counts, for the control only."""
    target = am.EVENT_TARGET
    for arm in am.ARMS:
        k = events.get(arm, 0)
        if target - k > 0:
            buf.write("SHORTFALL %s\n" % arm)
    if all(events.get(a, 0) >= target for a in am.ARMS):
        buf.write("every arm reached the criterion\n")
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--deff", type=float, default=1.0,
                    help="design effect from rigor.py. 1.0 is unclustered. It is "
                         "NOT automatically conservative: the measured Kish "
                         "deff for the full arm's override rate is 0.80, "
                         "under-dispersed, so clustering would NARROW this "
                         "interval rather than widen it")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return report(deff=args.deff)


if __name__ == "__main__":
    sys.exit(main())
