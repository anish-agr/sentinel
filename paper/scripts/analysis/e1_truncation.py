#!/usr/bin/env python
"""E1 - how much the 200-character ledger truncation can actually distort."""

import argparse
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import wilson  # noqa: E402

CAP = 200


def sessions(archive):
    from archive import require_nested
    require_nested(archive, "e1_truncation.py (permission_denials)")
    for d in sorted(os.listdir(archive)):
        base = os.path.join(archive, d)
        if os.path.isdir(base):
            yield d, base


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--archive", default=os.path.join("paper", "data",
                                                      "denials"))
    args = ap.parse_args()

    denied_total = 0          # full-text denial records found
    denied_long = 0           # ... whose command exceeds the cap
    at_risk_events = 0        # guard_decisions whose summary sits at the cap
    guard_events = 0
    sessions_with_result = 0
    sessions_with_denials = 0
    shell_calls = 0
    shell_truncated = 0
    longest = 0

    for _name, base in sessions(args.archive):
        ev = os.path.join(base, "events.jsonl")
        rj = os.path.join(base, "result.json")

        if os.path.exists(ev):
            for line in io.open(ev, encoding="utf-8", errors="replace"):
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                kind = e.get("kind")
                summary = e.get("args_summary") or ""
                truncated = summary.endswith("...")
                if kind == "tool_call" and e.get("tool") in ("Bash",
                                                             "PowerShell"):
                    shell_calls += 1
                    if truncated:
                        shell_truncated += 1
                elif kind == "guard_decision":
                    guard_events += 1
                    if truncated:
                        at_risk_events += 1

        if os.path.exists(rj):
            sessions_with_result += 1
            try:
                r = json.load(io.open(rj, encoding="utf-8",
                                      errors="replace"))
            except ValueError:
                continue
            pds = r.get("permission_denials") or []
            if pds:
                sessions_with_denials += 1
            for pd in pds:
                denied_total += 1
                ti = pd.get("tool_input") or {}
                cmd = ti.get("command") or json.dumps(ti)
                longest = max(longest, len(cmd))
                if len(cmd) > CAP:
                    denied_long += 1

    print("")
    print("E1 - ledger truncation, bounded from the full-text record")
    print("archive  %s" % args.archive)
    print("")
    lo, hi = wilson(shell_truncated, shell_calls)
    print("  shell calls truncated (marked)        %d / %d = %.1f%% [%.1f, %.1f]"
          % (shell_truncated, shell_calls,
             100.0 * shell_truncated / shell_calls if shell_calls else 0,
             100 * lo, 100 * hi))
    lo, hi = wilson(denied_long, denied_total)
    print("  DENIED commands over the cap (exact)  %d / %d = %.1f%% [%.1f, %.1f]"
          % (denied_long, denied_total,
             100.0 * denied_long / denied_total if denied_total else 0,
             100 * lo, 100 * hi))
    print("  longest denied command                %d chars" % longest)
    print("  guard events with a truncated summary %d / %d"
          % (at_risk_events, guard_events))
    print("  sessions with result.json             %d (with denials: %d)"
          % (sessions_with_result, sessions_with_denials))
    print("")
    print("  Reading: the identical-retry comparison operates on truncated")
    print("  summaries, so only denial events carrying a truncated summary")
    print("  can collide two different commands. The count above is that")
    print("  exposure, exactly; the full-text denial record exists in")
    print("  result.json for the events it covers, so the denial-side rate")
    print("  is exact, not a floor, over that coverage. The machine-writes")
    print("  sweep retains its floor caveat: it scans all calls, not only")
    print("  denials.")
    print("")
    print("  COVERAGE IS NOT 100%. Reconciled 2026-08-16: the harness")
    print("  under-records some mid-session denials (mostly Bash, not")
    print("  timeout-correlated, cause internal to the harness), so the")
    print("  full-text record covers about 92% of guard events. For the")
    print("  remainder the truncated summary is the only record, and the")
    print("  count above bounds their exposure.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
