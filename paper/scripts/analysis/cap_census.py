#!/usr/bin/env python
"""Was the session cap binding? Answered from the record that survives it."""

import argparse
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import wilson  # noqa: E402

DATA = os.path.join("paper", "data")

CAP_SECONDS = 420
CAP_SLACK = 5


def claude_archives():
    """Every archive in paper/data written by the Claude Code harness."""
    out = []
    try:
        names = sorted(os.listdir(DATA))
    except OSError:
        return out
    for name in names:
        base = os.path.join(DATA, name)
        cj = os.path.join(base, "campaign.json")
        if not os.path.isdir(base) or not os.path.exists(cj):
            continue
        try:
            camp = json.load(io.open(cj, encoding="utf-8", errors="replace"))
        except ValueError:
            camp = {}
        out.append((name, base, camp))
    return out


def sessions_of(base):
    """(name, label, result_bytes) per session directory."""
    for name in sorted(os.listdir(base)):
        d = os.path.join(base, name)
        lj = os.path.join(d, "label.json")
        if not os.path.isdir(d) or not os.path.exists(lj):
            continue
        try:
            lab = json.load(io.open(lj, encoding="utf-8", errors="replace"))
        except ValueError:
            continue
        rj = os.path.join(d, "result.json")
        rb = os.path.getsize(rj) if os.path.exists(rj) else None
        yield name, lab, rb


def q(sorted_vals, p):
    return sorted_vals[min(len(sorted_vals) - 1, int(p * len(sorted_vals)))]


def claude_report():
    arcs = claude_archives()
    if not arcs:
        print("")
        print("  No Claude Code archive found under %s (no campaign.json)."
              % DATA)
        print("  REFUSING to report. An empty sample is not evidence that the")
        print("  cap did not bind - that is precisely the error this script")
        print("  exists to prevent.")
        return 2

    print("")
    print("Claude Code arms: session duration against the %d s cap"
          % CAP_SECONDS)
    print("  read from label.json (survives the kill), with the max that")
    print("  result.json alone would have shown for comparison")
    print("")
    print("  %-26s %5s %7s %7s %7s %9s %8s %8s"
          % ("archive", "n", "median", "p90", "max", "result-max",
             "at cap", "exit=124"))

    grand_cap = []
    grand_n = 0
    for name, base, camp in arcs:
        cap = camp.get("session_timeout_seconds") or CAP_SECONDS
        lab_s, res_s, at_cap, e124 = [], [], [], 0
        for sname, lab, rb in sessions_of(base):
            sec = lab.get("seconds")
            if sec is None:
                continue
            lab_s.append(sec)
            if lab.get("exit") == 124:
                e124 += 1
            if sec >= cap - CAP_SLACK:
                at_cap.append((name, sname, lab, rb))
            # What models.py would have seen: result.json, when parseable.
            if rb:
                rj = os.path.join(base, sname, "result.json")
                try:
                    j = json.load(io.open(rj, encoding="utf-8",
                                          errors="replace"))
                except ValueError:
                    j = {}
                ms = j.get("duration_ms") or 0
                if ms:
                    res_s.append(ms / 1000.0)
        if not lab_s:
            print("  %-26s %5s   (no label.json - not counted)" % (name, "-"))
            continue
        lab_s.sort()
        res_s.sort()
        grand_n += len(lab_s)
        grand_cap.extend(at_cap)
        print("  %-26s %5d %6.0fs %6.0fs %6.0fs %8s %8d %8d"
              % (name, len(lab_s), q(lab_s, 0.5), q(lab_s, 0.9), lab_s[-1],
                 ("%.0fs" % res_s[-1]) if res_s else "none",
                 len(at_cap), e124))

    print("")
    if not grand_n:
        print("  Every archive present is unreadable. REFUSING to conclude.")
        return 2

    k = len(grand_cap)
    lo, hi = wilson(k, grand_n)
    print("  %d of %d sessions reached the cap (%.1f%% [%.1f, %.1f])."
          % (k, grand_n, 100.0 * k / grand_n, 100 * lo, 100 * hi))
    if not k:
        print("  The cap did not bind in any archive READ ABOVE. That is a")
        print("  statement about those archives and no others; arms absent")
        print("  from this checkout are not evidence either way.")
        return 0

    events = sum((s[2].get("denials") or 0) for s in grand_cap)
    at_risk = sum(1 for s in grand_cap if (s[2].get("denials") or 0) > 0)
    print("  They carry %d denial event(s), every one of them censored:" % events)
    print("")
    print("  %-46s %5s %5s %8s %8s %7s"
          % ("session", "sec", "exit", "timeout", "denials", "res.json"))
    for _arc, sname, lab, rb in grand_cap:
        print("  %-46s %5s %5s %8s %8s %7s"
              % (sname[:46], lab.get("seconds"), lab.get("exit"),
                 lab.get("timeout"), lab.get("denials"),
                 "0 bytes" if rb == 0 else (rb if rb is not None else "none")))
    print("")
    print("  Every one has an empty result.json, which is why a result.json")
    print("  census reported zero. The cap BOUND. Any sentence in the paper")
    print("  asserting otherwise is false of these archives.")
    print("")
    print("  How many CLASSIFIED events this can actually mislabel: %d."
          % at_risk)
    print("  The guard daemon writes its own log and the harness exports it")
    print("  after the kill, so these sessions' guard_decisions ARE in the")
    print("  event corpus. Within one session only the LAST denial is at")
    print("  risk: any earlier one is followed by the tool call the next")
    print("  denial fired on, so it cannot be scored 'no further tool call'.")
    print("  %d of the %d capped sessions carry any denial, so at most %d"
          % (at_risk, k, at_risk))
    print("  event(s) can be truncation wearing a stopping label.")
    ledger_check(arcs, k)
    return 1


def ledger_check(arcs, from_dirs):
    """Second source for the at-cap count: the campaign's own worker ledger."""
    tot = hits = 0
    for _name, base, _camp in arcs:
        for fn in sorted(os.listdir(base)):
            if not (fn.startswith("sessions.") and fn.endswith(".jsonl")):
                continue
            for line in io.open(os.path.join(base, fn), encoding="utf-8",
                                errors="replace"):
                line = line.strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                except ValueError:
                    continue
                tot += 1
                if j.get("timeout") or j.get("exit") == 124:
                    hits += 1
    if not tot:
        return
    print("")
    print("  Cross-check against the campaign worker ledger, which records")
    print("  sessions whose directories are not in the export: %d of %d"
          % (hits, tot))
    print("  timed out, against %d from the directory walk -- %s."
          % (from_dirs,
             "the two sources agree" if hits == from_dirs
             else "THE TWO SOURCES DISAGREE, do not quote either"))


def api_report():
    arcs = sorted(d for d in os.listdir(DATA)
                  if d.startswith("denials-api-")
                  and os.path.exists(os.path.join(DATA, d, "usage.jsonl")))
    if not arcs:
        print("")
        print("  No API archive with usage.jsonl under %s. REFUSING to"
              % DATA)
        print("  report a truncation rate over nothing.")
        return 2

    n_all = n_bank = trunc_all = trunc_bank = 0
    for a in arcs:
        path = os.path.join(DATA, a, "usage.jsonl")
        for line in io.open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except ValueError:
                continue
            hit = str(j.get("outcome") or "").split(":")[0] == "max-steps"
            n_all += 1
            trunc_all += hit
            if j.get("banked"):
                n_bank += 1
                trunc_bank += hit

    print("")
    print("API corpus: sessions truncated at the step cap (%d archives)"
          % len(arcs))
    lo, hi = wilson(trunc_bank, n_bank)
    print("  banked (the analysed corpus)  %d/%d = %.1f%% [%.1f, %.1f]"
          % (trunc_bank, n_bank, 100.0 * trunc_bank / n_bank,
             100 * lo, 100 * hi))
    lo, hi = wilson(trunc_all, n_all)
    print("  all attempts                  %d/%d = %.1f%% [%.1f, %.1f]"
          % (trunc_all, n_all, 100.0 * trunc_all / n_all, 100 * lo, 100 * hi))
    print("")
    print("  The %d unbanked attempts never enter any analysis, so the"
          % (n_all - n_bank))
    print("  banked rate is the one a claim about the corpus must quote.")
    print("  Quoting the all-attempts rate understates truncation by %.1f pts."
          % (100.0 * trunc_bank / n_bank - 100.0 * trunc_all / n_all))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", action="store_true",
                    help="step-cap truncation in the API corpus")
    ap.add_argument("--all", action="store_true", help="both corpora")
    args = ap.parse_args()
    rc = 0
    if args.all or not args.api:
        rc = claude_report()
    if args.all or args.api:
        rc = api_report() or rc
    print("")
    return rc


if __name__ == "__main__":
    sys.exit(main())
