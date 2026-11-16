#!/usr/bin/env python
"""Event-driven accrual for RUN B: stop on events, a clock, or a budget."""

import argparse
import glob
import io
import json
import math
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DATA = os.path.join(REPO, "paper", "data")
WORK = os.path.join(REPO, ".campaign", "api-run")
STOP_FILE = os.path.join(WORK, "STOP")

PREFIX = "denials-api-"
ARMS = ("defer", "full", "terse", "explain", "padded")


EVENT_TARGET = 787      # raw denial events per arm
BUDGET_USD = 600.0      # raised from 450 before collection
DEADLINE = "2026-08-27T06:00:00"

# Measured on the pilot: $/1k tokens on the anchor mix. Used only to decide
# whether the budget cap has bound, never to price a result.
USD_PER_1K_IN = 0.00015
USD_PER_1K_OUT = 0.0006


def arm_of(archive):
    """The arm an archive belongs to, or None."""
    if not archive.startswith(PREFIX):
        return None
    rest = archive[len(PREFIX):]
    for arm in ARMS:
        if rest.startswith(arm + "-"):
            return arm
    return None


BASELINE_WORKING = os.path.join(WORK, "run-b-pilot-sessions.json")
BASELINE_SHIPPED = os.path.join(REPO, "paper", "run-b-pilot-sessions.json")
BASELINE = (BASELINE_WORKING if os.path.exists(BASELINE_WORKING)
            else BASELINE_SHIPPED)


def baseline_set(path=BASELINE):
    """Session logs that already existed when Run B was declared."""
    if not os.path.exists(path):
        return None
    try:
        with io.open(path, encoding="utf-8") as fh:
            return set(json.load(fh).get("sessions") or [])
    except (IOError, OSError, ValueError):
        return None


def declare(data=DATA, path=BASELINE):
    """Freeze the pre-run census. Run once, before the first session."""
    seen = []
    for name in sorted(os.listdir(data)):
        if arm_of(name) is None:
            continue
        for p in glob.glob(os.path.join(data, name, "events", "*.jsonl")):
            seen.append(os.path.relpath(p, data).replace(os.sep, "/"))
    if not os.path.isdir(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))
    with io.open(path, "w", encoding="utf-8") as fh:
        json.dump({"declared": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "event_target": EVENT_TARGET, "budget_usd": BUDGET_USD,
                   "deadline": DEADLINE, "sessions": sorted(seen)}, fh,
                  indent=1)
    return len(seen)


def denial_events(data=DATA, baseline=None):
    """Raw denial events per arm, and sessions per arm. Counts, nothing else."""
    events = dict.fromkeys(ARMS, 0)
    sessions = dict.fromkeys(ARMS, 0)
    if not os.path.isdir(data):
        return events, sessions
    for name in sorted(os.listdir(data)):
        arm = arm_of(name)
        if arm is None:
            continue
        for path in glob.glob(os.path.join(data, name, "events", "*.jsonl")):
            if baseline is not None and os.path.relpath(path, data).replace(os.sep, "/") in baseline:
                continue
            sessions[arm] += 1
            try:
                with io.open(path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or '"guard_decision"' not in line:
                            continue
                        try:
                            e = json.loads(line)
                        except ValueError:
                            continue
                        if e.get("kind") != "guard_decision":
                            continue
                        verdict = (e.get("meta") or {}).get("verdict")
                        if verdict in ("deny", "overridden"):
                            events[arm] += 1
            except (IOError, OSError):
                continue
    return events, sessions


def spent_usd(data=DATA):
    """Dollars spent so far, from banked token counts."""
    tin = tout = 0
    for path in glob.glob(os.path.join(data, PREFIX + "*", "usage.jsonl")):
        try:
            with io.open(path, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    tin += int(row.get("input_tokens") or 0)
                    tout += int(row.get("output_tokens") or 0)
        except (IOError, OSError):
            continue
    return (tin / 1000.0) * USD_PER_1K_IN + (tout / 1000.0) * USD_PER_1K_OUT


def deadline_passed(now=None):
    now = time.time() if now is None else now
    tm = time.strptime(DEADLINE, "%Y-%m-%dT%H:%M:%S")
    return now >= time.mktime(tm)


def verdict(data=DATA, now=None, baseline=None):
    """(should_stop, reason, detail). Reads nuisance parameters only."""
    if baseline is None:
        baseline = baseline_set()
    events, sessions = denial_events(data, baseline)
    short = {a: EVENT_TARGET - n for a, n in events.items() if n < EVENT_TARGET}
    usd = spent_usd(data)
    detail = {"events": events, "sessions": sessions, "usd": usd,
              "short": short, "declared": baseline is not None,
              "baseline_n": len(baseline) if baseline else 0}
    if not short:
        return True, "criterion", detail
    if usd >= BUDGET_USD:
        return True, "budget", detail
    if deadline_passed(now):
        return True, "deadline", detail
    return False, "running", detail


def show(detail, reason):
    events, sessions = detail["events"], detail["sessions"]
    print("")
    print("  RUN B ACCRUAL   target %d denial events per arm" % EVENT_TARGET)
    print("")
    print("  %-10s %10s %10s %10s" % ("arm", "events", "short", "sessions"))
    for arm in ARMS:
        n = events[arm]
        print("  %-10s %10d %10s %10d"
              % (arm, n, ("-" if n >= EVENT_TARGET else EVENT_TARGET - n),
                 sessions[arm]))
    print("")
    print("  spent   $%.2f of $%.2f" % (detail["usd"], BUDGET_USD))
    print("  deadline %s  (%s)"
          % (DEADLINE, "passed" if deadline_passed() else "not reached"))
    if detail.get("declared"):
        print("  baseline %d pre-declaration session log(s), excluded"
              % detail["baseline_n"])
    else:
        print("  baseline NOT DECLARED - counts include the exploratory")
        print("           pilot. Run --declare before collecting.")
    print("  status  %s" % reason)
    print("")


def selftest():
    """Positive control: prove each stop rule fires, and that none fires early."""
    import shutil
    import tempfile

    tmp = tempfile.mkdtemp(prefix="accrual-")
    ok = True

    def want(label, got, expect):
        nonlocal ok
        good = (got == expect)
        ok = ok and good
        print("  %-56s %s"
              % (label, "ok" if good else "FAIL got %r want %r" % (got, expect)))

    def spend(arm, usd, model="gemini-x"):
        """Bank `usd` of output tokens into one arm's usage.jsonl."""
        d = os.path.join(tmp, PREFIX + arm + "-" + model)
        os.makedirs(d, exist_ok=True)
        tokens = int(math.ceil(usd / USD_PER_1K_OUT * 1000.0))
        for _ in range(64):
            if usd <= 0 or (tokens / 1000.0) * USD_PER_1K_OUT >= usd:
                break
            tokens += 1
        with io.open(os.path.join(d, "usage.jsonl"), "w",
                     encoding="utf-8") as fh:
            fh.write(json.dumps({"input_tokens": 0,
                                 "output_tokens": tokens}) + "\n")

    def write(arm, n_events, model="gemini-x", session="s1"):
        d = os.path.join(tmp, PREFIX + arm + "-" + model, "events")
        os.makedirs(d, exist_ok=True)
        with io.open(os.path.join(d, session + ".jsonl"), "w",
                     encoding="utf-8") as fh:
            for i in range(n_events):
                fh.write(json.dumps({
                    "kind": "guard_decision", "seq": i,
                    "meta": {"verdict": "deny" if i % 2 else "overridden"},
                }) + "\n")
            fh.write(json.dumps({"kind": "tool_call"}) + "\n")

    try:
        want("arm_of reads the arm past a hyphenated model",
             arm_of("denials-api-defer-gemini-2.5-flash-lite-high"), "defer")
        want("arm_of refuses a non-arm archive",
             arm_of("denials-api-nonsuch-gemini-x"), None)
        want("arm_of refuses a foreign prefix",
             arm_of("denials-agy-defer-gemini-x"), None)

        for arm in ARMS:
            write(arm, 3)
        ev, se = denial_events(tmp)
        want("counts denials per arm", [ev[a] for a in ARMS], [3] * 5)
        want("counts sessions per arm", [se[a] for a in ARMS], [1] * 5)
        want("ignores non-guard events", sum(ev.values()), 15)

        stop, reason, _ = verdict(tmp, now=0)
        want("does not stop while every arm is short", (stop, reason),
             (False, "running"))

        for arm in ARMS:
            write(arm, EVENT_TARGET, session="s2")
        stop, reason, _ = verdict(tmp, now=0)
        want("stops when every arm reaches the target", (stop, reason),
             (True, "criterion"))

        shutil.rmtree(tmp)
        tmp = tempfile.mkdtemp(prefix="accrual-")
        for arm in ARMS:
            write(arm, 3)
        write("full", EVENT_TARGET, session="s2")
        stop, reason, _ = verdict(tmp, now=0)
        want("one arm at target is not the criterion", (stop, reason),
             (False, "running"))

        want("the declared cap is the pre-registered $600",
             BUDGET_USD, 600.0)
        spend("full", BUDGET_USD - 1.0)
        stop, reason, detail = verdict(tmp, now=0, baseline=set())
        want("spend below the cap does not stop it", (stop, reason),
             (False, "running"))
        want("spent_usd reads the banked tokens",
             round(detail["usd"], 2), round(BUDGET_USD - 1.0, 2))
        spend("full", BUDGET_USD)
        stop, reason, detail = verdict(tmp, now=0, baseline=set())
        want("spend at the cap stops it", (stop, reason), (True, "budget"))
        want("the cap is the declared one", detail["usd"] >= BUDGET_USD, True)
        spend("full", 0.0)

        stop, reason, _ = verdict(tmp, now=4102444800.0, baseline=set())
        want("the deadline stops it", (stop, reason), (True, "deadline"))

        # The baseline must actually exclude. Freeze the census, then add a
        # full arm's worth of events and confirm the criterion still does not
        # fire on the excluded ones.
        bl = set()
        for name in sorted(os.listdir(tmp)):
            if arm_of(name) is None:
                continue
            for p in glob.glob(os.path.join(tmp, name, "events", "*.jsonl")):
                bl.add(os.path.relpath(p, tmp).replace(os.sep, "/"))
        ev, se = denial_events(tmp, bl)
        want("a fully-excluded baseline counts zero",
             (sum(ev.values()), sum(se.values())), (0, 0))
        write("full", 5, session="s9")
        ev, _ = denial_events(tmp, bl)
        want("only post-baseline sessions accrue",
             (ev["full"], ev["defer"]), (5, 0))

        print("")
        print("  POSITIVE CONTROL %s" % ("PASSED" if ok else "FAILED"))
        print("")
        return 0 if ok else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--status", action="store_true",
                    help="print accrual and exit. Spends nothing.")
    ap.add_argument("--watch", action="store_true",
                    help="poll, and touch the STOP file when a rule binds")
    ap.add_argument("--interval", type=int, default=300,
                    help="--watch: seconds between polls")
    ap.add_argument("--declare", action="store_true",
                    help="freeze the pre-run census so the exploratory pilot "
                         "does not count toward the confirmatory target. Run "
                         "once, before the first session.")
    ap.add_argument("--selftest", action="store_true",
                    help="prove each stop rule fires. Needs no data.")
    ap.add_argument("--data", default=DATA)
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if args.declare:
        n = declare(args.data)
        print("")
        print("  declared: %d pre-existing session log(s) excluded from "
              "accrual." % n)
        print("  written to %s" % BASELINE)
        print("")
        return 0

    if args.status or not args.watch:
        stop, reason, detail = verdict(args.data)
        show(detail, reason)
        return 0

    print("  watching. Target %d events/arm, cap $%.0f, deadline %s."
          % (EVENT_TARGET, BUDGET_USD, DEADLINE))
    print("  Reads event counts, the clock, and spend. Nothing else.")
    while True:
        stop, reason, detail = verdict(args.data)
        show(detail, reason)
        if stop:
            if not os.path.isdir(WORK):
                os.makedirs(WORK)
            with io.open(STOP_FILE, "w", encoding="utf-8") as fh:
                fh.write("stopped by accrual_monitor: %s\n" % reason)
            print("  STOP written to %s" % STOP_FILE)
            print("  The run ends after the session in flight banks.")
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
