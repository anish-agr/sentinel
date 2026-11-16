#!/usr/bin/env python
"""The cross-platform portability battery, parsed from its own recorded output."""

import argparse
import io
import os
import re
import sys

DATA = os.path.join("paper", "data", "platform")


def load(path):
    return io.open(path, encoding="utf-8", errors="replace").read()


def parse(text):
    out = {}

    m = re.search(r"^os:\s+(.+)$", text, re.M)
    out["os"] = m.group(1).strip() if m else "?"
    m = re.search(r"^cpu:\s+(.+)$", text, re.M)
    out["cpu"] = m.group(1).strip() if m else "?"
    m = re.search(r"^date:\s+(\d{4}-\d{2}-\d{2})[ T](\S+)", text, re.M)
    out["date"] = ("%sT%s" % m.groups()) if m else "?"
    m = re.search(r"^commit:\s+(\S+)", text, re.M)
    out["commit"] = m.group(1) if m else "?"

    # --- the portability battery ------------------------------------------
    m = re.search(r"dangerous spellings refused\s+(\d+) of (\d+) \((\d+)%\)", text)
    if m:
        out["dangerous_refused"] = int(m.group(1))
        out["dangerous_total"] = int(m.group(2))
    m = re.search(r"of which native to \w+\s+(\d+) of (\d+) \((\d+)%\)", text)
    if m:
        out["native_refused"] = int(m.group(1))
        out["native_of"] = int(m.group(2))
    m = re.search(r"benign controls refused\s+(\d+) of (\d+)", text)
    if m:
        out["benign_refused"] = int(m.group(1))
        out["benign_total"] = int(m.group(2))
    m = re.search(r"controls\s+(\d+)/(\d+) refused", text)
    if m:
        out["live_controls"] = (int(m.group(1)), int(m.group(2)))

    # --- per-intent table --------------------------------------------------
    intents = []
    block = re.search(r"intent\s+spellings\s+refused\s+native\s+native refused\n"
                      r"((?:\s+\w+\s+\d+\s+\d+\s+\d+\s+\d+/\d+\n)+)", text)
    if block:
        for line in block.group(1).strip().splitlines():
            f = line.split()
            intents.append({"intent": f[0], "spellings": int(f[1]),
                            "refused": int(f[2]), "native": int(f[3]),
                            "native_refused": f[4]})
    out["intents"] = intents

    # --- spellings that this platform's idiom hides ------------------------
    missed = []
    for m in re.finditer(r"^\s+\*?\s*allowed\s+(macos|linux|windows)\s+(.+)$",
                         text, re.M):
        missed.append((m.group(1), m.group(2).strip()))
    out["missed_native"] = missed

    every, intent = [], None
    for line in text.splitlines():
        head = re.match(r"^\s{4}(\w+)\s*$", line)
        if head:
            intent = head.group(1)
            continue
        m = re.match(r"^\s+\*\s+allowed\s+(\S+)\s+(.+)$", line)
        if m and intent and intent != "benign_control":
            every.append((m.group(1), intent, m.group(2).strip()))
    out["missed_native_all"] = every

    # --- respelling battery -------------------------------------------------
    m = re.search(r"respellings that changed the decision\s+(\d+) of (\d+)", text)
    if m:
        out["respell_changed"] = int(m.group(1))
        out["respell_total"] = int(m.group(2))
    out["divergent"] = [x.strip() for x in
                        re.findall(r"DENY -> ALLOW\s+(.+)", text)]

    # --- concurrency --------------------------------------------------------
    m = re.search(r"serial baseline\s+([\d.]+) ms per decision", text)
    if m:
        out["serial_ms"] = float(m.group(1))
    m = re.search(r"under concurrency\s+([\d.]+) ms median,\s+([\d.]+) ms p95,"
                  r"\s+([\d.]+) max", text)
    if m:
        out["conc_median_ms"] = float(m.group(1))
        out["conc_p95_ms"] = float(m.group(2))
        out["conc_max_ms"] = float(m.group(3))
    m = re.search(r"throughput\s+([\d.]+) decisions/s", text)
    if m:
        out["throughput"] = float(m.group(1))
    m = re.search(r"slowdown at median\s+([\d.]+)x", text)
    if m:
        out["slowdown"] = float(m.group(1))
    m = re.search(r"Concurrency:\s+(\d+) workers x (\d+) decisions", text)
    if m:
        out["workers"] = int(m.group(1))

    # --- the invariants that MUST match Windows ----------------------------
    m = re.search(r"argv normalisation\s+(\d+) of (\d+)", text)
    if m:
        out["argv_norm"] = (int(m.group(1)), int(m.group(2)))
    m = re.search(r"substring match\s+(\d+) of (\d+)", text)
    if m:
        out["substring"] = (int(m.group(1)), int(m.group(2)))
    m = re.search(r"prefix match\s+(\d+) of (\d+)", text)
    if m:
        out["prefix"] = (int(m.group(1)), int(m.group(2)))
    m = re.search(r"Fidelity: (\d+) of (\d+) mutations restored", text)
    if m:
        out["reversal"] = (int(m.group(1)), int(m.group(2)))
    out["reversal_error"] = "ERROR:" in text

    over = re.findall(r"over the 25ms budget: (\d+) of (\d+)", text)
    out["over_budget_by_config"] = [(int(a), int(b)) for a, b in over]
    # Section 2 is the idle bench: allow, deny, process-only, then the
    # dead-daemon path. The first three are the paths a live call takes.
    idle = over[:3]
    out["over_budget_live"] = sum(int(a) for a, _ in idle)
    out["budget_trials_live"] = sum(int(b) for _, b in idle)

    m = re.search(r"=== 17\..*?(?==== 18\.|\Z)", text, re.S)
    sec17 = m.group(0) if m else ""
    sat = re.findall(r"over the 25ms budget: (\d+) of (\d+)", sec17)
    # Within section 17 the dead-daemon path is last, same as section 2.
    out["saturated_by_config"] = [(int(a), int(b)) for a, b in sat]
    out["saturated_over"] = sum(int(a) for a, _ in sat[:-1]) if len(sat) > 1 \
        else (int(sat[0][0]) if sat else None)
    out["saturated_of"] = sum(int(b) for _, b in sat[:-1]) if len(sat) > 1 \
        else (int(sat[0][1]) if sat else None)
    m = re.search(r"saturating (\d+) cores", text)
    out["saturated_cores"] = int(m.group(1)) if m else None

    m = re.search(r"the deny-path command was allowed (\d+) of (\d+) times", text)
    if m:
        out["failopen_allowed"] = int(m.group(1))
        out["failopen_of"] = int(m.group(2))

    done = re.search(r"Verified: (\d+) invocations with no daemon, all allowed",
                     sec17)
    if done and not re.search(r"the deny-path command was allowed", sec17):
        out["saturated_denied"] = int(done.group(1))
    out["case_insensitive"] = "case-INSENSITIVE volume" in text

    out["battery_ran"] = "dangerous_refused" in out
    return out


def measure(data=DATA):
    out = {}
    if not os.path.isdir(data):
        return out
    for name in sorted(os.listdir(data)):
        if not name.endswith("-results.txt"):
            continue
        platform = name.split("-results")[0]
        out[platform] = parse(load(os.path.join(data, name)))
    return out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--spellings", action="store_true",
                    help="print every native spelling the ruleset missed")
    args = ap.parse_args()

    runs = measure(args.data)
    if not runs:
        print("  no platform result files under %s" % args.data)
        return 1

    for platform, r in sorted(runs.items()):
        print("")
        print("  PLATFORM BATTERY - %s" % platform)
        print("  %s, %s" % (r.get("os", "?"), r.get("cpu", "?")))
        live = r.get("live_controls")
        if live:
            print("  guard live: %d/%d controls refused" % live)
        print("")

        print("  Same intent, different idiom:")
        for it in r.get("intents", []):
            print("    %-22s %2d spellings  %2d refused   native %s"
                  % (it["intent"], it["spellings"], it["refused"],
                     it["native_refused"]))
        d, t = r.get("dangerous_refused"), r.get("dangerous_total")
        if d is not None:
            print("")
            print("    dangerous spellings refused   %2d of %2d  (%.0f%%)"
                  % (d, t, 100.0 * d / t))
            print("    of which native to %-10s %2d of %2d"
                  % (platform, r.get("native_refused", 0), r.get("native_of", 0)))
            print("    benign controls refused       %2d of %2d  (must be 0)"
                  % (r.get("benign_refused", 0), r.get("benign_total", 0)))

        c, tot = r.get("respell_changed"), r.get("respell_total")
        if c is not None:
            print("")
            print("  Respelling: %d of %d changed the decision. Divergent:" % (c, tot))
            for x in r.get("divergent", []):
                print("    DENY -> ALLOW  %s" % x[:64])

        if "serial_ms" in r:
            print("")
            print("  Concurrency, %d workers: serial %.2f ms, median %.2f ms, "
                  "p95 %.2f ms" % (r.get("workers", 0), r["serial_ms"],
                                   r.get("conc_median_ms", 0),
                                   r.get("conc_p95_ms", 0)))
            print("    %.0f decisions/s, %.2fx slowdown at the median"
                  % (r.get("throughput", 0), r.get("slowdown", 0)))
        print("  over the 25 ms budget, live paths only: %d of %d"
              % (r.get("over_budget_live", 0), r.get("budget_trials_live", 0)))
        print("    (the dead-daemon path is excluded: it exceeds the budget by")
        print("     construction wherever the connect timeout does)")
        if r.get("failopen_allowed"):
            print("")
            print("  MEDIATION REGRESSION: %d of %d invocations of a"
                  % (r["failopen_allowed"], r["failopen_of"]))
            print("  definitively-deniable command were allowed. This is the")
            print("  fault the hook's connect/retry split exists to prevent")
            print("  (a busy daemon read as an absent one). If it appears in a")
            print("  run recorded AFTER that fix, the fix regressed and the")
            print("  build must fail rather than the number be written up.")
        elif r.get("saturated_denied"):
            # Printed because the passing case is otherwise SILENT, and a
            # silence that looks like an unrun probe got a true result struck
            # from the paper once already.
            print("")
            # "all %d", not "%d of %d": there is one count here, and printing
            # it twice manufactures a ratio whose denominator cannot differ
            # from its numerator.
            print("  MEDIATION HELD UNDER LOAD: all %d invocations of a"
                  % r["saturated_denied"])
            print("  definitively-deniable command were refused with every")
            print("  core saturated. The saturated bench ran to completion,")
            print("  which it cannot do if even one was allowed - the abort")
            print("  above is what that failure looks like.")
        if not r.get("battery_ran"):
            print("")
            print("  NOTE: the spelling battery did not execute in this run,")
            print("  so this platform contributes latency and invariants only.")

        print("")
        print("  Invariants that must match Windows:")
        for key, label, want in (("argv_norm", "argv normalisation", (56, 56)),
                                 ("substring", "substring match", (46, 56)),
                                 ("prefix", "prefix match", (10, 56))):
            got = r.get(key)
            flag = "ok" if got == want else "DIFFERS from Windows %s" % (want,)
            print("    %-22s %s   %s" % (label, got, flag))
        rev = r.get("reversal")
        if rev:
            note = " (one case did not exercise a mutation on this platform)" \
                if r.get("reversal_error") else ""
            print("    %-22s %d of %d restored byte-for-byte%s"
                  % ("reversal battery", rev[0], rev[1], note))

        if args.spellings:
            every = r.get("missed_native_all", [])
            print("")
            print("  Native spellings this ruleset did NOT refuse (%d, against"
                  " %d native offered):"
                  % (len(every), r.get("native_of", 0)))
            for tag, intent, cmd in every:
                print("    %-8s %-18s %s" % (tag, intent, cmd[:70]))
            generic = [c for t, _i, c in every if t == "any"]
            if generic:
                print("    -- %d of those are tagged `any`: not this platform's"
                      " idiom but a" % len(generic))
                print("       ruleset gap every platform shares.")
    print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
