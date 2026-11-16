#!/usr/bin/env python
"""C16b - one monitor, one agent population, two action spaces."""

import argparse
import collections
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import wilson, newcombe, cluster_diff_paired  # noqa: E402

# The agent's own vocabulary, split by whether the action carries its semantics.
SHELL = {"Bash", "PowerShell"}
FILE_TOOL = {"Read", "Write", "Edit", "NotebookEdit", "Glob", "Grep"}


def space_of(tool):
    if tool in SHELL:
        return "shell"
    if tool in FILE_TOOL:
        return "file tool"
    return "other tool"


def sessions(archive):
    from archive import require_nested
    require_nested(archive, "own_action_space.py (action-space split)")
    for d in sorted(os.listdir(archive)):
        path = os.path.join(archive, d, "events.jsonl")
        if not os.path.isfile(path):
            continue
        events = []
        with io.open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        pass
        yield d, events


def calls_in(archive):
    """One record per recorded tool call, with everything the comparison needs."""
    out = []
    n_sessions = 0
    for name, events in sessions(archive):
        n_sessions += 1
        # The guard records a decision per (tool, argument text). A call with a
        # decision is one this ruleset reached; everything else it did not see.
        seen = collections.Counter()
        rules = collections.defaultdict(list)
        for e in events:
            if e.get("kind") == "guard_decision":
                key = (e.get("tool"), e.get("args_summary"))
                seen[key] += 1
                rules[key].append((e.get("meta") or {}).get("rule") or "?")
        for e in events:
            if e.get("kind") != "tool_call":
                continue
            tool = e.get("tool") or "?"
            key = (tool, e.get("args_summary"))
            hit = seen[key] > 0
            rule = ""
            if hit:
                seen[key] -= 1
                if rules[key]:
                    rule = rules[key].pop(0)
            rev = e.get("reversibility")
            out.append({
                "session": name,
                # Which rule refused it, when one did - the capacity-adjusted
                # comparison needs to know whether the rule that fired is one
                # that can fire in both action spaces.
                "rule": rule,
                # The recorded text itself, so external-ruleset replications
                # can evaluate third-party predicates over the same call.
                "args_summary": e.get("args_summary") or "",
                "tool": tool,
                # The table generator groups shell against everything else, so
                # it wants the two-way split; the report below wants three.
                "space": "shell" if space_of(tool) == "shell" else "tool",
                "detail": space_of(tool),
                "refused": hit,
                # Absent reversibility means the recorder did not label it, and
                # an unlabelled call is not evidence of a mutation.
                "read_only": (rev == "read_only" or not rev),
                "reversibility_absent": not rev,
            })
    return out, n_sessions


def capacity(records):
    """R37 - the action-space gap with rule-authoring bias factored out."""
    both_rules = {c["rule"] for c in records
                  if c["refused"] and c["space"] != "shell" and c["rule"]}
    ns = nt = ks = kt = 0
    # Per-session clusters, built in the same pass as the marginals so the
    # numerator behind the interval cannot drift from the numerator beside it.
    per = collections.defaultdict(lambda: [0, 0, 0, 0])
    for c in records:
        if c["read_only"]:
            continue
        capable = c["refused"] and c["rule"] in both_rules
        row = per[c["session"]]
        if c["space"] == "shell":
            ns += 1
            row[1] += 1
            ks += 1 if capable else 0
            row[0] += 1 if capable else 0
        else:
            nt += 1
            row[3] += 1
            kt += 1 if capable else 0
            row[2] += 1 if capable else 0
    clusters = [tuple(v) for v in per.values()]
    print("")
    print("Capacity-adjusted comparison (rules that fire in BOTH spaces: %s)"
          % ", ".join(sorted(both_rules)))
    for label, k, n in (("shell", ks, ns), ("tools", kt, nt)):
        lo, hi = wilson(k, n)
        print("  %-6s %d/%d = %.1f%%  [%.1f, %.1f]"
              % (label, k, n, 100.0 * k / n if n else 0, 100 * lo, 100 * hi))
    _p1, _p2, d_, lo, hi, K = cluster_diff_paired(clusters)
    d = 100.0 * d_
    print("  gap    %+.1f points  95%% CI [%+.1f, %+.1f]  %s"
          "   (paired session-clustered, K=%d, PRIMARY)"
          % (d, 100 * lo, 100 * hi,
             "excludes 0" if lo > 0 or hi < 0 else "INCLUDES 0", K))
    nlo, nhi = newcombe(ks, ns, kt, nt)
    print("  gap    %+.1f points  95%% CI [%+.1f, %+.1f]  %s"
          "   (Newcombe, independent samples, RETIRED for this pair)"
          % (d, 100 * nlo, 100 * nhi,
             "excludes 0" if nlo > 0 or nhi < 0 else "INCLUDES 0"))
    if (nlo > 0 or nhi < 0) and not (lo > 0 or hi < 0):
        print("  NOTE: the retired estimator excludes 0 here and the primary")
        print("  one does not. Any sentence that reads a SIGN off this")
        print("  contrast is reading it off the retired interval.")
    print("  Reading: within the shared capacity the same predicate faces")
    print("  both spaces; the remaining gap is the action-space effect with")
    print("  authoring bias factored out. It is a bound, not the headline.")


def raw_labels(archive):
    """Census of the recorder's `reversibility` field over every tool_call."""
    counts = collections.Counter()
    for _name, events in sessions(archive):
        for e in events:
            if e.get("kind") != "tool_call":
                continue
            rev = e.get("reversibility")
            counts[rev if rev else "(absent or empty)"] += 1
    return counts


def flat_labels(archive):
    """Same census for the Antigravity layout, which is flat, not nested."""
    from archive import is_contaminated
    counts = collections.Counter()
    root = os.path.join(archive, "events")
    if not os.path.isdir(root):
        return counts
    for name in sorted(os.listdir(root)):
        if not name.endswith(".jsonl"):
            continue
        if is_contaminated(os.path.join(root, name)):
            continue
        with io.open(os.path.join(root, name), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("kind") != "tool_call":
                    continue
                rev = e.get("reversibility")
                counts[rev if rev else "(absent or empty)"] += 1
    return counts


def reversibility(archive, records):
    """Is line 127's missing-label default load-bearing, or latent?"""
    counts = raw_labels(archive)
    total = sum(counts.values())
    absent = counts.get("(absent or empty)", 0)
    print("")
    print("Reversibility label census - %s" % archive)
    print("  %-24s %8s %8s" % ("recorded value", "calls", "share"))
    for value, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print("  %-24s %8d %7.2f%%" % (value, n, 100.0 * n / total))
    print("  %-24s %8d" % ("TOTAL tool_call", total))
    print("")
    print("  calls with NO reversibility label: %d of %d (%.2f%%)"
          % (absent, total, 100.0 * absent / total if total else 0.0))

    def block(include):
        """(totals, refusals, per-session clusters) under one missing-label rule."""
        tot = collections.Counter()
        hit = collections.Counter()
        per = collections.defaultdict(lambda: [0, 0, 0, 0])
        for c in records:
            if not include(c):
                continue
            side = "shell" if c["space"] == "shell" else "tools"
            tot[side] += 1
            if c["refused"]:
                hit[side] += 1
            slot = 0 if c["space"] == "shell" else 2
            per[c["session"]][slot] += 1 if c["refused"] else 0
            per[c["session"]][slot + 1] += 1
        return tot, hit, [tuple(v) for v in per.values()]

    base, base_hit, base_clusters = block(lambda c: not c["read_only"])
    alt, alt_hit, alt_clusters = block(
        lambda c: not c["read_only"] or c["reversibility_absent"])

    print("")
    print("Headline both ways (mutating calls only)")
    for title, tot, hit, clusters in (
            ("as published   (absent -> read-only)", base, base_hit,
             base_clusters),
            ("default flipped (absent -> mutating)", alt, alt_hit,
             alt_clusters)):
        ns, nt = tot["shell"], tot["tools"]
        ks, kt = hit["shell"], hit["tools"]
        if not (ns and nt):
            continue
        _p1, _p2, d, lo, hi, k_sessions = cluster_diff_paired(clusters)
        if k_sessions < 2:
            raise RuntimeError("cannot cluster the action-space difference: "
                               "%d session(s)" % k_sessions)
        print("  %s" % title)
        print("    shell %d/%d = %.1f%%   tools %d/%d = %.1f%%"
              % (ks, ns, 100.0 * ks / ns, kt, nt, 100.0 * kt / nt))
        print("    gap %+.1f points  95%% CI [%+.1f, %+.1f]  %s"
              % (100 * d, 100 * lo, 100 * hi,
                 "excludes 0" if lo > 0 or hi < 0 else "INCLUDES 0"))
        print("    paired, session-clustered over %d sessions; the estimator"
              % k_sessions)
        print("    tab-action-space.tex uses. Newcombe's independent-samples")
        print("    interval is not the right width or correlation here.")
    print("")
    if absent == 0:
        print("  VERDICT: LATENT. Every recorded call carries a label, so the")
        print("  `or not rev` branch never fires on this archive and the two")
        print("  blocks above are the same arithmetic. The default cannot be")
        print("  moving the headline because it never evaluates. What IS")
        print("  load-bearing is the read_only EXCLUSION itself, which is")
        print("  driven by explicit `read_only` labels, not by the default.")
    else:
        print("  VERDICT: LOAD-BEARING. %d calls reach the default, and the"
              % absent)
        print("  two blocks above differ. Report both.")

    print("")
    print("Same census, other harnesses on this machine")
    data = os.path.dirname(archive.rstrip(os.sep)) or "."
    for name in sorted(os.listdir(data)):
        if not name.startswith("denials-agy"):
            continue
        c = flat_labels(os.path.join(data, name))
        if not c:
            continue
        tot = sum(c.values())
        miss = c.get("(absent or empty)", 0)
        print("  %-44s %6d calls, %6d unlabelled (%.0f%%)"
              % (name[:44], tot, miss, 100.0 * miss / tot))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--archive", default=os.path.join("paper", "data", "denials"))
    ap.add_argument("--capacity", action="store_true",
                    help="R37: restrict both spaces to both-space-capable rules")
    ap.add_argument("--reversibility", action="store_true",
                    help="census the reversibility label and flip the missing-label default")
    args = ap.parse_args()

    calls = collections.Counter()
    matched = collections.Counter()
    mutating = collections.Counter()
    mut_matched = collections.Counter()
    by_tool = collections.defaultdict(lambda: [0, 0])

    records, n_sessions = calls_in(args.archive)
    if args.reversibility:
        reversibility(args.archive, records)
        return
    if args.capacity:
        capacity(records)
        return
    for c in records:
        sp = c["detail"]
        calls[sp] += 1
        by_tool[c["tool"]][0] += 1
        if c["refused"]:
            matched[sp] += 1
            by_tool[c["tool"]][1] += 1
        # Read-only calls cannot be refused by a rule about destruction, so
        # the fair comparison also excludes them from both sides.
        if not c["read_only"]:
            mutating[sp] += 1
            if c["refused"]:
                mut_matched[sp] += 1

    print("")
    print("C16b - one guard, two action spaces, inside the same sessions")
    print("archive  %s   %d sessions" % (args.archive, n_sessions))
    print("")

    def table(title, tot, hit):
        print(title)
        print("  %-11s %8s %8s %9s   %s" % ("space", "calls", "refused", "share", "95% CI"))
        for sp in ("shell", "file tool", "other tool"):
            n, c = tot[sp], hit[sp]
            if not n:
                continue
            lo, hi = wilson(c, n)
            print("  %-11s %8d %8d %8.1f%%   [%.1f, %.1f]"
                  % (sp, n, c, 100.0 * c / n, 100 * lo, 100 * hi))
        ns, cs = tot["shell"], hit["shell"]
        na = tot["file tool"] + tot["other tool"]
        ca = hit["file tool"] + hit["other tool"]
        if ns and na:
            d = 100.0 * (cs / float(ns) - ca / float(na))
            lo, hi = newcombe(cs, ns, ca, na)
            print("  shell - tools  %+.1f points   95%% CI [%+.1f, %+.1f]  %s"
                  "   (Newcombe, independent samples)"
                  % (d, 100 * lo, 100 * hi,
                     "excludes 0" if lo > 0 or hi < 0 else "INCLUDES 0"))
        print("")

    table("Every recorded tool call", calls, matched)
    table("Mutating calls only (read_only excluded from both sides)",
          mutating, mut_matched)

    print("Per tool")
    print("  %-14s %8s %8s %8s" % ("tool", "calls", "refused", "share"))
    for tool, (n, c) in sorted(by_tool.items(), key=lambda kv: -kv[1][0])[:12]:
        print("  %-14s %8d %8d %7.1f%%" % (tool, n, c, 100.0 * c / n))
    print("")
    print("'refused' means this ruleset produced a guard decision for that call:")
    print("the empirical C1 rate of a real 21-rule gate, not an estimate of what")
    print("a rule could in principle be written for.")


if __name__ == "__main__":
    main()
