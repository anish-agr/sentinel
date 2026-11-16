#!/usr/bin/env python3
"""Recompute the internal-consistency evidence over a built release."""

import argparse
import collections
import io
import json
import os
import re
import statistics
import sys

TS = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.(\d+))?Z?$")


def epoch(s):
    """Parse the recorder's timestamp, keeping sub-second digits."""
    m = TS.match(s.strip())
    if not m:
        return None
    import calendar
    base = calendar.timegm((int(m.group(1)), int(m.group(2)), int(m.group(3)),
                            int(m.group(4)), int(m.group(5)), int(m.group(6)),
                            0, 1, 0))
    frac = m.group(8) or ""
    return base + (float("0." + frac) if frac else 0.0), len(frac)


def iter_jsonl(path):
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    try:
                        yield json.loads(line)
                    except Exception:
                        continue
    except OSError:
        return


def walk(root, name):
    for dirpath, dirs, names in os.walk(root):
        dirs.sort()
        if name in names:
            yield os.path.join(dirpath, name)


def check_sequences(data):
    """1. Step counters rise and timestamps rise with them, per run_id."""
    files = runs = 0
    step_ok = step_bad = 0
    ts_ok = ts_bad = 0
    frac_digits = collections.Counter()
    gaps = []
    for p in walk(data, "events.jsonl"):
        files += 1
        by_run = collections.defaultdict(list)
        for e in iter_jsonl(p):
            by_run[e.get("run_id")].append(e)
        for run, evs in by_run.items():
            runs += 1
            steps = [e.get("step") for e in evs if isinstance(e.get("step"), int)]
            if steps == sorted(steps):
                step_ok += 1
            else:
                step_bad += 1
            times = []
            for e in evs:
                t = e.get("ts")
                if isinstance(t, str):
                    r = epoch(t)
                    if r:
                        times.append(r[0])
                        frac_digits[r[1]] += 1
            if times == sorted(times):
                ts_ok += 1
            else:
                ts_bad += 1
            for a, b in zip(times, times[1:]):
                gaps.append(b - a)
    return {
        "event_logs": files, "runs": runs,
        "step_monotone": step_ok, "step_out_of_order": step_bad,
        "ts_monotone": ts_ok, "ts_out_of_order": ts_bad,
        "fractional_digits": dict(frac_digits),
        "gaps": gaps,
    }


def check_hash_determinism(data):
    """2. Every argument hash names exactly one argument string."""
    h2s = collections.defaultdict(set)
    s2h = collections.defaultdict(set)
    n = truncated = 0
    for p in walk(data, "events.jsonl"):
        for e in iter_jsonl(p):
            h, s = e.get("args_hash"), e.get("args_summary")
            if h and s is not None:
                h2s[h].add(s)
                s2h[s].add(h)
                n += 1
    for s in s2h:
        if str(s).endswith("..."):
            truncated += 1
    return {"events_with_hash": n, "distinct_hashes": len(h2s),
            "distinct_summaries": len(s2h),
            "hashes_mapping_to_more_than_one_summary":
                sum(1 for v in h2s.values() if len(v) > 1),
            "summaries_mapping_to_more_than_one_hash":
                sum(1 for v in s2h.values() if len(v) > 1),
            "truncated_summaries": truncated}


def check_turns(data):
    """3. Two writers agree on how much work a session did."""
    ok = viol = 0
    diffs = []
    for dirpath, dirs, names in os.walk(data):
        dirs.sort()
        if "result.json" not in names or "events.jsonl" not in names:
            continue
        try:
            with io.open(os.path.join(dirpath, "result.json"),
                         encoding="utf-8", errors="replace") as fh:
                r = json.load(fh)
        except Exception:
            continue
        nt = r.get("num_turns") or 0
        tc = sum(1 for e in iter_jsonl(os.path.join(dirpath, "events.jsonl"))
                 if e.get("kind") == "tool_call")
        if not tc:
            continue
        diffs.append(nt - tc)
        if nt >= tc:
            ok += 1
        else:
            viol += 1
    diffs.sort()
    return {"sessions": ok + viol, "turns_at_least_tool_calls": ok,
            "violations": viol,
            "median_excess_turns": diffs[len(diffs) // 2] if diffs else None}


def check_session_joins(data):
    """4. The same session id turns up in files written by different writers."""
    both = only_result = 0
    for dirpath, dirs, names in os.walk(data):
        dirs.sort()
        if "result.json" not in names:
            continue
        try:
            with io.open(os.path.join(dirpath, "result.json"),
                         encoding="utf-8", errors="replace") as fh:
                sid = (json.load(fh) or {}).get("session_id")
        except Exception:
            continue
        if not sid:
            continue
        ev = os.path.join(dirpath, "events.jsonl")
        if not os.path.exists(ev):
            only_result += 1
            continue
        try:
            blob = io.open(ev, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if sid in blob:
            both += 1
        else:
            only_result += 1
    return {"session_id_in_both_files": both,
            "session_id_in_result_only": only_result}


def check_failures(data):
    """2. The failures, counted. Nobody fabricates their own failure modes."""
    out = collections.Counter()
    oauth = collections.Counter()
    for p in walk(data, "result.json"):
        try:
            with io.open(p, encoding="utf-8", errors="replace") as fh:
                d = json.load(fh)
        except Exception:
            out["result.json unparseable"] += 1
            continue
        if d.get("is_error"):
            out["result.json is_error"] += 1
            r = str(d.get("result") or "")[:60]
            if "auth" in r.lower():
                oauth[r] += 1
                out["OAuth session expired"] += 1
        tr = d.get("terminal_reason")
        if tr:
            out["terminal_reason=%s" % tr] += 1
    for dirpath, dirs, names in os.walk(data):
        dirs.sort()
        base = os.path.basename(dirpath)
        if base in ("events.quarantined", "events.incomplete", "events.staging"):
            out["%s/ files" % base] += len([n for n in names
                                            if n.endswith(".jsonl")])
        for n in names:
            if n == "usage.jsonl":
                for rec in iter_jsonl(os.path.join(dirpath, n)):
                    o = str(rec.get("outcome") or "")
                    if o.startswith("api-error"):
                        code = re.search(r"\b(\d{3})\b", o)
                        out["api-error %s" % (code.group(1) if code
                                              else "?")] += 1
                    elif o:
                        out["outcome=%s" % o.split(":")[0]] += 1
                    if not (rec.get("total_tokens") or 0):
                        out["zero-token record"] += 1
            elif re.match(r"^sessions(\.w\d+)?\.jsonl$", n):
                for rec in iter_jsonl(os.path.join(dirpath, n)):
                    u = rec.get("usage") or {}
                    if u.get("api_error"):
                        out["session api_error"] += 1
                    if rec.get("timeout"):
                        out["timeout"] += 1
    return out, oauth


def check_clock(data):
    """5. Concurrent workers agree about the wall clock."""
    spans = []
    for p in walk(data, "events.jsonl"):
        ts = [epoch(e["ts"])[0] for e in iter_jsonl(p)
              if isinstance(e.get("ts"), str) and epoch(e["ts"])]
        if len(ts) >= 2:
            spans.append((min(ts), max(ts), p))
    spans.sort()
    overlaps = 0
    for i in range(1, len(spans)):
        if spans[i][0] < spans[i - 1][1]:
            overlaps += 1
    return {"sessions_with_span": len(spans),
            "overlapping_with_previous": overlaps,
            "span_seconds_median": (statistics.median(
                [b - a for a, b, _ in spans]) if spans else 0)}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--root", default=os.path.abspath(
        os.path.join(here, "..", "..", "..")))
    ap.add_argument("--json", dest="jsonout")
    args = ap.parse_args()
    data = os.path.join(args.root, "paper", "data")
    if not os.path.isdir(data):
        raise SystemExit("no paper/data under %s" % args.root)

    print("evidence of authenticity, recomputed from %s" % data)
    print("")

    seq = check_sequences(data)
    print("1. sequence and clock")
    print("   %d event logs, %d runs" % (seq["event_logs"], seq["runs"]))
    print("   step counters monotone in %d runs, out of order in %d"
          % (seq["step_monotone"], seq["step_out_of_order"]))
    print("   timestamps monotone in %d runs, out of order in %d"
          % (seq["ts_monotone"], seq["ts_out_of_order"]))
    print("   sub-second digits recorded: %s"
          % ", ".join("%d digits x%d" % (k, v)
                      for k, v in sorted(seq["fractional_digits"].items())))
    g = [x for x in seq["gaps"] if x >= 0]
    if g:
        g.sort()
        print("   inter-event gaps (s): min %.6f  p50 %.4f  p90 %.3f  max %.1f"
              % (g[0], g[len(g) // 2], g[int(len(g) * .9)], g[-1]))
        print("   distinct gap values: %d of %d samples"
              % (len(set(g)), len(g)))
    print("")

    tok = check_hash_determinism(data)
    print("2. argument-hash determinism")
    print("   %d events carry an argument hash, %d distinct hashes"
          % (tok["events_with_hash"], tok["distinct_hashes"]))
    print("   hashes mapping to more than one summary: %d"
          % tok["hashes_mapping_to_more_than_one_summary"])
    print("   summaries mapping to more than one hash: %d "
          "(expected: the summary is truncated, the hash is not)"
          % tok["summaries_mapping_to_more_than_one_hash"])
    print("   truncated summaries: %d" % tok["truncated_summaries"])
    print("")

    turns = check_turns(data)
    print("3. turn accounting across two writers")
    print("   %d sessions have both a vendor result and a guard event log"
          % turns["sessions"])
    print("   num_turns >= mediated tool calls in %d, violated in %d"
          % (turns["turns_at_least_tool_calls"], turns["violations"]))
    print("   median excess turns: %s" % turns["median_excess_turns"])
    print("")

    joins = check_session_joins(data)
    print("4. cross-file session joins")
    print("   vendor session id also present in the guard's event log: %d"
          % joins["session_id_in_both_files"])
    print("   present in result.json only: %d"
          % joins["session_id_in_result_only"])
    print("")

    fails, oauth = check_failures(data)
    print("5. failures, which is the evidence nobody fabricates")
    for k, v in sorted(fails.items(), key=lambda kv: -kv[1]):
        print("   %-42s %7d" % (k, v))
    print("")

    clock = check_clock(data)
    print("6. concurrent workers")
    print("   %d sessions with a measurable span, %d overlap the previous "
          "session in wall-clock time" % (clock["sessions_with_span"],
                                          clock["overlapping_with_previous"]))
    print("   median session span %.1f s" % clock["span_seconds_median"])

    if args.jsonout:
        seq.pop("gaps", None)
        io.open(args.jsonout, "w", encoding="utf-8", newline="\n").write(
            json.dumps({"sequences": seq, "hash_determinism": tok, "turns": turns, "joins": joins,
                        "failures": dict(fails), "clock": clock},
                       indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
