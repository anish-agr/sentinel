#!/usr/bin/env python3
"""Inventory every archive under paper/data, counting sessions three ways."""

import argparse
import io
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DATA = os.path.join(REPO, "paper", "data")

RECORD_FILES = re.compile(r"^(usage\.jsonl|sessions\.jsonl|sessions\.w\d+\.jsonl)$")
PRE_PRUNE = re.compile(r"\.pre-prune$")

# A session directory in the CLI layout is `<family>.<task>-v<N>-<epoch>`.
SESSION_DIR = re.compile(r"^[a-z]+\.[a-z_]+-v\d+-\d+$")

# Directories that hold evidence about failure rather than sessions. They are
# counted separately and never folded into a session count.
FAILURE_DIRS = ("events.quarantined", "events.incomplete", "events.staging")


def _lines(path):
    """Non-empty line count, tolerant of a file being appended to as we read."""
    n = 0
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    n += 1
    except OSError:
        return 0
    return n


def gradient_count(archive):
    """gradient.sh's count(), transcribed. Deliberately not generalized."""
    import glob
    n = 0
    for f in glob.glob(archive + "/sessions.w*.jsonl"):
        for line in io.open(f, encoding="utf-8", errors="replace"):
            if not line.strip():
                continue
            try:
                u = (json.loads(line).get("usage") or {})
            except Exception:
                continue
            if u.get("api_error"):
                continue
            if not (u.get("total_tokens") or 0):
                continue
            n += 1
    return n


def carries_data(rec):
    """gradient.sh's rule, over any of the three record shapes."""
    u = rec.get("usage")
    if isinstance(u, dict):                       # CLI / Antigravity
        if u.get("api_error"):
            return False
        total = u.get("total_tokens") or 0
        if not total:
            total = (u.get("input_tokens") or 0) + (u.get("output_tokens") or 0)
    else:                                         # API harness, flat record
        total = rec.get("total_tokens") or 0
    outcome = str(rec.get("outcome") or rec.get("status") or "")
    if outcome.startswith("api-error") or outcome == "ERROR":
        return False
    if rec.get("is_error"):
        return False
    return bool(total)


def scan(archive):
    """One pass over an archive. Returns the inventory row."""
    nbytes = nfiles = 0
    mtimes = []
    record_files, preprune_files = [], []
    session_dirs = 0
    result_jsons = 0
    result_ok = 0
    event_logs = 0
    failure_counts = {k: 0 for k in FAILURE_DIRS}
    unparseable = 0

    for root, dirs, names in os.walk(archive):
        dirs.sort()
        rel = os.path.relpath(root, archive)
        if rel != "." and os.path.dirname(rel) == "":
            if SESSION_DIR.match(os.path.basename(root)):
                session_dirs += 1
        base = os.path.basename(root)
        for name in names:
            p = os.path.join(root, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not os.path.isfile(p):
                continue
            nfiles += 1
            nbytes += st.st_size
            mtimes.append(st.st_mtime)
            if base in failure_counts and name.endswith(".jsonl"):
                failure_counts[base] += 1
            if name == "result.json":
                result_jsons += 1
                try:
                    with io.open(p, encoding="utf-8", errors="replace") as fh:
                        d = json.load(fh)
                    if carries_data(d):
                        result_ok += 1
                except Exception:
                    unparseable += 1
            elif name == "events.jsonl":
                event_logs += 1
            elif PRE_PRUNE.search(name):
                preprune_files.append(p)
            elif RECORD_FILES.match(name) and root == archive:
                record_files.append(p)

    # M1 - raw entries, uninterpreted.
    raw_lines = sum(_lines(p) for p in record_files)
    m1 = raw_lines if record_files else session_dirs

    # M3g - the rule, generalized.
    m3g = 0
    for p in record_files:
        for line in io.open(p, encoding="utf-8", errors="replace"):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                unparseable += 1
                continue
            if carries_data(rec):
                m3g += 1
    if not record_files and session_dirs:
        m3g = result_ok

    return {
        "name": os.path.basename(archive),
        "bytes": nbytes,
        "files": nfiles,
        "first_mtime": min(mtimes) if mtimes else None,
        "last_mtime": max(mtimes) if mtimes else None,
        "layout": ("dir-per-session" if session_dirs and not record_files else
                   "dir-per-session+record" if session_dirs else
                   "record-file" if record_files else "other"),
        "record_files": sorted(os.path.basename(p) for p in record_files),
        "session_dirs": session_dirs,
        "m1_raw": m1,
        "m1_raw_lines": raw_lines,
        "m2_result_json": result_jsons if (result_jsons or session_dirs) else None,
        "m3_gradient": gradient_count(archive),
        "m3g_carrying": m3g,
        "result_json_carrying": result_ok,
        "event_logs": event_logs,
        "quarantined": failure_counts["events.quarantined"],
        "incomplete": failure_counts["events.incomplete"],
        "staging": failure_counts["events.staging"],
        "preprune_files": len(preprune_files),
        "unparseable": unparseable,
    }


def ignore_status(name, gitignore_lines, tracked):
    """tracked / ignored / untracked, without traversing the data symlink."""
    import fnmatch
    if tracked is None:
        return NO_REPO
    if any(t.startswith("paper/data/" + name + "/") or t == "paper/data/" + name
           for t in tracked):
        return "tracked"
    for pat in gitignore_lines:
        p = pat.rstrip("/")
        if not p.startswith("paper/data/"):
            continue
        if fnmatch.fnmatch("paper/data/" + name, p):
            return "ignored"
    return "untracked"


# The value of the `git` column when there is no repository to ask. Not blank
# and not "untracked": both of those are answers, and this is the absence of
# one.
NO_REPO = "n/a (no repository)"


class InventoryError(Exception):
    """The inventory could not be taken. Never reported as an empty one."""


def repository_view():
    """(gitignore rules, tracked set) - or (None, None) in a release tree."""
    import subprocess
    if not os.path.exists(os.path.join(REPO, ".git")):
        return None, None
    gi_path = os.path.join(REPO, ".gitignore")
    if not os.path.isfile(gi_path):
        raise InventoryError(
            "%s has a .git but no .gitignore; the tracking column cannot be"
            " computed and this is not a release tree" % REPO)
    gi = [l.strip() for l in io.open(gi_path, encoding="utf-8")
          if l.strip() and not l.startswith("#")]
    try:
        proc = subprocess.run(["git", "ls-files", "paper/data"], cwd=REPO,
                              capture_output=True, text=True)
    except Exception as exc:            # noqa: BLE001 - reported, not swallowed
        raise InventoryError("a .git is present but git could not be run: %s"
                             % exc)
    if proc.returncode != 0:
        raise InventoryError(
            "a .git is present but `git ls-files paper/data` exited %d: %s"
            % (proc.returncode, (proc.stderr or "").strip()[:80]))
    return gi, set(proc.stdout.split())


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stdout", action="store_true",
                    help="print the table and write no files")
    ap.add_argument("--out", default=os.path.join(REPO, "paper", "RELEASE-INVENTORY.md"))
    ap.add_argument("--json", dest="jsonout",
                    default=os.path.join(REPO, "paper", "release-inventory.json"))
    args = ap.parse_args()

    snapshot = time.time()
    try:
        gi, tracked = repository_view()
        if not os.path.isdir(DATA):
            raise InventoryError("there is no paper/data under %s" % REPO)
        entries = sorted(os.listdir(DATA))
    except InventoryError as exc:
        sys.stderr.write("inventory: %s\n" % exc)
        sys.stderr.write("inventory: no inventory was produced. A table with"
                         " a column this run could not compute would read as"
                         " a measurement.\n")
        return 2
    except OSError as exc:
        sys.stderr.write("inventory: cannot read %s: %s\n" % (DATA, exc))
        return 2

    rows = []
    for entry in entries:
        p = os.path.join(DATA, entry)
        if not os.path.isdir(p):
            continue
        row = scan(p)
        row["status"] = ignore_status(entry, gi, tracked)
        rows.append(row)

    # Loose files directly under paper/data are inventoried as one pseudo-row
    # so the byte total is the whole corpus and not just its directories.
    loose_bytes = loose_files = 0
    loose_mt = []
    for entry in entries:
        p = os.path.join(DATA, entry)
        if os.path.isfile(p):
            loose_files += 1
            loose_bytes += os.path.getsize(p)
            loose_mt.append(os.path.getmtime(p))

    if not rows and not loose_files:
        sys.stderr.write(
            "inventory: %s contains no archive directories and no files.\n"
            % DATA)
        sys.stderr.write("inventory: refusing to print an empty inventory; "
                         "nothing was counted.\n")
        return 2

    out = {
        "snapshot_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(snapshot)),
        "snapshot_epoch": snapshot,
        "note": ("A collection run was in progress during this scan; archives "
                 "under active write grow after the snapshot time."),
        "data_root": DATA,
        # Which tree this was taken in, so the `git` column is never read as a
        # measurement when there was nothing to measure it against.
        "repository": "absent" if tracked is None else "present",
        "archives": rows,
        "loose_files": {"files": loose_files, "bytes": loose_bytes,
                        "first_mtime": min(loose_mt) if loose_mt else None,
                        "last_mtime": max(loose_mt) if loose_mt else None},
    }
    print("  %d archives, %d files, %.1f MB"
          % (len(rows), sum(r["files"] for r in rows) + loose_files,
             (sum(r["bytes"] for r in rows) + loose_bytes) / 1048576.0))
    if args.stdout:
        write_markdown(out, "-")
        return 0
    io.open(args.jsonout, "w", encoding="utf-8", newline="\n").write(
        json.dumps(out, indent=1, sort_keys=True) + "\n")
    write_markdown(out, args.out)
    print("  wrote %s" % os.path.relpath(args.out, REPO))
    print("  wrote %s" % os.path.relpath(args.jsonout, REPO))
    return 0


def ts(v):
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(v)) if v else "-"


def disagreements(rows):
    """Archives where the three 18.1 methods do not agree, grouped by cause."""
    glob_miss, inflated, deflated, other = [], [], [], []
    for r in rows:
        counts = [r["m1_raw"], r["m3_gradient"]]
        if r["m2_result_json"] is not None:
            counts.append(r["m2_result_json"])
        if len(set(counts)) == 1:
            continue
        if r["m3_gradient"] == 0 and r["m1_raw"] > 0:
            glob_miss.append(r)
            continue
        # An archive can be in both lists: `denials-defer-supp` has one raw
        # entry more than it has carrying sessions AND thirty fewer
        # `result.json` than either. Both are defects and both are reported.
        truth = r["m3g_carrying"]
        hi, lo = max(counts), min(counts)
        hit = False
        if truth and hi > truth:
            inflated.append((r, hi / float(truth)))
            hit = True
        if truth and lo < truth:
            deflated.append((r, truth / float(lo) if lo else float("inf")))
            hit = True
        if not hit:
            other.append(r)
    inflated.sort(key=lambda t: -t[1])
    deflated.sort(key=lambda t: -t[1])
    return glob_miss, inflated, deflated, other


def write_markdown(out, path):
    rows = out["archives"]
    w = sys.stdout if path == "-" else io.open(path, "w", encoding="utf-8",
                                               newline="\n")
    W = w.write
    W("# Corpus inventory\n\n")
    W("Snapshot %s. A collection run (`run_api.py --campaign`, 12 workers) was\n"
      "writing into the API archives while this ran, so every count here is a\n"
      "lower bound for those and exact for the rest. Nothing under `paper/data/`\n"
      "was written, moved or removed to produce it.\n\n" % out["snapshot_utc"])
    tot_b = sum(r["bytes"] for r in rows) + out["loose_files"]["bytes"]
    tot_f = sum(r["files"] for r in rows) + out["loose_files"]["files"]
    W("%d archives, %d loose files, %d files total, %.1f MB.\n\n"
      % (len(rows), out["loose_files"]["files"], tot_f, tot_b / 1048576.0))
    if out.get("repository") == "absent":
        W("This tree carries no repository, which `DATA-RELEASE.md` 2.7\n"
          "requires of a release, so the `git` column below reads\n"
          "`%s` throughout: tracking status is a property of the\n"
          "repository and not of the released corpus. Every other column is\n"
          "measured from the files themselves and is unaffected.\n\n" % NO_REPO)

    W("## The three counts\n\n")
    W("`M1` raw entries. `M2` `result.json` files, `-` where the layout has\n"
      "none. `M3` `gradient.sh`'s `count()` transcribed unchanged. `M3g` the\n"
      "same rule generalized over the record shape the archive actually uses;\n"
      "this is the number to quote.\n\n")
    W("| archive | bytes | files | layout | M1 raw | M2 result.json | M3 count() "
      "| M3g carrying | first | last | git |\n")
    W("|---|---:|---:|---|---:|---:|---:|---:|---|---|---|\n")
    for r in rows:
        W("| `%s` | %d | %d | %s | %d | %s | %d | %d | %s | %s | %s |\n"
          % (r["name"], r["bytes"], r["files"], r["layout"], r["m1_raw"],
             "-" if r["m2_result_json"] is None else r["m2_result_json"],
             r["m3_gradient"], r["m3g_carrying"], ts(r["first_mtime"]),
             ts(r["last_mtime"]), r["status"]))

    glob_miss, inflated, deflated, other = disagreements(rows)
    n_dis = len(glob_miss) + len(inflated) + len(deflated) + len(other)
    W("\n## Disagreements\n\n")
    W("%d of %d archives disagree across the three methods. They fall into "
      "three causes.\n\n" % (n_dis, len(rows)))

    W("### D1 - `count()` returns 0 on %d archives, and the 0 is not a count\n\n"
      % len(glob_miss))
    W("`gradient.sh`'s `count()` globs `sessions.w*.jsonl`. Two of the three\n"
      "harnesses do not use that filename: the API harness writes `usage.jsonl`\n"
      "and the Antigravity harness writes `sessions.jsonl`. The glob matches\n"
      "nothing, the loop runs zero times, and the function returns 0 - which is\n"
      "indistinguishable from an archive that collected nothing. %d archives\n"
      "holding %d data-carrying sessions between them read as empty under the\n"
      "definition the project names as the only correct one.\n\n"
      % (len(glob_miss), sum(r["m3g_carrying"] for r in glob_miss)))
    W("| record file | archives | entries (M1) | carrying (M3g) | `count()` |\n")
    W("|---|---:|---:|---:|---:|\n")
    by_file = {}
    for r in glob_miss:
        k = r["record_files"][0] if r["record_files"] else "(directories only)"
        a = by_file.setdefault(k, [0, 0, 0])
        a[0] += 1
        a[1] += r["m1_raw"]
        a[2] += r["m3g_carrying"]
    for k in sorted(by_file):
        n, m1, m3g = by_file[k]
        W("| `%s` | %d | %d | %d | 0 |\n" % (k, n, m1, m3g))
    if glob_miss:
        worst = max(glob_miss, key=lambda r: r["m3g_carrying"])
        W("\nThe largest single archive affected is `%s` at %d carrying "
          "sessions counted as 0.\n\n" % (worst["name"], worst["m3g_carrying"]))
    else:
        W("\nNo archive in this tree is affected: `count()`'s glob matched a "
          "record file in every one.\n\n")

    W("### D2 - overcounts: entries that are not sessions\n\n")
    W("Every row here reads high against the data-carrying count. `M2` counts\n"
      "`result.json` files, one of which exists for every session directory the\n"
      "harness created, including the ones whose API call never returned.\n\n")
    W("| archive | M1 raw | M2 result.json | M3 count() | M3g carrying | worst "
      "ratio | what the entries are |\n")
    W("|---|---:|---:|---:|---:|---:|---|\n")
    for r, ratio in inflated:
        W("| `%s` | %d | %s | %d | %d | %.1fx | %s |\n"
          % (r["name"], r["m1_raw"],
             "-" if r["m2_result_json"] is None else r["m2_result_json"],
             r["m3_gradient"], r["m3g_carrying"], ratio, explain(r)))

    W("\n### D3 - undercounts: sessions with no `result.json`\n\n")
    W("The opposite defect, and the reason `M2` cannot be used as a floor\n"
      "either. These archives banked more data-carrying sessions than they have\n"
      "`result.json` files, so a count of `result.json` understates them.\n\n")
    W("| archive | M1 raw | M2 result.json | M3 count() | M3g carrying | "
      "shortfall |\n")
    W("|---|---:|---:|---:|---:|---:|\n")
    for r, ratio in deflated:
        W("| `%s` | %d | %s | %d | %d | %d missing |\n"
          % (r["name"], r["m1_raw"],
             "-" if r["m2_result_json"] is None else r["m2_result_json"],
             r["m3_gradient"], r["m3g_carrying"],
             r["m3g_carrying"] - (r["m2_result_json"] or 0)))
    if other:
        W("\n### D4 - unclassified\n\n")
        for r in other:
            W("- `%s`: M1 %d, M2 %s, M3 %d, M3g %d\n"
              % (r["name"], r["m1_raw"], r["m2_result_json"],
                 r["m3_gradient"], r["m3g_carrying"]))
    if w is not sys.stdout:
        w.close()


def explain(r):
    m2 = r["m2_result_json"]
    if m2 and r["result_json_carrying"] < m2:
        return ("%d of %d `result.json` carry no tokens"
                % (m2 - r["result_json_carrying"], m2))
    if r["m1_raw"] > r["m3g_carrying"]:
        return ("%d of %d entries are API errors or zero-token stubs"
                % (r["m1_raw"] - r["m3g_carrying"], r["m1_raw"]))
    return "counts differ; see the row"


if __name__ == "__main__":
    sys.exit(main())
