#!/usr/bin/env python3
"""Make inventory staleness detectable, and refuse to ship a stale ledger."""

import argparse
import io
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DATA = os.path.join(REPO, "paper", "data")
JSON_IN = os.path.join(REPO, "paper", "release-inventory.json")
MD_IN = os.path.join(REPO, "paper", "RELEASE-INVENTORY.md")
OUT = os.path.join(REPO, "paper", "release-inventory-freshness.json")

# A ledger older than this describes a tree the build no longer built from.
MAX_AGE_SECONDS = 3 * 3600
# Growth beyond this many files since the snapshot means the same.
MAX_FILE_DRIFT = 2000


def count_corpus(root):
    files = nbytes = 0
    for dirpath, dirnames, names in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
        for name in names:
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not os.path.isfile(p):
                continue
            files += 1
            nbytes += st.st_size
    return files, nbytes


def parse_iso(s):
    try:
        return time.mktime(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")) \
            - time.timezone
    except Exception:
        return None


def build_record():
    now = time.time()
    rec = {
        "schema": "release-inventory-freshness/1",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "generator": "paper/scripts/release/inventory_freshness.py",
        "ledger": "paper/release-inventory.json + paper/RELEASE-INVENTORY.md",
    }
    inv = None
    try:
        with io.open(JSON_IN, encoding="utf-8") as fh:
            inv = json.load(fh)
    except Exception as exc:
        rec["stale"] = True
        rec["verdict"] = "the ledger could not be read: %s" % exc
        return rec

    snap = inv.get("snapshot_utc")
    rows = inv.get("archives") or []
    loose = inv.get("loose_files") or {}
    at_snapshot_files = sum(r.get("files", 0) for r in rows) \
        + loose.get("files", 0)
    at_snapshot_bytes = sum(r.get("bytes", 0) for r in rows) \
        + loose.get("bytes", 0)

    rec["snapshot_utc"] = snap
    rec["archives_at_snapshot"] = len(rows)
    rec["files_at_snapshot"] = at_snapshot_files
    rec["bytes_at_snapshot"] = at_snapshot_bytes

    if os.path.isdir(DATA):
        now_files, now_bytes = count_corpus(DATA)
        rec["files_now"] = now_files
        rec["bytes_now"] = now_bytes
        rec["file_drift"] = now_files - at_snapshot_files
        rec["byte_drift"] = now_bytes - at_snapshot_bytes
        rec["corpus_measurable"] = True
    else:
        rec["corpus_measurable"] = False
        rec["corpus_note"] = (
            "the source corpus is not present here, so drift cannot be "
            "recomputed; the snapshot instant above is what this ledger "
            "describes")

    epoch = parse_iso(snap) if snap else None
    if epoch is not None:
        age = now - epoch
        rec["age_seconds"] = int(age)
        rec["age_human"] = "%.1f h" % (age / 3600.0)
    else:
        rec["age_seconds"] = None

    for path, key in ((MD_IN, "markdown"), (JSON_IN, "json")):
        try:
            rec[key + "_mtime_utc"] = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(path)))
        except OSError:
            rec[key + "_mtime_utc"] = None

    problems = []
    if rec.get("age_seconds") is None:
        problems.append("the ledger records no snapshot instant")
    elif rec["age_seconds"] > MAX_AGE_SECONDS:
        problems.append("the snapshot is %.1f h old, over the %.1f h bound"
                        % (rec["age_seconds"] / 3600.0,
                           MAX_AGE_SECONDS / 3600.0))
    if rec.get("corpus_measurable") and abs(rec.get("file_drift", 0)) > MAX_FILE_DRIFT:
        problems.append("the corpus has moved by %d files since the snapshot, "
                        "over the %d bound"
                        % (rec["file_drift"], MAX_FILE_DRIFT))
    rec["thresholds"] = {"max_age_seconds": MAX_AGE_SECONDS,
                         "max_file_drift": MAX_FILE_DRIFT}
    rec["stale"] = bool(problems)
    rec["verdict"] = ("; ".join(problems) if problems else
                      "the ledger describes the tree it was built from: "
                      "snapshot %s, %d files, drift %s"
                      % (snap, at_snapshot_files,
                         rec.get("file_drift", "not measurable here")))
    rec["how_to_refresh"] = "python paper/scripts/release/inventory.py"
    return rec


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 when the ledger is stale")
    ap.add_argument("--stdout", action="store_true",
                    help="print the record and write nothing")
    args = ap.parse_args()

    rec = build_record()
    text = json.dumps(rec, indent=1, sort_keys=True) + "\n"
    if args.stdout:
        sys.stdout.write(text)
    else:
        io.open(OUT, "w", encoding="utf-8", newline="\n").write(text)
        print("  inventory freshness: %s" % rec["verdict"])
    if args.check and rec.get("stale"):
        sys.stderr.write("\n  THE INVENTORY IS STALE: %s\n"
                         "  Refresh it with %s\n\n"
                         % (rec["verdict"], rec["how_to_refresh"]))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
