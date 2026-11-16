#!/usr/bin/env python
"""Move aside sessions in which the guard was never consulted."""

import argparse
import io
import json
import os
import shutil
import sys

DATA = os.path.join("paper", "data")


def session_dirs(archive):
    for name in sorted(os.listdir(archive)):
        path = os.path.join(archive, name)
        if os.path.isdir(path) and os.path.isfile(os.path.join(path, "events.jsonl")):
            yield name, path


def kinds(path):
    """Event-kind counts, and the first timestamp, for one session."""
    counts, first = {}, None
    with io.open(os.path.join(path, "events.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if first is None:
                first = e.get("ts")
            k = e.get("kind")
            counts[k] = counts.get(k, 0) + 1
    return counts, first


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                    help="actually move the sessions; default is report only")
    args = ap.parse_args()

    archives = sorted(d for d in os.listdir(DATA)
                      if d.startswith("denials") and os.path.isdir(os.path.join(DATA, d))
                      and not d.endswith(".unhooked"))

    total_bad = total_all = 0
    moved = []
    print("")
    print("%-26s %7s %7s %7s   %s" % ("archive", "ok", "unhooked", "total", "first unhooked"))
    for archive in archives:
        root = os.path.join(DATA, archive)
        good = bad = 0
        firstbad = None
        badpaths = []
        for name, path in session_dirs(root):
            counts, first = kinds(path)
            if counts.get("tool_call", 0) > 0:
                good += 1
            elif counts.get("file_mutation", 0) == 0 and counts.get("checkpoint", 0) == 0:
                turns = 0
                rj = os.path.join(path, "result.json")
                if os.path.exists(rj):
                    try:
                        with io.open(rj, encoding="utf-8",
                                     errors="replace") as fh:
                            turns = json.load(fh).get("num_turns") or 0
                    except ValueError:
                        pass
                if turns > 1:
                    bad += 1
                    badpaths.append((name, path))
                    if firstbad is None:
                        firstbad = ""
                else:
                    good += 1
            else:
                bad += 1
                badpaths.append((name, path))
                if firstbad is None or (first or "") < firstbad:
                    firstbad = first
        total_bad += bad
        total_all += good + bad
        if good + bad:
            print("%-26s %7d %7d %7d   %s"
                  % (archive, good, bad, good + bad, (firstbad or "-")[:19]))
        if bad and args.apply:
            dest = root + ".unhooked"
            if not os.path.isdir(dest):
                os.makedirs(dest)
            for name, path in badpaths:
                target = os.path.join(dest, name)
                if not os.path.exists(target):
                    shutil.move(path, target)
                    moved.append(target)

    print("")
    print("%d of %d sessions ran with no guard." % (total_bad, total_all))
    if not args.apply:
        print("")
        print("Report only. Re-run with --apply to move them to <archive>.unhooked/")
        print("Nothing is deleted - they are the record of how long the guard was")
        print("down, and the paper reports that as a finding.")
    else:
        print("Moved %d session(s) into <archive>.unhooked/." % len(moved))
        print("")
        print("The session .jsonl manifests still list them, so per-arm session")
        print("counts read from those files stay high until the arm is re-run.")
        print("Event-level rates are unaffected: a session with no guard")
        print("contributes no denial events, so it never entered them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
