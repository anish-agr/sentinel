#!/usr/bin/env python3
"""Regenerate the section 4 number map and report what moved."""

import argparse
import io
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
GENERATOR = os.path.join(HERE, "number_map.py")
OUT_JSON = os.path.join(REPO, "paper", "number-map.json")
OUT_MD = os.path.join(REPO, "paper", "NUMBER-MAP.md")


def load(path):
    try:
        with io.open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def claims(doc):
    """{(bucket, id): value-and-liveness} over both direction A orphan lists."""
    out = {}
    if not doc:
        return out
    a = doc.get("direction_a") or {}
    for bucket in ("untraceable", "contradicted"):
        for row in (a.get("orphans") or {}).get(bucket, []) or []:
            key = (bucket, row.get("id") or row.get("value"))
            out[key] = {"value": row.get("value"),
                        "live": row.get("present_in_main_tex_today")}
    return out


def report(before, after):
    """Print the delta. Returns the number of differences."""
    cb, ca = claims(before), claims(after)
    n = 0

    gone = sorted(set(cb) - set(ca))
    new = sorted(set(ca) - set(cb))
    for key in gone:
        n += 1
        print("  - dropped from the map   %-14s %s" % (key[0], cb[key]["value"]))
    for key in new:
        n += 1
        print("  + added to the map       %-14s %s" % (key[0], ca[key]["value"]))

    for key in sorted(set(cb) & set(ca)):
        if cb[key]["live"] != ca[key]["live"]:
            n += 1
            was, now = cb[key]["live"], ca[key]["live"]
            print("  ~ %-14s %-40s in main.tex: %s -> %s"
                  % (key[0], str(ca[key]["value"])[:40],
                     _live(was), _live(now)))

    bb = ((before or {}).get("direction_b") or {})
    ba = ((after or {}).get("direction_b") or {})
    for field, label in (("shipped_archives", "shipped archives"),
                         ("orphans", "archives feeding no number"),
                         ("no_post_denial_number",
                          "archives feeding no post-denial number")):
        x, y = bb.get(field), ba.get(field)
        x = len(x) if isinstance(x, list) else x
        y = len(y) if isinstance(y, list) else y
        if x != y:
            n += 1
            print("  ~ direction B: %-38s %s -> %s" % (label, x, y))
    return n


def _live(v):
    return {True: "live", False: "retired", None: "prose"}.get(v, str(v))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="report the delta without replacing the committed map")
    args = ap.parse_args()

    before = load(OUT_JSON)
    if before is None:
        print("  no committed map at paper/number-map.json; this is a first "
              "generation and every row will read as new")

    if args.dry_run:
        r = subprocess.run([sys.executable, GENERATOR, "--check"], cwd=REPO,
                           capture_output=True, text=True, timeout=7200,
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        if r.returncode != 0:
            print("  the generator refuses to regenerate here; nothing was "
                  "written and nothing was compared.")
            return r.returncode
        print("  --dry-run: the corpus supports a regeneration. Rerun without "
              "--dry-run to take it and see the delta.")
        return 0

    r = subprocess.run([sys.executable, GENERATOR], cwd=REPO,
                       capture_output=True, text=True, timeout=7200,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        print("")
        print("  THE MAP WAS NOT REGENERATED (generator exit %d) and the "
              "committed one is untouched." % r.returncode)
        return r.returncode

    after = load(OUT_JSON)
    print("")
    print("  delta against the previously committed map:")
    n = report(before, after)
    if n == 0:
        print("    nothing moved: the map already described `main.tex` and the "
              "corpus as they are now.")
    else:
        print("    %d change(s) above. `main.tex` or the corpus moved since "
              "the committed map was written, which is why this runs last."
              % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
