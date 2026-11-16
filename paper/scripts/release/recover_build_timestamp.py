#!/usr/bin/env python3
"""Recover the collecting binary's BUILD TIMESTAMP, or say why it cannot be."""

import argparse
import calendar
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
PIN = os.path.join(REPO, "paper", "run-b-guard.json")
OUT = os.path.join(REPO, "paper", "run-b-guard-build.json")

# How far to look for a cargo build tree. Bounded: an unbounded walk of a home
# directory on this machine crosses the corpus and several checkouts.
SEARCH_DEPTH = 5


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def iso_ns(ns):
    """UTC from INTEGER nanoseconds since the epoch."""
    if ns is None:
        return None
    whole, frac = divmod(int(ns), 1000000000)
    return (time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(whole))
            + ".%09dZ" % frac)


# stat(1)'s %w, e.g. `2026-08-24 15:31:56.752174801 +0000`. os.stat() has no
# birth time on Linux at any Python version this project runs on.
_BIRTH_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})"
                       r"(?:\.(\d+))?\s*([+-])(\d{2})(\d{2})")


def birth_ns(path):
    """Creation time in integer nanoseconds, or None if the fs has none."""
    try:
        r = subprocess.run(["stat", "-c", "%w", path], capture_output=True,
                           text=True, timeout=20)
    except Exception:
        return None
    m = _BIRTH_RE.match((r.stdout or "").strip())
    if not m:
        return None                      # "-" on a filesystem without btime
    y, mo, d, hh, mm, ss, frac, sign, oh, om = m.groups()
    secs = calendar.timegm((int(y), int(mo), int(d), int(hh), int(mm),
                            int(ss), 0, 0, 0))
    off = (int(oh) * 3600 + int(om) * 60) * (-1 if sign == "-" else 1)
    frac = (frac or "").ljust(9, "0")[:9]
    return (secs - off) * 1000000000 + int(frac)


def stat_times(path):
    st = os.stat(path)
    out = {"mtime": iso_ns(st.st_mtime_ns), "ctime": iso_ns(st.st_ctime_ns),
           "mtime_ns": st.st_mtime_ns,
           "links": st.st_nlink, "inode": st.st_ino, "bytes": st.st_size}
    b = birth_ns(path)
    if b is not None:
        out["birth"] = iso_ns(b)
        out["birth_ns"] = b
    return out


def rustc_version(path):
    """The one build-provenance string rustc does embed. Not a timestamp."""
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return None
    key = b"rustc version "
    i = blob.find(key)
    if i < 0:
        return None
    end = i
    while end < len(blob) and 32 <= blob[end] < 127:
        end += 1
    return blob[i:end].decode("ascii", "replace")


def embedded_timestamp(path):
    """Look for a build date the binary asserts about itself. There is none
    today; the check is here so a future rebuild that adds one is picked up
    automatically rather than by somebody remembering."""
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return None
    for key in (b"SOURCE_DATE_EPOCH", b"VERGEN_BUILD_TIMESTAMP",
                b"BUILD_TIMESTAMP", b"CARGO_BUILD_TIMESTAMP"):
        i = blob.find(key)
        if i >= 0:
            return key.decode("ascii")
    return None


def candidate_release_dirs(roots):
    """Every `target/release` under the roots, bounded by SEARCH_DEPTH."""
    found = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, _names in os.walk(root):
            if dirpath.count(os.sep) - base_depth >= SEARCH_DEPTH:
                dirnames[:] = []
                continue
            # Never descend into the corpus or into a VCS directory.
            dirnames[:] = [d for d in dirnames
                           if d not in (".git", ".hg", ".jj", "data",
                                        ".campaign", ".sentinel", "node_modules")]
            if os.path.basename(dirpath) == "release" and \
                    os.path.basename(os.path.dirname(dirpath)) == "target":
                found.append(dirpath)
                dirnames[:] = []
    return found


def is_cargo_tree(release_dir):
    return (os.path.isdir(os.path.join(release_dir, "deps"))
            and os.path.isdir(os.path.join(release_dir, ".fingerprint")))


def worktree_commit(release_dir):
    """The commit the build tree was checked out at, if git can say."""
    top = os.path.dirname(os.path.dirname(release_dir))
    try:
        r = subprocess.run(["git", "-C", top, "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return None, None
        head = r.stdout.strip()
        s = subprocess.run(["git", "-C", top, "status", "--porcelain"],
                           capture_output=True, text=True, timeout=60)
        return head, (s.returncode == 0 and s.stdout.strip() == "")
    except Exception:
        return None, None


def commit_date(commit):
    """UTC, always. `%cI` renders the committer's own offset, and a `-07:00`
    in a released file narrows the author to a timezone for nothing - the
    release is double-blind. Epoch in, Z out."""
    try:
        r = subprocess.run(["git", "-C", REPO, "log", "-1",
                            "--format=%ct", commit],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            return time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                 time.gmtime(int(r.stdout.strip())))
    except Exception:
        pass
    return None


def corroborate(release_dir, cand, hook_name, pinned_commit):
    """C1-C4 over one candidate tree. Returns (passed, [failure, ...], detail)."""
    st = os.stat(cand)
    fails = []
    detail = {"mtime": iso_ns(st.st_mtime_ns), "mtime_ns": st.st_mtime_ns}

    # C1 - born when it was written. cp -p carries mtime and cannot carry
    # btime, so a restored copy is born strictly after its own mtime.
    b = birth_ns(cand)
    detail["birth"] = iso_ns(b)
    if b is None:
        fails.append("C1 birth==mtime: the filesystem records no birth time, "
                     "so a restored copy cannot be told from a linker output")
    elif b != st.st_mtime_ns:
        fails.append(
            "C1 birth==mtime: born %s but written %s (%+d ns). A linker writes "
            "its output once; a file born after it was written was copied in "
            "with its mtime preserved."
            % (iso_ns(b), iso_ns(st.st_mtime_ns), b - st.st_mtime_ns))

    # C2 - rustc started before the link finished.
    fp = fingerprint_dir(release_dir, hook_name)
    inv = os.path.join(fp, "invoked.timestamp") if fp else None
    if inv and os.path.exists(inv):
        inv_ns = os.stat(inv).st_mtime_ns
        detail["fingerprint_invoked_timestamp"] = iso_ns(inv_ns)
        if inv_ns > st.st_mtime_ns:
            fails.append(
                "C2 invoked.timestamp <= mtime: cargo started this unit's "
                "rustc at %s, after the %s link it is supposed to have "
                "produced. The fingerprint belongs to a later build than the "
                "binary." % (iso_ns(inv_ns), iso_ns(st.st_mtime_ns)))
    else:
        fails.append("C2 invoked.timestamp <= mtime: no fingerprint for this "
                     "unit, so the compile cannot be bracketed")

    # C3 - cargo's uplift signature.
    twin = deps_twin(release_dir, hook_name, st.st_ino)
    detail["hardlinked_to_deps"] = bool(twin)
    if not twin:
        fails.append("C3 hardlinked to deps/: cargo uplifts a release binary "
                     "as a hardlink, and this one is not")

    # C4 - the source it was built from.
    head, clean = worktree_commit(release_dir)
    detail["worktree_head"] = head
    detail["worktree_clean"] = clean
    if not head:
        fails.append("C4 worktree at the pinned commit: git could not report "
                     "a HEAD for this tree")
    elif not (pinned_commit and head.startswith(pinned_commit)):
        fails.append("C4 worktree at the pinned commit: HEAD is %s, the pin is "
                     "%s. A tree at a different commit did not build the "
                     "pinned binary." % (head[:12], pinned_commit))
    elif clean is False:
        fails.append("C4 worktree at the pinned commit: HEAD matches but the "
                     "worktree is dirty, so the source that was compiled is "
                     "not the source the commit names")
    return (not fails), fails, detail


def find_build_tree(want_sha, hook_name, pinned_commit, roots=None):
    """The cargo build tree that CORROBORATES having built the pinned bytes."""
    if roots is None:
        home = os.path.expanduser("~")
        roots = [os.path.dirname(REPO), home]
    considered = []
    accepted = None
    seen = set()
    for rel in candidate_release_dirs(roots):
        if rel in seen:
            continue
        seen.add(rel)
        cand = os.path.join(rel, hook_name)
        if not os.path.isfile(cand):
            continue
        try:
            if sha256_file(cand) != want_sha:
                continue
        except OSError:
            continue
        # The tree is named by a placeholder: the real path is under the
        # operator's home directory and this record ships.
        label = "<cargo tree %d>" % (len(considered) + 1)
        if not is_cargo_tree(rel):
            considered.append({"tree": label, "accepted": False,
                               "failed": ["C0 cargo tree: no `deps/` and "
                                          "`.fingerprint/` beside the binary"]})
            continue
        ok, fails, detail = corroborate(rel, cand, hook_name, pinned_commit)
        entry = {"tree": label, "accepted": ok, "evidence": detail}
        if not ok:
            entry["failed"] = fails
        considered.append(entry)
        if ok and accepted is None:
            accepted = (rel, cand, label)
    if accepted:
        return accepted[0], accepted[1], considered
    return None, None, considered


def deps_twin(release_dir, hook_name, inode):
    """The `deps/` object the uplifted binary is a hardlink of."""
    deps = os.path.join(release_dir, "deps")
    stem = hook_name.replace("-", "_")
    try:
        names = os.listdir(deps)
    except OSError:
        return None
    for name in sorted(names):
        if not name.startswith(stem + "-") or "." in name:
            continue
        p = os.path.join(deps, name)
        try:
            if os.stat(p).st_ino == inode:
                return name, p
        except OSError:
            continue
    return None


def fingerprint_dir(release_dir, hook_name):
    fp = os.path.join(release_dir, ".fingerprint")
    try:
        names = sorted(os.listdir(fp))
    except OSError:
        return None
    for name in names:
        if name.startswith(hook_name + "-"):
            return os.path.join(fp, name)
    return None


def recover(roots=None):
    with io.open(PIN, encoding="utf-8") as fh:
        pin = json.load(fh)
    want = pin["sha256"]
    hook_rel = pin.get("hook", "target/release/sentinel-hook")
    hook_name = os.path.basename(hook_rel)
    hook_abs = os.path.join(REPO, hook_rel)

    rec = {
        "schema": "run-b-instrument-build/1",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generator": "paper/scripts/release/recover_build_timestamp.py",
        "binary_sha256": want,
        "binary_path_in_repo": hook_rel,
        "pinned_commit": pin.get("commit"),
        "pinned_at": pin.get("pinned_at"),
    }

    # 1. Is the file the watchdog hashes still the pinned one?
    if os.path.isfile(hook_abs):
        got = sha256_file(hook_abs)
        rec["binary_present"] = True
        rec["binary_hash_matches_pin"] = (got == want)
        if got != want:
            rec["binary_sha256_on_disk"] = got
        rec["binary_in_repo_stat"] = stat_times(hook_abs)
        rec["rustc_version"] = rustc_version(hook_abs)
        rec["embedded_build_stamp"] = embedded_timestamp(hook_abs)
    else:
        rec["binary_present"] = False
        rec["binary_hash_matches_pin"] = None

    # 2. Why the in-repo mtime is not the build timestamp.
    rel_dir = os.path.dirname(hook_abs)
    siblings = []
    if os.path.isdir(rel_dir):
        siblings = sorted(n for n in os.listdir(rel_dir))
    rec["repo_target_release_contents"] = siblings
    rec["repo_target_release_is_cargo_tree"] = is_cargo_tree(rel_dir)
    if not is_cargo_tree(rel_dir):
        rec["why_repo_mtime_is_not_the_build_time"] = (
            "The directory holds %d entr%s and neither `deps/` nor "
            "`.fingerprint/`, and the binary's link count is %s. Cargo uplifts "
            "a release binary as a HARDLINK from `deps/`, so a genuine build "
            "leaves both the directory and a link count of 2. This tree was "
            "populated by a copy, and its mtime is the copy's, not the "
            "linker's."
            % (len(siblings), "y" if len(siblings) == 1 else "ies",
               rec.get("binary_in_repo_stat", {}).get("links")))
    else:
        rec["why_repo_mtime_is_not_the_build_time"] = (
            "This IS a cargo tree, which is necessary and not sufficient: a "
            "tree that was rebuilt and then had the pinned bytes copied back "
            "over the rebuild looks exactly like this. Whether it built these "
            "bytes is decided by C1-C4 in `corroboration`, not by the presence "
            "of `deps/`.")

    # 3. Find a cargo build tree that CORROBORATES having built these bytes.
    release_dir, cand, considered = find_build_tree(
        want, hook_name, pin.get("commit"), roots=roots)
    rec["corroboration"] = {
        "tests": {
            "C1": "the binary's birth time equals its mtime - a linker writes "
                  "its output once, and `cp -p` cannot forge a birth time",
            "C2": "the unit's `invoked.timestamp` is at or before the mtime - "
                  "rustc cannot start after the link it feeds",
            "C3": "the uplifted binary is a hardlink of its `deps/` twin - "
                  "cargo's uplift signature",
            "C4": "the tree's worktree is clean and checked out at the pinned "
                  "commit",
        },
        "candidates_considered": considered,
        "why": ("Structure alone accepted a tree that had the pinned bytes "
                "copied into it after a rebuild, and this script published its "
                "mtime as a build timestamp while printing, in the same "
                "record, a fingerprint timestamp fourteen hours later and a "
                "worktree at the wrong commit."),
    }
    if not release_dir:
        rejected = [c for c in considered if not c.get("accepted")]
        rec["recovered"] = False
        rec["build_timestamp"] = None
        rec["build_timestamp_status"] = "unrecoverable"
        rec["build_timestamp_reason"] = (
            "No build timestamp was captured at build time: the workspace has "
            "no build.rs, the binary embeds no date (only a rustc version "
            "string), and no surviving cargo build tree corroborates having "
            "built a binary with the pinned SHA-256. %d candidate tree(s) held "
            "the right bytes and each failed at least one of C1-C4; the "
            "failures are listed under `corroboration.candidates_considered`. "
            "A tree that was populated by a copy carries the copy's mtime, and "
            "publishing it would be a fabricated build record. Collection ends "
            "at the 2026-08-27 budget cap and the instrument must not be "
            "rebuilt, so this field cannot be filled later without inventing "
            "it. What survives are the bounds below."
            % len(rejected))
        rec["build_timestamp_lower_bound"] = commit_date(pin.get("commit"))
        rec["build_timestamp_lower_bound_note"] = (
            "commit date of the pinned source commit; the binary cannot "
            "predate it")
        rec["build_timestamp_upper_bound"] = \
            rec.get("binary_in_repo_stat", {}).get("mtime")
        rec["build_timestamp_upper_bound_note"] = (
            "mtime of the binary at the path the watchdog hashes; whatever "
            "wrote those bytes there had them by then")
        return rec

    st = os.stat(cand)
    twin = deps_twin(release_dir, hook_name, st.st_ino)
    fp = fingerprint_dir(release_dir, hook_name)
    head, clean = worktree_commit(release_dir)

    ev = {
        # Deliberately a placeholder: the real path names the operator's home
        # directory, and this record ships.
        "build_tree": "<cargo build tree, outside the released corpus>",
        "uplifted_binary": os.path.join("target/release", hook_name),
        "uplifted_binary_stat": stat_times(cand),
    }
    if twin:
        ev["deps_object"] = os.path.join("target/release/deps", twin[0])
        ev["deps_object_stat"] = stat_times(twin[1])
        ev["hardlinked_to_deps"] = True
    else:
        ev["hardlinked_to_deps"] = False
    if fp:
        ev["fingerprint_dir"] = os.path.join(
            "target/release/.fingerprint", os.path.basename(fp))
        for name in ("invoked.timestamp", "bin-" + hook_name):
            p = os.path.join(fp, name)
            if os.path.exists(p):
                ev["fingerprint_" + name.replace(".", "_").replace("-", "_")] \
                    = stat_times(p)["mtime"]
    ev["worktree_head"] = head
    ev["worktree_clean"] = clean
    ev["worktree_head_matches_pinned_commit"] = (
        bool(head) and bool(pin.get("commit"))
        and head.startswith(pin["commit"]))
    rec["evidence"] = ev

    linked = ev["uplifted_binary_stat"]["mtime"]
    rec["recovered"] = True
    rec["build_timestamp"] = linked
    rec["build_timestamp_status"] = "recovered from filesystem evidence"
    rec["build_timestamp_resolution"] = (
        "nanosecond, read from st_mtime_ns as an integer. An earlier version "
        "formatted the float st_mtime and printed three digits the filesystem "
        "never held (`...752174854Z` for a file stat(1) reports as "
        "`...752174801Z`).")
    rec["build_timestamp_method"] = (
        "mtime of the linker's output for this unit. The binary with the pinned "
        "SHA-256 was found in a cargo build tree that passed C1-C4: it is a "
        "hardlink of `target/release/deps/<crate>-<metadata>` (same inode), its "
        "birth time equals its mtime to the nanosecond so nothing copied it in, "
        "the unit's `invoked.timestamp` precedes the link, and the tree is a "
        "clean worktree at the pinned commit.")
    rec["build_timestamp_caveats"] = [
        "An mtime is a filesystem fact, not an assertion the compiler made "
        "about itself. Nothing in the binary corroborates it.",
        "It is the link-completion instant, not the instant compilation began; "
        "`invoked.timestamp` above gives that.",
        "It is recovered after the fact from a tree that was not created for "
        "this purpose. It is evidence, not a captured build record.",
        "C1 rests on the filesystem recording a birth time and on nothing "
        "having reset it. It rules out `cp -p`, which is the restore path this "
        "project actually used; it does not rule out a deliberate forgery.",
    ]
    rec["build_timestamp_lower_bound"] = commit_date(pin.get("commit"))
    rec["build_timestamp_lower_bound_note"] = (
        "commit date of the pinned source commit; the binary cannot predate it")
    rec["build_timestamp_upper_bound"] = \
        rec.get("binary_in_repo_stat", {}).get("mtime")
    rec["build_timestamp_upper_bound_note"] = (
        "mtime of the copy at the path the watchdog hashes; the binary existed "
        "before it was copied there")
    return rec


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stdout", action="store_true",
                    help="print the record and write nothing")
    ap.add_argument("--search-root", action="append", metavar="DIR",
                    help="where to look for a cargo build tree (repeatable). "
                         "Default: the repository's parent and $HOME. Given "
                         "explicitly, this is how the corroboration gate is "
                         "falsified: point it at a tree that did not build the "
                         "pinned bytes and the field must come back "
                         "unrecoverable rather than carrying that tree's "
                         "mtime.")
    args = ap.parse_args()

    rec = recover(roots=args.search_root)
    text = json.dumps(rec, indent=1, sort_keys=True) + "\n"
    if args.stdout:
        sys.stdout.write(text)
        return 0
    io.open(OUT, "w", encoding="utf-8", newline="\n").write(text)
    print("  wrote %s" % os.path.relpath(OUT, REPO))
    if rec.get("recovered"):
        print("  build timestamp recovered: %s" % rec["build_timestamp"])
    else:
        print("  build timestamp UNRECOVERABLE - recorded with the reason")
    rejected = [c for c in rec.get("corroboration", {})
                .get("candidates_considered", []) if not c.get("accepted")]
    for c in rejected:
        print("  rejected %s: %s" % (c["tree"], c["failed"][0].split(":")[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
