#!/usr/bin/env python
"""One reader for every campaign archive, and a check that it read them all."""

import argparse
import collections
import io
import json
import os
import re
import sys

DATA = os.path.join("paper", "data")

SET_ASIDE_PREFIX = "events."

_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "..", "..", ".."))
_CONTAM_NAME = os.path.join("paper", "run-b-excluded-sessions.txt")
# Every spelling tried, in order, kept so the refusal can name all of them.
CONTAMINATED_CANDIDATES = (os.path.join(_ROOT, _CONTAM_NAME), _CONTAM_NAME)
CONTAMINATED = (CONTAMINATED_CANDIDATES[0]
                if os.path.exists(CONTAMINATED_CANDIDATES[0])
                else _CONTAM_NAME)


class OffInstrumentListError(RuntimeError):
    """The off-instrument exclusion list is missing, unreadable or inconsistent."""


def _refuse_contaminated(path, why):
    tried = "".join("    %s\n" % os.path.abspath(c)
                    for c in dict.fromkeys((path,) + CONTAMINATED_CANDIDATES))
    raise OffInstrumentListError(
        "\n\n"
        "  THE OFF-INSTRUMENT EXCLUSION LIST COULD NOT BE USED, so no reader\n"
        "  can say which sessions the pinned instrument decided.\n"
        "\n"
        "  %s\n"
        "\n"
        "  Spellings tried:\n"
        "%s"
        "\n"
        "  Refusing to read the corpus rather than admitting sessions that\n"
        "  may have been decided by another guard binary. On 2026-08-25 that\n"
        "  was 97 sessions and 1,087 events, pooled into Run B, reported as a\n"
        "  clean parse with off-inst printed as 0.\n"
        "\n"
        "  If this tree genuinely has no off-instrument sessions, say so:\n"
        "  write %s containing a header line\n"
        "  reading '# count   0' and no entries. An empty exclusion has to be\n"
        "  declared, because a file that is not there is not a claim that\n"
        "  there is nothing to exclude.\n"
        % (why, tried, _CONTAM_NAME))

EXCLUDE_CONTAMINATED = True

_CONTAM_CACHE = {}


_DECLARED_RE = re.compile(r"^#\s*count\s+(\d+)\s*$")


def _load_contaminated(path=CONTAMINATED):
    """(keys, depths) from the list. Cached on (path, mtime, size)."""
    try:
        st = os.stat(path)
        stamp = (os.path.abspath(path), st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = (os.path.abspath(path), None, None)
    hit = _CONTAM_CACHE.get(stamp)
    if hit is not None:
        return hit
    keys, depths = set(), set()
    declared = None
    try:
        fh = io.open(path, encoding="utf-8")
    except (IOError, OSError) as exc:
        _refuse_contaminated(
            path, "It could not be opened: %s." % exc)
    with fh:
        for line in fh:
            line = line.strip().replace("\\", "/").strip("/")
            if line.startswith("#"):
                m = _DECLARED_RE.match(line)
                if m:
                    declared = int(m.group(1))
                continue
            if not line:
                continue
            keys.add(line)
            depths.add(len(line.split("/")))
    if declared is None:
        _refuse_contaminated(
            path,
            "It was read, but it declares no count. A list has to state how\n"
            "  many sessions it holds ('# count   N') or a truncated copy is\n"
            "  indistinguishable from a complete one.")
    if declared != len(keys):
        _refuse_contaminated(
            path,
            "It declares '# count   %d' and carries %d entr%s. A list that\n"
            "  disagrees with its own header has been truncated, merged or\n"
            "  hand-edited, and the difference is sessions that would be\n"
            "  re-admitted."
            % (declared, len(keys), "y" if len(keys) == 1 else "ies"))
    out = (frozenset(keys), tuple(sorted(depths, reverse=True)))
    _CONTAM_CACHE[stamp] = out
    return out


def contaminated_declared(path=CONTAMINATED):
    """The count the list declares in its own header. Raises if unusable."""
    keys, _depths = _load_contaminated(path)
    return len(keys)


def contaminated_sessions(path=CONTAMINATED):
    """The archive-relative path of every session collected off-instrument."""
    return _load_contaminated(path)[0]


def _contaminated_hit(path, keys, depths):
    """The primitive: does `path` end in one of the listed spellings?"""
    if not keys:
        return False
    parts = os.path.normpath(path).replace("\\", "/").split("/")
    for depth in depths:
        if len(parts) >= depth and "/".join(parts[-depth:]) in keys:
            return True
    return False


def is_contaminated(path, listing=CONTAMINATED):
    """Was this session log decided by a guard that was not the instrument?"""
    keys, depths = _load_contaminated(listing)
    return _contaminated_hit(path, keys, depths)


def contaminated_in(archive, listing=CONTAMINATED):
    """The (session, path) pairs `session_files` drops from this archive."""
    keys, depths = _load_contaminated(listing)
    if not keys:
        return []
    return [(s, p) for s, p in session_files(archive, exclude_contaminated=False)
            if _contaminated_hit(p, keys, depths)]


def session_files(archive, exclude_contaminated=None):
    """(session_name, path) for each session log, whichever layout is used."""
    if exclude_contaminated is None:
        exclude_contaminated = EXCLUDE_CONTAMINATED
    out = []
    stray = []
    stray_dir = []
    # `layout()`'s flat test, inlined: an archive with an events/ directory is
    # an Antigravity/API archive and its sessions are the files inside it.
    flat = os.path.isdir(os.path.join(archive, "events"))
    for root, dirs, names in os.walk(archive):
        rel = os.path.relpath(root, archive)
        parts = [] if rel == os.curdir else rel.split(os.sep)
        holder = parts[-1] if parts else os.path.basename(root)

        # Never descend into a set-aside sibling, and never read one if the
        # caller handed us the sibling itself as the archive.
        dirs[:] = [d for d in dirs if not d.startswith(SET_ASIDE_PREFIX)]
        if holder.startswith(SET_ASIDE_PREFIX):
            continue

        if holder == "events":
            for name in dirs:
                if not name.startswith(SET_ASIDE_PREFIX):
                    stray_dir.append(os.path.join(root, name))
            dirs[:] = []
            for name in names:
                if name.endswith(".jsonl"):
                    out.append((name[:-len(".jsonl")],
                                os.path.join(root, name)))
            continue

        if "events.jsonl" in names:
            if flat:
                stray.append(os.path.join(root, "events.jsonl"))
            else:
                out.append((holder, os.path.join(root, "events.jsonl")))

    if stray:
        sys.stderr.write(
            "\n  %s has an events/ directory, so it is a flat archive and its\n"
            "  sessions are the files in events/. %d file(s) named\n"
            "  events.jsonl sit outside it and were NOT read:\n%s\n"
            "  Move them under events/ if they are sessions, or rename the\n"
            "  directory holding them to events.<something> if they were set\n"
            "  aside. Reporting rather than reading them silently.\n\n"
            % (archive, len(stray),
               "".join("    %s\n" % p for p in sorted(stray))))
    if stray_dir:
        sys.stderr.write(
            "\n  %s has %d DIRECTOR%s inside events/, where this reader\n"
            "  expects one file per session. They were NOT read and nothing\n"
            "  below them was walked:\n%s\n"
            "  Rename to events.<something> if they were set aside, or move\n"
            "  their logs up into events/ if they are sessions. Reporting\n"
            "  rather than dropping them silently.\n\n"
            % (archive, len(stray_dir), "Y" if len(stray_dir) == 1 else "IES",
               "".join("    %s\n" % p for p in sorted(stray_dir))))
    out.sort()
    if exclude_contaminated:
        keys, depths = _load_contaminated()
        out = [(s, p) for s, p in out
               if not _contaminated_hit(p, keys, depths)]
    return out


BAD_LINES = {}
UNREADABLE = {}


def reset_read_census():
    """Forget what previous reads dropped. For tests and positive controls."""
    BAD_LINES.clear()
    UNREADABLE.clear()


def read_census():
    """(dropped lines, logs with dropped lines, unreadable logs) so far."""
    return (sum(BAD_LINES.values()), len(BAD_LINES), len(UNREADABLE))


def report_read_losses(what, stream=None):
    """Write what the reader dropped, and return the number of lines."""
    dropped, logs, unread = read_census()
    if not dropped and not unread:
        return 0
    out = stream or sys.stderr
    out.write("\n  %s DID NOT READ EVERYTHING IT WALKED.\n" % what)
    if dropped:
        out.write("  %d line(s) in %d session log(s) would not parse and were\n"
                  "  dropped. Every count above is over the remainder:\n"
                  % (dropped, logs))
        for path in sorted(BAD_LINES)[:20]:
            out.write("    %-6d %s\n" % (BAD_LINES[path], path))
        if len(BAD_LINES) > 20:
            out.write("    ... and %d more\n" % (len(BAD_LINES) - 20))
        out.write("  A torn last line is the normal in-flight state of a log a\n"
                  "  collection is still appending to. It is also what a\n"
                  "  half-written record looks like forever. Check which.\n")
    if unread:
        out.write("  %d session log(s) could not be opened at all and were\n"
                  "  counted as empty:\n" % unread)
        for path in sorted(UNREADABLE)[:20]:
            out.write("    %s  (%s)\n" % (path, UNREADABLE[path]))
    out.write("\n")
    return dropped


def read_log(path):
    """(events, bad_line_count) from one session log."""
    events, bad = [], 0
    try:
        fh = io.open(path, encoding="utf-8", errors="replace")
    except OSError as exc:
        UNREADABLE[path] = "%s: %s" % (type(exc).__name__, exc)
        return events, bad
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                bad += 1
    if bad:
        BAD_LINES[path] = bad
    elif path in BAD_LINES:
        del BAD_LINES[path]
    return events, bad


def load_events(archive, where=None):
    """Every event in the archive. `where` maps run_id -> session name."""
    events = []
    for session, path in session_files(archive):
        got, _bad = read_log(path)
        for e in got:
            events.append(e)
            if where is not None:
                run = e.get("run_id")
                if run:
                    where.setdefault(str(run), session)
    return events


def looks_populated(archive):
    """Does this directory obviously hold session data, by any layout?"""
    n = 0
    for root, dirs, names in os.walk(archive):
        for name in names:
            if name in ("campaign.json", "sessions.jsonl", "manifest.json"):
                continue
            full = os.path.join(root, name)
            if name.endswith(".jsonl"):
                n += 1
            elif name.endswith((".jsonl.gz", ".jsonl.bz2", ".jsonl.zst",
                                ".jsonl.xz", ".ndjson")):
                # A log the reader cannot open is still data nobody read.
                n += 1
            elif not os.path.exists(full) and os.path.islink(full):
                # A dangling symlink: `session_files` counts it and reads
                # nothing out of it.
                n += 1
        for name in dirs:
            # A DIRECTORY named like a session log. `session_files` yields it
            # and `read_log` swallows the IsADirectoryError into an empty
            # list, so the archive reports zero events over real data.
            if name.endswith(".jsonl"):
                n += 1
    return n


def schema(archive):
    """Which fields this archive's tool_calls actually carry."""
    fields = collections.Counter()
    calls = 0
    for _session, path in session_files(archive):
        got, _bad = read_log(path)
        for e in got:
            if e.get("kind") != "tool_call":
                continue
            calls += 1
            for k, v in e.items():
                if v is not None:
                    fields[k] += 1
    return calls, fields


def layout(archive):
    """'nested' (Claude Code), 'flat' (Antigravity), or 'unknown'."""
    if os.path.isdir(os.path.join(archive, "events")):
        return "flat"
    try:
        for name in os.listdir(archive):
            if name.startswith(SET_ASIDE_PREFIX):
                continue
            if os.path.isfile(os.path.join(archive, name, "events.jsonl")):
                return "nested"
    except OSError:
        pass
    return "unknown"


def require_nested(archive, what):
    """Refuse to analyse a flat archive with a nested-only analysis."""
    lay = layout(archive)
    if lay == "nested":
        return
    sys.stderr.write(
        "\n  %s reads the per-session layout (result.json, one directory per\n"
        "  session) that only the Claude Code campaigns write. %s has a '%s'\n"
        "  layout, so this analysis has nothing to read and would report zero.\n"
        "  Refusing rather than printing it.\n\n" % (what, archive, lay))
    raise SystemExit(2)


def require_sessions(archive, what):
    """Refuse an archive whose sessions this reader cannot see. Both layouts."""
    lay = layout(archive)
    files = (session_files(archive, exclude_contaminated=False)
             if lay in ("nested", "flat") else [])
    if files:
        return
    populated = looks_populated(archive)
    if lay in ("nested", "flat") and not populated:
        # A recognised layout holding nothing at all. Empty is a real answer.
        return
    if lay == "unknown":
        why = ("has no layout this reader recognises (neither "
               "<session>/events.jsonl nor events/<session>.jsonl)")
    else:
        why = ("has a '%s' layout but no session logs in it, while %d .jsonl "
               "file(s) sit elsewhere below it" % (lay, populated))
    sys.stderr.write(
        "\n  %s found no session logs to read. %s\n  %s.\n"
        "  Every count over it would be zero, and a zero here is\n"
        "  indistinguishable from an archive with nothing in it.\n"
        "  Refusing rather than printing it.\n\n" % (what, archive, why))
    raise SystemExit(2)


def archives():
    if not os.path.isdir(DATA):
        return []
    out = []
    for d in sorted(os.listdir(DATA)):
        p = os.path.join(DATA, d)
        if d.startswith("denials") and os.path.isdir(p):
            out.append((d, p))
    return out


def unhooked_counts():
    """(rows, affected, totals) for tab:app-blastradius, computed not printed."""
    rows = []
    total_g = total_u = 0
    for label, path in archives():
        if label.endswith(".unhooked"):
            continue
        guarded = sum(1 for x in os.listdir(path)
                      if os.path.isdir(os.path.join(path, x)))
        up = path + ".unhooked"
        quar = 0
        if os.path.isdir(up):
            quar = sum(1 for x in os.listdir(up)
                       if os.path.isdir(os.path.join(up, x)))
        total_g += guarded
        total_u += quar
        rows.append((label, guarded, quar))
    affected = [r for r in rows if r[2]]
    return rows, affected, (total_g, total_u)


def unhooked_census():
    """Guarded against quarantined session directories, per archive."""
    rows, affected, (total_g, total_u) = unhooked_counts()
    print("")
    print("  INPUT: %s" % os.path.abspath(DATA))
    print("         %d archive(s) matching denials*, .unhooked/ read beside"
          % len(rows))
    print("         each; both columns are directory counts.")
    print("")
    print("  The guard-down window: sessions collected while the hooks")
    print("  were not firing are quarantined, not deleted.")
    print("")
    print("  %-30s %9s %11s" % ("archive", "guarded", "quarantined"))
    for label, guarded, quar in affected:
        print("  %-30s %9d %11d" % (label, guarded, quar))
    ag = sum(g for _l, g, _q in affected)
    aq = sum(q for _l, _g, q in affected)
    print("  %-30s %9s %11s" % ("", "-" * 9, "-" * 11))
    print("  %-30s %9d %11d" % ("those %d archives" % len(affected), ag, aq))
    print("  %-30s %9d %11d" % ("every other archive",
                                total_g - ag, total_u - aq))
    print("  %-30s %9d %11d" % ("all archives", total_g, total_u))
    print("")
    biggest = max(rows, key=lambda r: r[1]) if rows else None
    if biggest:
        print("  The guarded column counts DIRECTORIES, which is the right")
        print("  unit for a blast radius and the wrong one for a rate: %d of"
              % biggest[1])
        print("  the %d in the last row but one are %s."
              % (total_g - ag, biggest[0]))
        print("  See models.py --census for how many of those ever ran.")
    print("")
    print("  The five archives above are closed. The last two rows include")
    print("  every denials-api-* cell and grow while a run collects.")
    return 0


def contaminated_census():
    """The 97, per archive: retained on disk, excluded from every analysis."""
    keys = contaminated_sessions()
    declared = contaminated_declared()
    print("")
    print("  INPUT: %s" % os.path.abspath(CONTAMINATED))
    print("         %d session log(s) listed, %d declared by its header"
          % (len(keys), declared))
    print("")
    if not keys:
        # A DECLARED empty list. `_load_contaminated` has already refused an
        # absent or unreadable one, so this is a tree that states it has no
        # off-instrument sessions rather than a tree that lost the list.
        print("  The list declares '# count   0': this tree states that it")
        print("  holds no off-instrument sessions, so nothing is excluded and")
        print("  nothing should be. An absent or unreadable list is refused")
        print("  by the reader before it reaches here.")
        print("")
        return 0

    print("  Sessions decided by a guard binary that was not the pinned")
    print("  instrument. RETAINED on disk (project policy), admitted by nothing.")
    print("")
    print("  %-52s %8s %8s %8s" % ("archive", "on disk", "withheld", "read"))
    total_disk = total_excl = total_read = 0
    mismatched = []
    missing = []
    for label, path in archives():
        allf = session_files(path, exclude_contaminated=False)
        excl = contaminated_in(path)
        if not excl:
            continue
        # OBSERVED, NOT INFERRED: the filtered walk is run and counted. A
        # subtraction would report the exclusion as done whether or not
        # `session_files` performed it.
        read = session_files(path)
        total_disk += len(allf)
        total_excl += len(excl)
        total_read += len(read)
        if len(allf) - len(read) != len(excl):
            mismatched.append((label, len(allf), len(read), len(excl)))
        print("  %-52s %8d %8d %8d"
              % (label, len(allf), len(allf) - len(read), len(read)))
    print("  %-52s %8s %8s %8s" % ("", "-" * 8, "-" * 8, "-" * 8))
    print("  %-52s %8d %8d %8d"
          % ("those archives", total_disk, total_disk - total_read, total_read))
    print("")

    # THE READER MUST HAVE DONE IT. A listed path that matches the corpus and
    # is still returned by the filtered walk is the exclusion failing while
    # the census reports it succeeding.
    if mismatched:
        print("  THE FILTERED WALK DID NOT WITHHOLD WHAT THE LIST MATCHES:")
        for label, n_all, n_read, n_excl in mismatched:
            print("    %-48s on disk %d, read %d, listed %d"
                  % (label, n_all, n_read, n_excl))
        print("")
        print("  session_files() is admitting sessions the list names, or")
        print("  dropping sessions it does not. Either way the corpus every")
        print("  analysis reads is not the corpus this census describes.")
        print("")
        return 1

    # EVERY LISTED PATH MUST STILL BE THERE. They are retained deliberately, so
    # a path that has gone missing is not a stale list, it is deleted evidence.
    for key in sorted(keys):
        if not os.path.exists(os.path.join(DATA, key)):
            missing.append(key)
    if missing:
        print("  %d LISTED SESSION(S) ARE NOT ON DISK:" % len(missing))
        for key in missing:
            print("    %s" % key)
        print("")
        print("  These are retained by rule. A missing one means the log was")
        print("  deleted, moved or renamed, and the exclusion can no longer be")
        print("  audited against the corpus it describes.")
        print("")
        return 1
    print("  All %d listed session logs are present on disk." % len(keys))
    print("  Declared by the list header: %d." % declared)
    print("  Matched under %s: %d." % (DATA, total_excl))
    print("  Withheld by the filtered walk: %d." % (total_disk - total_read))
    print("")
    if not (declared == total_excl == total_disk - total_read):
        print("  DECLARED, MATCHED AND WITHHELD DISAGREE. The exclusion is")
        print("  not the one the list describes.")
        print("")
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--schema", action="store_true",
                    help="report which tool_call fields each archive carries")
    ap.add_argument("--unhooked", action="store_true",
                    help="the guard-down window: guarded against quarantined "
                         "session counts, per archive")
    ap.add_argument("--contaminated", action="store_true",
                    help="the sessions collected against a guard that was not "
                         "the pinned instrument: retained on disk, excluded "
                         "from every analysis, counted here")
    args = ap.parse_args()

    if args.unhooked:
        return unhooked_census()
    if args.contaminated:
        return contaminated_census()

    rows, unreadable, empty = [], [], []
    excluded_total = 0
    for label, path in archives():
        files = session_files(path)
        events = load_events(path)
        populated = looks_populated(path)
        nexcl = len(contaminated_in(path))
        excluded_total += nexcl
        rows.append((label, len(files), len(events), populated, nexcl))
        if not events:
            if files:
                empty.append((label, len(files)))
            elif populated:
                unreadable.append((label, populated))

    print("")
    print("  %-44s %7s %9s %8s %8s"
          % ("archive", "logs", "events", "jsonl", "off-inst"))
    for label, nf, ne, pop, nexcl in rows:
        mark = ""
        if ne == 0 and nf:
            mark = "  <-- all logs empty (stubs)"
        elif ne == 0 and pop:
            mark = "  <-- UNREADABLE LAYOUT"
        print("  %-44s %7d %9d %8d %8d%s"
              % (label, nf, ne, pop, nexcl, mark))
    if excluded_total:
        print("")
        print("  off-inst: %d session log(s) retained on disk and admitted by"
              % excluded_total)
        print("  no analysis - collected against a guard binary that was not")
        print("  the pinned instrument. See --contaminated.")

    if empty:
        print("")
        print("  %d archive(s) hold only empty logs - launched, recorded"
              % len(empty))
        print("  nothing. Expected for quota stubs; confirm before reporting:")
        for label, nf in empty:
            print("    %-44s %d empty log(s)" % (label, nf))

    if args.schema:
        print("")
        print("  tool_call fields present, by archive")
        for label, path in archives():
            calls, fields = schema(path)
            if not calls:
                continue
            named = ", ".join("%s=%d" % (k, v) for k, v in
                              sorted(fields.items()) if k != "kind")
            print("    %-42s %5d calls" % (label, calls))
            print("      %s" % named)

    print("")
    if unreadable:
        print("  %d ARCHIVE(S) HOLD DATA THIS READER CANNOT PARSE:" %
              len(unreadable))
        for label, pop in unreadable:
            print("    %-44s %d .jsonl file(s)" % (label, pop))
        print("")
        print("  An analysis over these returns empty, which is")
        print("  indistinguishable from an archive with nothing in it.")
        print("  Teach session_files() the layout before trusting any")
        print("  number computed over them.")
        return 1

    total_logs = sum(r[1] for r in rows)
    total_events = sum(r[2] for r in rows)
    print("  every archive parsed: %d session logs, %d events, 0 unreadable"
          % (total_logs, total_events))
    return 0


if __name__ == "__main__":
    # The refusal is printed rather than tracebacked, but it is still a
    # refusal: exit 2, no table, nothing that could be mistaken for a count.
    try:
        _rc = main()
    except OffInstrumentListError as _exc:
        sys.stderr.write("%s\n" % _exc)
        sys.exit(2)
    report_read_losses("archive.py")
    sys.exit(_rc)
