#!/usr/bin/env python
"""Does every number in the paper still come out of the data?"""

import argparse
import ast
import collections
import io
import json
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", ".."))
DATA = os.path.join(REPO, "paper", "data")
PASS, FAIL, INFO = [], [], []

SKIP_ABSENT = "absent"
SKIP_UNMEASURED = "unmeasured"

SKIP = []


def load(name):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return None
    rows = []
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    return rows


def check(name, got, want):
    """Exact equality against a published number."""
    if got == want:
        PASS.append((name, got))
    else:
        FAIL.append((name, got, want))


def note(name, value):
    INFO.append((name, value))


def near(name, got, want, tol):
    if abs(got - want) <= tol:
        PASS.append((name, "%.2f" % got))
    else:
        FAIL.append((name, "%.2f" % got, "%.2f +/- %.2f" % (want, tol)))



_PRESENT = {}


def present(key):
    """Is the named corpus on this machine? Memoised; the disk does not move."""
    if key not in _PRESENT:
        _PRESENT[key] = bool(CORPUS[key]())
    return _PRESENT[key]


def _file(*parts):
    """A corpus file that exists and has something in it."""
    try:
        return os.path.getsize(os.path.join(DATA, *parts)) > 0
    except OSError:
        return False


# THE PATH BEHIND EACH FLAT CORPUS KEY, DECLARED RATHER THAN CLOSED OVER, so
# `corpus_files_intact()` can look at the file itself instead of only at the
# boolean `_file()` reduces it to.
_FLAT_CORPUS = {
    "atbench": ("atbench-violations.jsonl",),
    "atbench-actions": ("atbench-actions.jsonl",),
    "stepshield": ("violations.jsonl",),
    "rjudge": ("rjudge-violations.jsonl",),
    "policy": ("policy-statements.jsonl",),
    "aiware": ("aiware-statements.jsonl",),
    "readmes": ("readmes-statements.jsonl",),
    "holdout-atbench": ("atbench-violations.jsonl.labels-holdout.jsonl",),
    "holdout-policy": ("policy-statements.labels-holdout.jsonl",),
    "labelkit": ("labelkit", "_keys", "key-holdout-policy.json"),
}

# The inverse, for the blocks that name a corpus by its filename and need to
# say which key is missing.
_KEY_OF_FILE = dict((parts[-1], key) for key, parts in _FLAT_CORPUS.items())


def _glob(*parts):
    return bool(glob.glob(os.path.join(DATA, *parts)))


def _campaign_events():
    """The nested layout: paper/data/denials/<session>/events.jsonl."""
    return _glob("denials", "*", "events.jsonl")


def _api_events():
    """The API layout: paper/data/denials-api-<cell>/events/<session>.jsonl."""
    return _glob("**", "events", "*.jsonl") or _glob("**", "events.jsonl")


def _effort_archives():
    """Every archive `tab:app-effort` reads: two models x six effort rungs."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import models as md
    except Exception:  # noqa: BLE001 - see the docstring: fail closed
        return True
    for _model, rungs in md.EFFORT.items():
        for _label, archive in rungs:
            if not _glob(archive, "*", "events.jsonl"):
                return False
    return True


def _runa_corpus():
    """Run A's ten cells, WHICH ARE NOT UNDER paper/data/. See run_a_report.py."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import run_a_report as ra
    except Exception:  # noqa: BLE001 - see the docstring: fail closed
        return True
    return len(ra.cell_dirs(ra.CORPUS)) == ra.CELLS


CORPUS = {
    # Flat corpora, one file each; the paths are in `_FLAT_CORPUS`.
    # Archives.
    "campaign": _campaign_events,
    "api": _api_events,
    "agy": lambda: _glob("denials-agy-*"),
    # Run A, out of tree. See `_runa_corpus`.
    "runa": _runa_corpus,
    "opus-arms": lambda: all(
        _glob(a, "*", "events.jsonl") for a in
        ("denials-opus", "denials-terse-opus", "denials-explain-opus",
         "denials-padded-opus", "denials-defer-opus")),
    "ablation": lambda: _glob("denials-terse*") or _glob("denials-full*"),
    "models": lambda: all(_glob(a, "*", "events.jsonl") for a in
                          ("denials-full", "denials-sonnet", "denials-opus")),
    # The effort rungs, which are a strict superset of `models` and are what
    # tab:app-effort reads. See `_effort_archives`.
    "models-effort": _effort_archives,
    "platform": lambda: _glob("platform", "*results.txt"),
    "incidents": lambda: os.path.isdir(os.path.join(DATA, "incidents")),
    # The empty requirement. A gate that reads no corpus can never be excused
    # by a missing one, so its failures are always failures.
    "none": lambda: True,
}

for _key, _parts in _FLAT_CORPUS.items():
    # `_parts=_parts` binds at definition time; a bare closure over the loop
    # variable gives every corpus the LAST path, which is the shadowed-loop-
    # variable bug this suite's opening docstring is about.
    CORPUS[_key] = (lambda parts: lambda: _file(*parts))(_parts)
del _key, _parts


def corpus_files_intact():
    """A required corpus that is HERE AND EMPTY is a failure, not an errand."""
    if not os.path.isdir(DATA):
        # A tree with no paper/data at all has nothing to be truncated. That
        # is absence and is reported as one named skip - NOT as a pass, which
        # is what a bare `return` here would have amounted to.
        SKIP.append(("corpus files inspected for truncation",
                     "no paper/data directory in this tree", SKIP_ABSENT))
        return
    inspected = 0
    for key, parts in sorted(_FLAT_CORPUS.items()):
        path = os.path.join(DATA, *parts)
        if not os.path.exists(path):
            continue          # genuinely absent; the per-gate skips say so
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            FAIL.append(("corpus file %s is readable" % key,
                         str(exc)[:50], "readable"))
            continue
        inspected += 1
        if size == 0:
            FAIL.append(("corpus file %s is not empty" % key,
                         "0 bytes at paper/data/%s" % os.path.join(*parts),
                         "a populated corpus, not a truncated one"))
    # A tree with paper/data present and every flat corpus gone reads zero
    # here and FAILS, instead of passing silently the way the failures-only
    # version did.
    check("corpus files inspected for truncation", inspected >= 1, True)


def needs(*keys):
    """A gate whose every check reads the same corpus (usually exactly one)."""
    return lambda row: keys


def _absent(keys):
    return [k for k in keys if not present(k)]


def _no_corpus(gone):
    """The reason string for a corpus-absence skip."""
    return "no %s corpus on this machine" % ", ".join(gone)


def guarded(label, keys, names, body):
    """Run `body`; or, if the corpus it reads is absent, skip it OUT LOUD."""
    gone = _absent(keys)
    if gone:
        for name in names:
            SKIP.append((name, _no_corpus(gone), SKIP_ABSENT))
        return
    at_pass, at_fail = len(PASS), len(FAIL)
    body()
    emitted = sorted([r[0] for r in PASS[at_pass:]]
                     + [r[0] for r in FAIL[at_fail:]])
    if emitted != sorted(names):
        undeclared = [n for n in emitted if n not in names]
        undelivered = [n for n in names if n not in emitted]
        FAIL.append(
            ("%s declares every gate it runs" % label,
             "%d undeclared, %d undelivered (%s)"
             % (len(undeclared), len(undelivered),
                "; ".join(undeclared + undelivered)[:90]),
             "roster matches what ran"))


# --------------------------------------------------------------- corpora ---

def corpora():
    sizes = {
        "atbench-actions.jsonl": 8321,
        "atbench-violations.jsonl": 4726,
        "violations.jsonl": 747,
        "rjudge-violations.jsonl": 842,
        "rjudge-actions.jsonl": 1459,
        "policy-statements.jsonl": 13818,
        "aiware-statements.jsonl": 120094,
        "readmes-statements.jsonl": 32281,
    }
    for name, want in sorted(sizes.items()):
        rows = load(name)
        if rows is None:
            FAIL.append(("corpus %s rows" % name,
                         "MISSING - no file at paper/data/%s" % name,
                         "%d rows" % want))
            continue
        check("corpus %s rows" % name, len(rows), want)

    for name, want in (("policy-statements.jsonl", 1204),
                       ("aiware-statements.jsonl", 4273),
                       ("readmes-statements.jsonl", 1717)):
        rows = load(name)
        if rows is None:
            # `continue` HERE WAS SILENCE. No pass, no fail, no skip: the gate
            # ceased to exist and the tally moved by one with nothing to say
            # which one. Absence is a reported state.
            SKIP.append(("corpus %s distinct repos" % name,
                         _no_corpus([_KEY_OF_FILE[name]]), SKIP_ABSENT))
            continue
        if not rows:
            FAIL.append(("corpus %s distinct repos" % name,
                         "present but yielded 0 records", "%d" % want))
            continue
        check("corpus %s distinct repos" % name,
              len(set(r.get("repo") for r in rows if r.get("repo"))), want)

    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import dedup_statements
    except ImportError as exc:
        FAIL.append(("dedup_statements.py imports", str(exc), "ok"))
        dedup_statements = None
    if dedup_statements is not None:
        for name, kept_want, near_want in (
                ("policy-statements.jsonl", 11483, 1),
                ("readmes-statements.jsonl", 28596, 4)):
            rows = load(name)
            if rows is None:
                for label in ("corpus %s after exact dedup" % name,
                              "corpus %s near-duplicates (Hamming <= 3)" % name):
                    SKIP.append((label, _no_corpus([_KEY_OF_FILE[name]]),
                                 SKIP_ABSENT))
                continue
            if not rows:
                # Present but empty. See the note above: a skip here would
                # excuse a truncated corpus as an absent one.
                for label in ("corpus %s after exact dedup" % name,
                              "corpus %s near-duplicates (Hamming <= 3)" % name):
                    FAIL.append((label, "present but yielded 0 records", "ok"))
                continue
            kept = dedup_statements.exact_pass(rows)
            check("corpus %s after exact dedup" % name, len(kept), kept_want)
            check("corpus %s near-duplicates (Hamming <= 3)" % name,
                  dedup_statements.near_duplicates(kept), near_want)

    # The task corpus size, pinned. It was extended from 184 to 240 mid-project
    # and the paper now names both; a silent change to either would make the
    # sentence in section 4 wrong with nothing to catch it.
    tasks = os.path.join(DATA, "..", "scripts", "denials", "tasks.tsv")
    if os.path.isfile(tasks):
        rows = [l for l in io.open(tasks, encoding="utf-8") if l.strip()]
        check("task corpus size", len(rows) - 1, 240)

    guarded("incident artifacts", ("incidents",), [
        "incident startup-folder entries",
        "incident application-data entries",
        "incident real-home files",
        "incident settings file, bytes",
    ], _incident_artifacts)

    holdout_gates()
    agreement_gates()
    policy_gates()
    tables_fresh()

    guarded("ATBench corpus", ("atbench",), [
        "ATBench C1 steps",
        "ATBench C2 steps",
        "ATBench C3 steps",
        "ATBench main rows",
        "ATBench-Claw rows",
        "ATBench-Codex rows",
        "ATBench trajectories",
        "ATBench step-level C1 %",
        "ATBench task populated",
        "ATBench reason populated",
        "ATBench harm_type populated",
        "ATBench failure_mode populated",
        "ATBench risk_source populated",
        "ATBench prior_steps + step-0 rows == all",
        "ATBench rows at step 0",
    ], _atbench_corpus)

    guarded("StepShield corpus", ("stepshield",), [
        "StepShield C1 steps",
        "StepShield C1 % (the published 18.6)",
    ], _stepshield_corpus)

    guarded("R-Judge corpus", ("rjudge",), [
        "R-Judge C1 steps",
    ], _rjudge_corpus)


def _incident_artifacts():
    inc = os.path.join(DATA, "incidents")
    startup = os.path.join(inc, "startup-artifacts")
    if os.path.isdir(startup):
        names = sorted(os.listdir(startup))
        appdata = [n for n in names if n.startswith("appdata-")]
        check("incident startup-folder entries", len(names) - len(appdata), 17)
        check("incident application-data entries", len(appdata), 1)
    else:
        FAIL.append(("incident startup-folder entries", "MISSING", 17))
        FAIL.append(("incident application-data entries", "MISSING", 1))
    home = os.path.join(inc, "home-artifacts")
    if os.path.isdir(home):
        check("incident real-home files", len(os.listdir(home)), 4)
    else:
        FAIL.append(("incident real-home files", "MISSING", 4))
    wiped = os.path.join(inc, "settings-wiped-20260813-2044.json")
    if os.path.isfile(wiped):
        check("incident settings file, bytes", os.path.getsize(wiped), 121)
    else:
        FAIL.append(("incident settings file, bytes", "MISSING", 121))


def _atbench_corpus():
    at = load("atbench-violations.jsonl")
    cls = collections.Counter(r.get("machine_class") for r in at)
    check("ATBench C1 steps", cls.get("C1", 0), 0)
    check("ATBench C2 steps", cls.get("C2"), 3985)
    check("ATBench C3 steps", cls.get("C3"), 741)
    by = collections.Counter(r.get("category") for r in at)
    check("ATBench main rows", by.get("ATBench"), 2419)
    check("ATBench-Claw rows", by.get("ATBench-Claw"), 1706)
    check("ATBench-Codex rows", by.get("ATBench-Codex"), 601)
    trajs = set(r["id"].rsplit("-", 1)[0] for r in at)
    check("ATBench trajectories", len(trajs), 1043)
    near("ATBench step-level C1 %", 100.0 * cls.get("C1", 0) / len(at),
         0.00, 0.01)

    # The enrichment fields. A silent emptying here is the bug this file
    # exists for, so each is asserted rather than eyeballed.
    for field in ("task", "reason", "harm_type", "failure_mode",
                  "risk_source"):
        check("ATBench %s populated" % field,
              sum(1 for r in at if r.get(field)), 4726)
    with_prior = sum(1 for r in at if r.get("prior_steps"))
    at_step0 = sum(1 for r in at if (r.get("step") or 0) == 0)
    check("ATBench prior_steps + step-0 rows == all",
          with_prior + at_step0, 4726)
    check("ATBench rows at step 0", at_step0, 1043)


def _stepshield_corpus():
    ss = load("violations.jsonl")
    cls = collections.Counter(r.get("machine_class") for r in ss)
    check("StepShield C1 steps", cls.get("C1"), 139)
    near("StepShield C1 % (the published 18.6)",
         100.0 * cls.get("C1", 0) / len(ss), 18.6, 0.05)


def _rjudge_corpus():
    rj = load("rjudge-violations.jsonl")
    cls = collections.Counter(r.get("machine_class") for r in rj)
    check("R-Judge C1 steps", cls.get("C1"), 5)


# -------------------------------------------------------------- campaign ---

def campaign():
    archive = os.path.join(DATA, "denials")
    if not os.path.isdir(archive):
        FAIL.append(("campaign archive exists", "MISSING", "672 sessions"))
        return
    dirs = [d for d in os.listdir(archive)
            if os.path.isdir(os.path.join(archive, d))]
    check("campaign session directories", len(dirs), 661)
    recorded = 0
    for d in dirs:
        p = os.path.join(archive, d, "events.jsonl")
        try:
            if os.path.getsize(p) > 10:
                recorded += 1
        except OSError:
            pass
    check("campaign recorded sessions (analysis denominator)", recorded, 644)

    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import responses
    except ImportError as exc:
        FAIL.append(("responses.py imports", str(exc), "ok"))
        return
    rows = responses.denials_in(archive)
    check("denial events", len(rows), 424)
    counts = collections.Counter(r["response"] for r in rows)
    for key, want in responses.EXPECTED.items():
        check("post-denial %s" % key, counts.get(key, 0), want)

    onset = responses.onset_facts(archive)
    check("per-ordinal runs (responses.py --timing)", onset["sessions"], 723)
    check("per-ordinal runs reaching a denial", onset["reached"], 235)
    check("denial-onset quartiles, Claude corpus",
          (onset["p25"], onset["median"], onset["p75"], onset["max"]),
          (2, 4, 8, 48))



BLAST_ROWS = {
    "denials": (661, 11),
    "denials-defer-supp": (51, 76),
    "denials-explain-supp": (67, 38),
    "denials-full-supp": (50, 73),
    "denials-padded": (119, 4),
}

BLAST_TREE_FLOOR = 10666


def _blast_radius_control():
    """POSITIVE CONTROL for the quarantine membership and the tree-wide floor."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import archive as archive_mod
    except ImportError as exc:
        FAIL.append(("positive control: archive.py imports", str(exc), "ok"))
        return
    tmp = tempfile.mkdtemp(prefix="blast-control-")
    old = archive_mod.DATA
    try:
        for rel in ("denials-hit/s1", "denials-hit/s2", "denials-hit/s3",
                    "denials-hit.unhooked/q1", "denials-hit.unhooked/q2",
                    "denials-clean/s1"):
            os.makedirs(os.path.join(tmp, rel))
        archive_mod.DATA = tmp
        rows, affected, (total_g, total_u) = archive_mod.unhooked_counts()
    finally:
        archive_mod.DATA = old
        shutil.rmtree(tmp, ignore_errors=True)
    check("positive control: only an archive with a quarantine directory is "
          "in the affected set",
          sorted(label for label, _g, _q in affected), ["denials-hit"])
    check("positive control: the guarded and quarantined columns are "
          "counted apart", (total_g, total_u), (4, 2))
    check("positive control: a .unhooked directory is not an archive of its "
          "own", sorted(label for label, _g, _q in rows),
          ["denials-clean", "denials-hit"])


def blast_radius():
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import archive as archive_mod
    except ImportError as exc:
        FAIL.append(("archive.py imports", str(exc), "ok"))
        return
    rows, affected, (total_g, total_u) = archive_mod.unhooked_counts()
    by_label = dict((label, (g, q)) for label, g, q in rows)

    for label in sorted(BLAST_ROWS):
        want = BLAST_ROWS[label]
        got = by_label.get(label)
        check("blast radius %s (guarded, quarantined)" % label, got, want)

    # The membership of the affected set, not just its size: a sixth archive
    # acquiring an `.unhooked/` directory is a new guard-down window and must
    # not be absorbed into a total that still reads 202.
    check("blast radius: which archives were quarantined",
          sorted(label for label, _g, _q in affected), sorted(BLAST_ROWS))
    check("blast radius: those five, guarded",
          sum(g for _l, g, _q in affected), 948)
    check("blast radius: those five, quarantined",
          sum(q for _l, _g, q in affected), 202)
    check("blast radius: quarantined tree-wide", total_u, 202)

    if total_g >= BLAST_TREE_FLOOR:
        PASS.append(("blast radius: guarded tree-wide",
                     "%d (>= floor %d; grows while a run collects)"
                     % (total_g, BLAST_TREE_FLOOR)))
    else:
        FAIL.append(("blast radius: guarded tree-wide",
                     "%d, BELOW floor" % total_g,
                     ">= %d" % BLAST_TREE_FLOOR))

    # The caption's reason for not quoting that total: most of it is not data.
    # This archive is closed, so it is exact.
    check("blast radius: denials-opus-max is mostly not data",
          by_label.get("denials-opus-max", (0, 0))[0], 7291)


def _family_coverage_control():
    """POSITIVE CONTROL for the three coverage counts. Both directions."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import ablation
    except ImportError as exc:
        FAIL.append(("positive control: ablation.py imports", str(exc), "ok"))
        return
    tmp = tempfile.mkdtemp(prefix="famcov-control-")
    old = ablation.DATA
    try:
        data = os.path.join(tmp, "paper", "data")
        for archive, fams in (("denials-terse", ("fam.a", "fam.b")),
                              ("denials-terse-supp", ("fam.b", "fam.c"))):
            for fam in fams:
                os.makedirs(os.path.join(data, archive, "%s-v1" % fam))
        tasks = os.path.join(tmp, "paper", "scripts", "denials", "tasks.tsv")
        os.makedirs(os.path.dirname(tasks))
        with io.open(tasks, "w", encoding="utf-8") as fh:
            fh.write(u"family\tprompt\n")
            for fam in ("fam.a", "fam.b", "fam.c", "fam.d"):
                fh.write(u"%s\tirrelevant\n" % fam)
        ablation.DATA = data
        f = ablation.coverage_facts()
    finally:
        ablation.DATA = old
        shutil.rmtree(tmp, ignore_errors=True)
    check("positive control: family coverage counts the arms it walked",
          (f["corpus"], f["main"], f["added"], f["reached"]), (4, 2, 1, 3))
    check("positive control: a supplement family the main arms reached is "
          "not counted as added", f["added"] < len(("fam.b", "fam.c")), True)
    check("positive control: an unreached family is named, not just counted",
          f["missing"], ["fam.d"])


def family_coverage():
    """§app:repro's "17 of 20", and the three families named as unreached."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import ablation
    except ImportError as exc:
        FAIL.append(("ablation.py imports", str(exc), "ok"))
        return
    f = ablation.coverage_facts()
    check("ablation family denominator (tasks.tsv)", f["corpus"], 20)
    check("ablation families reached by the main arms", f["main"], 10)
    check("ablation families added by the supplement", f["added"], 7)
    check("ablation campaign family coverage", f["reached"], 17)
    # NAMED, not counted. The draft this replaced said 18 of 20 AND named a
    # family that had in fact been reached; a count alone would have caught
    # only the first error, and both pointed the way that flatters the design.
    check("ablation families no arm reached", f["missing"],
          ["fs.system_write", "proc.unbounded", "sql.destructive"])


def stopping_durations():
    """tab:models's Stopped column: behaviour, or a session killed at the cap?"""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import models
    except ImportError as exc:
        FAIL.append(("models.py imports", str(exc), "ok"))
        return
    f = models.stopping_facts()
    check("stopping: model arms read", f["arms"], 3)
    check("stopping events across the three arms", f["events"], 35)
    check("stopping sessions with a duration", f["sessions"], 35)
    check("stopping: median seconds", int(round(f["median"] or -1)), 69)
    check("stopping: longest seconds", int(round(f["max"] or -1)), 154)
    check("stopping: sessions NOT ending normally", f["abnormal"], 0)


def paper_table_matches_emitter():
    """tab:models as PRINTED IN main.tex, against what models.py computes."""
    import re as _re
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import models as _models
    except Exception as exc:                       # pragma: no cover
        FAIL.append(("tab:models emitter imports", str(exc)[:60], "ok"))
        return

    tex = io.open(os.path.join(REPO, "paper", "main.tex"),
                  encoding="utf-8").read()
    after = tex.split("\\label{tab:models}")[1]
    block = after.split("\\end{tabular}")[0]
    rows = {}
    for name in ("Haiku", "Opus", "Sonnet"):
        m = _re.search(
            r"\n%s\s*&\s*(\d+)\s*&\s*(\d+)\s*&[^&]*?([0-9.]+)\\%%[^&]*&"
            r"[^&]*?([0-9.]+)\\%%[^&]*&[^&]*?([0-9.]+)\\%%" % name, block)
        if m:
            rows[name.lower()] = tuple(m.groups())
    if len(rows) != 3:
        FAIL.append(("tab:models parsed from main.tex",
                     "%d of 3 rows" % len(rows), "3 rows"))
        return

    for label, archive in _models.ARMS:
        evs, sess = _models.arm_rows(archive)
        if evs is None:
            SKIP.append(("tab:models %s vs emitter" % label,
                         "archive %s absent" % archive, SKIP_ABSENT))
            continue
        got = rows.get(label)
        if got is None:
            FAIL.append(("tab:models has a row for %s" % label,
                         "missing", "present"))
            continue
        n = len(evs)
        share = lambda k: round(100.0 * k / n, 1) if n else -1.0
        counts = collections.Counter(r["response"] for r in evs)
        want = (str(sess), str(n),
                "%.1f" % share(counts.get("Overrode", 0)),
                "%.1f" % share(counts.get("Rewrote", 0)),
                "%.1f" % share(counts.get("EndOfRun", 0)))
        if tuple(got) == want:
            PASS.append(("tab:models %s row matches the emitter" % label,
                         "sessions %s, events %s, %s%%/%s%%/%s%%" % want))
        else:
             FAIL.append(("tab:models %s row matches the emitter" % label,
                         "main.tex %s" % (tuple(got),),
                         "emitter %s" % (want,)))



_MAIN_TEX = {}


def _main_tex():
    """main.tex, read once. Absence is the caller's failure to report."""
    if "text" not in _MAIN_TEX:
        _MAIN_TEX["text"] = io.open(
            os.path.join(REPO, "paper", "main.tex"), encoding="utf-8").read()
    return _MAIN_TEX["text"]


def _tex_cell(s):
    """One LaTeX cell as the reader sees it: markup off, digits intact."""
    s = s.strip()
    for macro in ("textbf", "emph", "textit", "texttt", "mathit"):
        for _ in range(2):                      # one nesting level is enough
            s = re.sub(r"\\%s\{([^{}]*)\}" % macro, r"\1", s)
    s = s.replace("{,}", "").replace("\\%", "%").replace("$", "")
    s = s.replace("\\_", "_").replace("-{}-", "--").replace("\\,", " ")
    s = s.replace("\\rightarrow", "->").replace("\\geq", ">=")
    return re.sub(r"\s+", " ", s).strip()


def _tex_rows(tabular):
    """[[cell, ...], ...] for one tabular body, rules and comments dropped."""
    out = []
    for line in tabular.split("\\\\"):
        line = re.sub(r"(?m)^\s*%.*$", "", line).strip()
        line = re.sub(r"\\(?:toprule|midrule|bottomrule|hline)", "", line)
        if "&" not in line:
            continue
        out.append([_tex_cell(c) for c in line.split("&")])
    return out


def _tex_table(label, nth=0):
    """Rows of the tabular that follows `\\label{<label>}`, keyed by column 0."""
    tex = _main_tex()
    marker = "\\label{%s}" % label
    if marker not in tex:
        return None, None
    after = tex.split(marker, 1)[1]
    parts = after.split("\\begin{tabular}")
    if len(parts) < nth + 2:
        return None, None
    body = parts[nth + 1].split("\\end{tabular}", 1)[0]
    rows = _tex_rows(body)
    return dict((r[0], tuple(r[1:])) for r in rows), rows


def _cmp(name, tex_row, emitted):
    """One published row against one recomputed row."""
    if tex_row is None:
        FAIL.append((name, "no such row in main.tex", "emitter %s" % (emitted,)))
    elif tuple(tex_row[:len(emitted)]) == tuple(emitted):
        PASS.append((name, " | ".join(str(x) for x in emitted)))
    else:
        FAIL.append((name, "main.tex %s" % (tuple(tex_row[:len(emitted)]),),
                     "emitter %s" % (tuple(emitted),)))


def _stats_wilson():
    """`stats.wilson`, WHICH IS NOT `_wilson` FURTHER DOWN THIS FILE."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    from stats import wilson
    return wilson


def _pct(k, n, places=1):
    return "%.*f%%" % (places, 100.0 * k / n) if n else "---"


def _ci(k, n, places=1):
    lo, hi = _stats_wilson()(k, n)
    return "[%.*f, %.*f]" % (places, 100 * lo, places, 100 * hi)


def _no_tex(label, names):
    """The table itself is gone from main.tex. Loud, and not a corpus excuse."""
    for name in names:
        FAIL.append((name, "%s is not in main.tex" % label, "the table"))



PAPER_GENERATED_TABLES = {
    "tab:space": "tab-action-space.tex",
    "tab:app-effort": "tab-app-effort.tex",
    "tab:crossvendor": "tab-crossvendor.tex",
    "tab:residual": "tab-residual.tex",
    "tab:ablation": "tab-ablation.tex",
    "tab:comp": "tab-composition.tex",
}

PAPER_HAND_TABLES = {
    "tab:after": "paper_tab_after",
    "tab:app-families": "paper_tab_app_families",
    "tab:app-ordinal": "paper_tab_app_ordinal",
    "tab:app-machinewrites": "paper_tab_app_machinewrites",
    "tab:app-artifacts": "paper_tab_app_artifacts",
    "tab:app-verbs": "paper_tab_app_verbs",
    "tab:app-composition": "paper_tab_app_composition",
    "tab:app-dedup": "paper_tab_app_dedup",
    "tab:app-filetype": "paper_tab_app_filetype",
    "tab:app-latency": "paper_tab_app_latency",
    "tab:app-blastradius": "paper_tab_app_blastradius",
    "tab:app-runa": "paper_tab_app_runa",
    "tab:models": "paper_table_matches_emitter",
    "tab:pilot": "paper_tab_pilot",
    "tab:related": "paper_tab_related",
    "float after app:placebo": "paper_tab_placebo",
}


def _paper_floats():
    """Every table in main.tex as (identity, kind, generated file or None)."""
    tex = _main_tex()
    out, spans = [], []
    for m in re.finditer(r"\\begin\{(table\*?)\}", tex):
        end = tex.find("\\end{%s}" % m.group(1), m.start())
        end = len(tex) if end < 0 else end + len("\\end{%s}" % m.group(1))
        spans.append((m.start(), end))
        block = tex[m.start():end]
        lab = re.search(r"\\label\{(tab:[^}]*)\}", block)
        gen = re.search(r"\\input\{figures/(tab-[^}]*)\}", block)
        out.append((lab.group(1) if lab else "(unlabelled table environment)",
                    "generated" if gen else "hand",
                    gen.group(1) + ".tex" if gen else None))
    for m in re.finditer(r"\\begin\{tabular\}", tex):
        if any(a <= m.start() < b for a, b in spans):
            continue
        labs = re.findall(r"\\label\{([^}]*)\}", tex[:m.start()])
        out.append(("float after %s" % (labs[-1] if labs else "?"),
                    "hand", None))
    return out


def _unchecked_generated(generated, corpus):
    """Labels whose emitted file is not one `tables.py --check` compares."""
    return sorted(label for label, filename in generated.items()
                  if filename not in corpus)


def _generated_registry_control():
    """POSITIVE CONTROL for the six rows above. Both directions."""
    check("positive control: a generated table missing from tables.py "
          "--check is named",
          _unchecked_generated({"tab:x": "tab-x.tex", "tab:y": "tab-y.tex"},
                               {"tab-y.tex": ("campaign",)}), ["tab:x"])
    check("positive control: a generated table under tables.py --check is "
          "not named",
          _unchecked_generated({"tab:x": "tab-x.tex", "tab:y": "tab-y.tex"},
                               {"tab-x.tex": (), "tab-y.tex": ()}), [])


def paper_table_inventory():
    """Every table in main.tex is either generated-and-checked or gated here."""
    floats = _paper_floats()
    gen = sorted(f[0] for f in floats if f[1] == "generated")
    hand = sorted(f[0] for f in floats if f[1] == "hand")
    check("paper tables, total", len(floats), 22)
    check("paper tables generated and \\input{} from figures",
          gen, sorted(PAPER_GENERATED_TABLES))
    check("paper tables typed into main.tex by hand",
          hand, sorted(PAPER_HAND_TABLES))
    # Each generated table's file must be one `tables.py --check` compares
    # against its generator, or "generated" above is an unearned reassurance.
    unchecked = _unchecked_generated(PAPER_GENERATED_TABLES, TABLE_CORPUS)
    for label, _filename in sorted(PAPER_GENERATED_TABLES.items()):
        check("%s's generated file is under tables.py --check" % label,
              label not in unchecked, True)
    # And the emitted file main.tex actually \input{}s is the one registered.
    for label, _kind, filename in floats:
        if filename is None:
            continue
        check("%s \\input{}s the file it is registered under" % label,
              filename, PAPER_GENERATED_TABLES.get(label))


# ---------------------------------------------- the campaign's three -------

def paper_tab_after():
    """tab:after, the post-denial distribution, against responses.py."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import responses
    rows = responses.denials_in(os.path.join(DATA, "denials"))
    n = len(rows)
    counts = collections.Counter(r["response"] for r in rows)
    tex, _ = _tex_table("tab:after")
    labels = [("Overrode the block", "Overrode"),
              ("Rewrote the command", "Rewrote"),
              ("Was blocked again", "BlockedAgain"),
              ("Run ended", "EndOfRun"),
              ("Abandoned the attempt", "Abandoned"),
              ("Retried the identical command", "RetriedIdentical")]
    if tex is None:
        _no_tex("tab:after", ["tab:after %s row" % l for l, _k in labels])
        return
    for label, key in labels:
        k = counts.get(key, 0)
        _cmp("tab:after %s row" % label, tex.get(label),
             (str(k), _pct(k, n), _ci(k, n)))
    # The caption's denominators, which are numbers a reader reads too.
    caption = _main_tex().split("\\label{tab:after}")[0].rsplit(
        "\\begin{table}", 1)[1]
    check("tab:after caption denial events",
          bool(re.search(r"over %d denial events" % n, caption)), True)
    check("tab:after caption denial sessions",
          bool(re.search(r"\(\$%d\$ denial sessions\)"
                         % len(set(r["session"] for r in rows)), caption)),
          True)


def paper_tab_app_families():
    """tab:app-families, all twenty rules plus the total, against responses.py."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import responses
    archive = os.path.join(DATA, "denials")
    rows = responses.denials_in(archive)
    chances = collections.Counter()
    # Per-FAMILY session counts. Well defined, and deliberately NOT joined to
    # a rule name any more - see the note at the row comparison below.
    for session, _path in responses.session_files(archive):
        family, _variant = responses.family_variant(session)
        if family:
            chances[family] += 1
    by = collections.defaultdict(list)
    for r in rows:
        by[r["rule"]].append(r)

    tex, _ = _tex_table("tab:app-families")
    if tex is None:
        _no_tex("tab:app-families", ["tab:app-families rows"])
        return
    check("tab:app-families lists every rule that fired",
          sorted(k for k in tex if "." in k), sorted(by))
    for rule, rs in sorted(by.items()):
        k = sum(1 for r in rs if r["response"] == "Overrode")
        _cmp("tab:app-families %s row" % rule, tex.get(rule),
             (str(len(rs)), _pct(k, len(rs)), _ci(k, len(rs)),
              str(len(set(r["session"] for r in rs)))))
    n = len(rows)
    k = sum(1 for r in rows if r["response"] == "Overrode")
    _cmp("tab:app-families total row", tex.get("All denial events"),
         (str(n), _pct(k, n), _ci(k, n)))


def paper_tab_app_ordinal():
    """tab:app-ordinal, three responses by three ordinal buckets."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import responses
    rows = responses.denials_in(os.path.join(DATA, "denials"))
    buckets = dict((k, [r for r in rows
                        if (r["ordinal"] == k if k < 3 else r["ordinal"] >= 3)])
                   for k in (1, 2, 3))
    tex, ordered = _tex_table("tab:app-ordinal")
    names = ["tab:app-ordinal denominators"] + [
        "tab:app-ordinal %s row" % l for l in
        ("Overrode", "Rewrote", "Blocked again")]
    if tex is None:
        _no_tex("tab:app-ordinal", names)
        return
    got = tuple("(n=%d)" % len(buckets[k]) for k in (1, 2, 3))
    row = next((r[1:4] for r in ordered
                if len(r) > 3 and all(re.match(r"^\(n=\d+\)$", c)
                                      for c in r[1:4])), None)
    _cmp("tab:app-ordinal denominators", row, got)
    for label, key in (("Overrode", "Overrode"), ("Rewrote", "Rewrote"),
                       ("Blocked again", "BlockedAgain")):
        cells = []
        for k in (1, 2, 3):
            sel = buckets[k]
            hit = sum(1 for r in sel if r["response"] == key)
            cells.append("%s %s" % (_pct(hit, len(sel)), _ci(hit, len(sel))))
        _cmp("tab:app-ordinal %s row" % label, tex.get(label), tuple(cells))


def paper_tab_app_machinewrites():
    """tab:app-machinewrites, against `machine_writes.py`'s own output."""
    script = os.path.join(REPO, "paper", "scripts", "analysis",
                          "machine_writes.py")
    proc = subprocess.Popen([sys.executable, script], cwd=REPO,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    out = out.decode("utf-8", "replace")
    pattern = re.compile(r"^(\S+)\s+.*?(\d+)\s+(\d+)\s+(\d+)\s+"
                         r"([0-9.]+)%\s+\[\s*([0-9.]+),\s*([0-9.]+)\]"
                         r"\s+(\S.*?)\s*$")
    emitted = {}
    for line in out.splitlines():
        m = pattern.match(line)
        if m:
            emitted[m.group(1)] = m.groups()[1:]

    # tab:app-machinewrites's row label -> machine_writes.py's category key.
    rowmap = [("Write/Edit into the real home", "direct_write"),
              ("git config outside the repo", "global_git"),
              ("Startup folders and Run keys", "autostart"),
              ("Scheduled tasks, cron, launch agents", "scheduler"),
              ("Persistent environment variables", "env_persist"),
              ("Shell startup files", "login_profile"),
              ("Shared package roots", "global_install"),
              ("Any category", "ANY")]
    names = ["tab:app-machinewrites %s row" % l for l, _k in rowmap]
    tex, _ = _tex_table("tab:app-machinewrites")
    if tex is None:
        _no_tex("tab:app-machinewrites", names)
        return
    if proc.returncode != 0 or len(emitted) != len(rowmap):
        for name in names:
            FAIL.append((name,
                         "machine_writes.py exit %d, %d of %d rows parsed"
                         % (proc.returncode, len(emitted), len(rowmap)),
                         "the emitter's table, all rows"))
        return

    def verdicts_tex(s):
        out = {}
        for part in s.split(","):
            m = re.match(r"\s*(\d+)\s+(.+?)\s*$", part)
            if m:
                out[m.group(2)] = int(m.group(1))
        return out

    def verdicts_emitted(s):
        out = {}
        for part in s.split(","):
            m = re.match(r"\s*(.+?)\s+(\d+)\s*$", part)
            if m:
                key = m.group(1).strip()
                out["unmatched" if key == "no rule matched" else key] = \
                    int(m.group(2))
        return out

    for label, key in rowmap:
        attempted, sess, _ment, share, lo, hi, verdicts = emitted[key]
        want = (attempted, sess, "%s%% [%s, %s]" % (share, lo, hi))
        row = tex.get(label)
        name = "tab:app-machinewrites %s row" % label
        if row is None:
            FAIL.append((name, "no such row in main.tex", "emitter %s" % (want,)))
            continue
        got_v, want_v = verdicts_tex(row[3]), verdicts_emitted(verdicts)
        if tuple(row[:3]) == want and got_v == want_v:
            PASS.append((name, " | ".join(want) + " | " + row[3]))
        else:
            FAIL.append((name, "main.tex %s %s" % (tuple(row[:3]), got_v),
                         "emitter %s %s" % (want, want_v)))


def paper_tab_app_blastradius():
    """tab:app-blastradius, against `archive.py --unhooked`."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import archive as archive_mod
    rows, affected, _totals = archive_mod.unhooked_counts()
    by_label = dict((label, (g, q)) for label, g, q in rows)
    rowmap = [("denials-defer-supp", "denials-defer-supp"),
              ("denials-full-supp", "denials-full-supp"),
              ("denials-explain-supp", "denials-explain-supp"),
              ("denials-padded", "denials-padded"),
              ("denials (main)", "denials")]
    names = ["tab:app-blastradius %s row" % l for l, _k in rowmap] + [
        "tab:app-blastradius total row"]
    tex, _ = _tex_table("tab:app-blastradius")
    if tex is None:
        _no_tex("tab:app-blastradius", names)
        return
    for label, key in rowmap:
        got = by_label.get(key)
        _cmp("tab:app-blastradius %s row" % label, tex.get(label),
             (str(got[0]), str(got[1])) if got else ("MISSING", "MISSING"))
    _cmp("tab:app-blastradius total row", tex.get("Those five"),
         (str(sum(g for _l, g, _q in affected)),
          str(sum(q for _l, _g, q in affected))))


# ---------------------------------------------------- the ATBench two ------

def paper_tab_app_verbs():
    """tab:app-verbs, the verb-table sensitivity envelope."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import taxonomy_robustness as tr
    rows = tr.load("atbench-violations.jsonl")
    tex, _ = _tex_table("tab:app-verbs")
    verbs = [v for v in ("create", "send", "update")]
    names = (["tab:app-verbs as-published row"]
             + ["tab:app-verbs %s row" % v for v in verbs]
             + ["tab:app-verbs union row"])
    if tex is None:
        _no_tex("tab:app-verbs", names)
        return
    base_c1, steps, base_tr, trajs = tr.rates(rows)
    _cmp("tab:app-verbs as-published row", tex.get("as published"),
         ("---", "%.2f%%" % (100.0 * base_c1 / steps),
          "%.2f%%" % (100.0 * base_tr / trajs)))
    counts = collections.Counter(r.get("machine_signature") for r in rows
                                 if r.get("machine_class") == "C2")
    for verb in verbs:
        c1, st, tr_c1, tt = tr.rates(rows, {verb})
        _cmp("tab:app-verbs %s row" % verb, tex.get(verb),
             (str(counts.get(verb, 0)), "%.2f%%" % (100.0 * c1 / st),
              "%.2f%%" % (100.0 * tr_c1 / tt)))
    all_c1, st, all_tr, tt = tr.rates(rows, set(tr.ARGUABLE))
    union = sum(1 for r in rows if r.get("machine_class") == "C2"
                and r.get("machine_signature") in set(tr.ARGUABLE))
    # "All 16 arguable verbs" names its own arity, so the roster is checked
    # too: adding a seventeenth verb to ARGUABLE moves the union and leaves
    # the label saying sixteen.
    check("tab:app-verbs union row says how many verbs ARGUABLE holds",
          "All %d arguable verbs" % len(tr.ARGUABLE) in tex, True)
    _cmp("tab:app-verbs union row",
         tex.get("All %d arguable verbs" % len(tr.ARGUABLE)),
         (str(union), "%.2f%%" % (100.0 * all_c1 / st),
          "%.2f%%" % (100.0 * all_tr / tt)))


_FACTOR_WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five",
                 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten"}


def _caption_factor_claims(flat, ratios):
    """Every "factor of N" in a caption that no row of its table exhibits."""
    bad = []
    for c in re.findall(r"factor of (\w+)", flat):
        try:
            want = float(c)
        except ValueError:
            want = next((k for k, v in _FACTOR_WORDS.items()
                         if v == c.lower()), None)
        if want is None:
            bad.append(("unparseable", c))
            continue
        if not any(abs(r - want) < 0.5 for r in ratios.values()):
            bad.append((c, "no row within 0.5 of it; rows are %s"
                        % ", ".join("%s %.2fx" % (n, r)
                                    for n, r in sorted(ratios.items()))))
    return bad


def _caption_factor_control():
    """POSITIVE CONTROL for the row above. Both directions."""
    rows = {"R-Judge": 1.84, "StepShield": 1.00}
    check("positive control: a caption factor no row exhibits is named",
          [c for c, _why in _caption_factor_claims(
              "the two levels differ by a factor of four", rows)], ["four"])
    check("positive control: a caption factor a row does exhibit is allowed",
          _caption_factor_claims("they differ by a factor of 2", rows), [])
    check("positive control: an unparseable factor claim is not a satisfied "
          "one",
          [c for c, _why in _caption_factor_claims(
              "they differ by a factor of several", rows)], ["unparseable"])


def paper_tab_comp_caption():
    """tab:comp's caption, against the rows it justifies the table with."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import taxonomy_robustness as tr
    text = _main_tex()
    if "\\label{tab:comp}" not in text:
        FAIL.append(("tab:comp caption: the table is in main.tex",
                     "absent", "the table"))
        return
    caption = text.split("\\label{tab:comp}")[0].rsplit(
        "\\begin{table}", 1)[1]
    flat = re.sub(r"\s+", " ", caption)
    rates = tr.step_and_trajectory_rates()
    ratios = {}
    for name, sn, sk, tn, tk in rates:
        if not sn or not tn or not sk:
            continue
        ratios[name] = (100.0 * tk / tn) / (100.0 * sk / sn)
    check("tab:comp caption: every ratio it claims is a ratio of its own rows",
          _caption_factor_claims(flat, ratios), [])
    # The row that CAN differ must be the one quoted, with both its levels.
    for name, sn, sk, tn, tk in rates:
        if not sn or not tn or not sk or sn == tn:
            continue
        check("tab:comp caption quotes %s's two levels" % name,
              ("%.2f\\%%" % (100.0 * tk / tn)) in flat
              and ("%.2f\\%%" % (100.0 * sk / sn)) in flat, True)


def paper_tab_app_composition():
    """tab:app-composition, the three ATBench sub-corpora and their pool."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import taxonomy_robustness as tr
    rows = tr.load("atbench-violations.jsonl")
    tex, _ = _tex_table("tab:app-composition")
    rowmap = [("ATBench", "ATBench"), ("ATBench-Claw", "ATBench-Claw"),
              ("ATBench-Codex", "ATBench-Codex"), ("Pooled", None)]
    if tex is None:
        _no_tex("tab:app-composition",
                ["tab:app-composition %s row" % l for l, _c in rowmap])
        return
    # The three named sub-corpora are the whole of the corpus, which is what
    # licenses the Pooled row being their sum rather than a fourth population.
    seen = collections.Counter(r.get("category") for r in rows)
    check("tab:app-composition rows cover every ATBench category",
          sorted(seen), sorted(c for _l, c in rowmap if c))
    for label, category in rowmap:
        sub = rows if category is None else [r for r in rows
                                             if r.get("category") == category]
        c1, steps, tr_c1, trajs = tr.rates(sub)
        _cmp("tab:app-composition %s row" % label, tex.get(label),
             (str(steps), str(c1), "%.2f%%" % (100.0 * c1 / steps),
              str(trajs), str(tr_c1), "%.2f%%" % (100.0 * tr_c1 / trajs)))


# ------------------------------------------------- the statement corpora ---

def paper_tab_app_dedup():
    """tab:app-dedup, three corpora and their pool, against dedup_statements."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import dedup_statements
    rowmap = [("This paper", "policy-statements.jsonl", "policy"),
              ("AIWare", "aiware-statements.jsonl", "aiware"),
              ("Agent READMEs", "readmes-statements.jsonl", "readmes")]
    tex, _ = _tex_table("tab:app-dedup")
    names = ["tab:app-dedup %s row" % l for l, _f, _k in rowmap] + [
        "tab:app-dedup pooled row"]
    if tex is None:
        _no_tex("tab:app-dedup", names)
        return
    total_n = total_kept = 0
    complete = True
    for label, filename, key in rowmap:
        if not present(key):
            SKIP.append(("tab:app-dedup %s row" % label,
                         _no_corpus([key]), SKIP_ABSENT))
            complete = False
            continue
        rows = dedup_statements.load(filename)
        kept = dedup_statements.exact_pass(rows)
        total_n += len(rows)
        total_kept += len(kept)
        before, after = dedup_statements.shares(rows), dedup_statements.shares(kept)
        _cmp("tab:app-dedup %s row" % label, tex.get(label),
             (str(len(rows)), str(len(kept)),
              _pct(len(rows) - len(kept), len(rows)),
              "%.2f%% %s" % (before["c1_share"], _ci(before["C1"], before["n"], 2)),
              "%.2f%% %s" % (after["c1_share"], _ci(after["C1"], after["n"], 2))))
    if not complete:
        SKIP.append(("tab:app-dedup pooled row",
                     "the pooled row needs all three statement corpora",
                     SKIP_ABSENT))
        return
    _cmp("tab:app-dedup pooled row", tex.get("Pooled"),
         (str(total_n), str(total_kept),
          _pct(total_n - total_kept, total_n), "---", "---"))


def paper_tab_app_filetype():
    """tab:app-filetype, six instruction-file formats over the AIWare corpus."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import dedup_statements
    # The table's own spelling of each filename `FILETYPE_ROWS` lowercases.
    labels = {"agents.md": "AGENTS.md",
              "copilot-instructions.md": "copilot-instructions.md",
              "skill.md": "SKILL.md",
              "claude.md": "CLAUDE.md",
              ".cursorrules": ".cursorrules",
              "github-actions-ci-cd-best-practices.instructions.md":
                  "CI/CD best-practice instructions"}
    tex, _ = _tex_table("tab:app-filetype")
    names = ["tab:app-filetype %s row" % labels.get(k, k)
             for k in dedup_statements.FILETYPE_ROWS]
    if tex is None:
        _no_tex("tab:app-filetype", names)
        return
    check("tab:app-filetype covers every row the emitter prints",
          sorted(labels), sorted(dedup_statements.FILETYPE_ROWS))
    facts, corpus_n = dedup_statements.by_file_facts("aiware-statements.jsonl")
    named = 0
    by_key = {}
    for f in facts:
        key = f["key"]
        n = f["n"]
        named += n
        by_key[key] = f
        cell_n = ("%d^{\\dagger}" % n) if f.get("replication") else str(n)
        _cmp("tab:app-filetype %s row" % labels.get(key, key),
             tex.get(labels.get(key, key)),
             (cell_n, _pct(f.get("k", 0), n, 2),
              _ci(f.get("ci_k", 0), f.get("ci_n", n), 2)))
    # THE CAPTION'S TWO DENOMINATORS. The rows are a subset and the caption has
    # to carry both numbers or it contradicts its own rows - which is the fault
    # `by_file_report`'s docstring was written about.
    caption = _main_tex().split("\\label{tab:app-filetype}")[0].rsplit(
        "\\begin{table}", 1)[1].replace("{,}", "")
    check("tab:app-filetype caption: the rows' own denominator",
          bool(re.search(r"sum to \$%d\$" % named, caption)), True)
    check("tab:app-filetype caption: the corpus it is drawn from",
          bool(re.search(r"\$%d\$ statements" % corpus_n, caption)), True)
    check("tab:app-filetype caption: the long tail",
          bool(re.search(r"other \$%d\$ sit in a tail" % (corpus_n - named),
                         caption)), True)

    # ---- THE GENERALISATION, against the rows it generalises over.
    wilson = _stats_wilson()
    live = [f for f in facts if f["n"]]
    biggest = max(live, key=lambda f: f["n"])
    b_lo, b_hi = wilson(biggest["ci_k"], biggest["ci_n"])
    flat, outliers = [], []
    for f in live:
        lo, hi = wilson(f["ci_k"], f["ci_n"])
        (flat if (lo <= b_hi and hi >= b_lo) else outliers).append(f)
    check("tab:app-filetype caption: flatness is claimed over the rows it "
          "holds for",
          bool(re.search(r"[Tt]he %s largest formats are flat"
                         % {2: "two", 3: "three", 4: "four", 5: "five",
                            6: "six"}.get(len(flat), str(len(flat))),
                         caption)), True)
    for f in outliers:
        label = labels.get(f["key"], f["key"])
        stem = label.replace("\\", "").split("/")[0]
        check("tab:app-filetype caption names the disjoint row %s" % label,
              stem.lower().lstrip(".") in caption.lower().replace("\\", ""),
              True)
    # A replicated row's caption must say what its interval is over, because
    # the table's own denominator column says something else.
    for f in live:
        if not f.get("replication"):
            continue
        check("tab:app-filetype caption states the CI denominator for %s"
              % labels.get(f["key"], f["key"]),
              bool(re.search(r"\$%d\$ distinct" % f["distinct_n"], caption)),
              True)


# ------------------------------------------------------------ the pilot ----

def paper_tab_pilot():
    """tab:pilot, the API pilot's five arms and its isolation row."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import pilot_contrasts as pcs
    rowmap = [("Terse", "terse"), ("Explain", "explain"), ("Padded", "padded"),
              ("Defer", "defer"), ("Full", "full")]
    names = ["tab:pilot %s row" % l for l, _a in rowmap] + [
        "tab:pilot arm-isolation row"]
    tex, _ = _tex_table("tab:pilot")
    if tex is None:
        _no_tex("tab:pilot", names)
        return
    # The census is a precondition here for the same reason it is in
    # `pilot_contrasts()`: without it the readers pool Run B into the pilot and
    # every cell below becomes a statement about the wrong 6,640 sessions.
    if pcs.baseline_census() is None:
        for name in names:
            FAIL.append((name, CENSUS_ABSENT, "the frozen 631-session census"))
        return
    m = pcs.measure(DATA)
    if m is None:
        for name in names:
            FAIL.append((name, "no pilot cells read", "160 cells"))
        return
    for label, arm in rowmap:
        t = m["by_arm"][arm]
        lo, hi = t["ci"]
        _cmp("tab:pilot %s row" % label, tex.get(label),
             (str(t["sessions"]), str(t["denying"]), str(t["refusals"]),
              str(t["overrides"]),
              "%s [%.1f, %.1f]" % (_pct(t["overrides"], t["refusals"]),
                                   100 * lo, 100 * hi)))
    non_full = [a for a in pcs.ARMS if a != "full"]
    _cmp("tab:pilot arm-isolation row",
         tex.get("Four arms without the affordance"),
         ("---", "---",
          str(sum(m["by_arm"][a]["refusals"] for a in non_full)),
          str(sum(m["by_arm"][a]["overrides"] for a in non_full)), "---"))


def paper_tab_placebo():
    """The decomposition in \\S\\ref{app:placebo}: the paper's 21st table."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import placebo
    tex = _main_tex()
    marker = "\\label{app:placebo}"
    names = ["placebo decomposition: %s" % l for l in
             ("terse -> explain, the headline", "terse -> padded, length alone",
              "padded -> explain, content alone")]
    if marker not in tex:
        _no_tex("app:placebo", names)
        return
    body = tex.split(marker, 1)[1]
    if "\\begin{tabular}" not in body:
        _no_tex("app:placebo's decomposition tabular", names)
        return
    body = body.split("\\begin{tabular}", 1)[1].split("\\end{tabular}", 1)[0]
    rows = dict((r[0], tuple(r[1:])) for r in _tex_rows(body))
    arms = placebo.arms()
    for label, lo_arm, hi_arm in (
            ("terse -> explain, the headline", "terse", "explain"),
            ("terse -> padded, length alone", "terse", "padded"),
            ("padded -> explain, content alone", "padded", "explain")):
        n1, k1 = arms[lo_arm]
        n2, k2 = arms[hi_arm]
        want = "%+.1f" % (100.0 * (k2 / float(n2) - k1 / float(n1)))
        _cmp("placebo decomposition: %s" % label, rows.get(label), (want,))




def _figure_text(name, gates):
    path = os.path.join(REPO, "paper", "figures", name)
    try:
        return io.open(path, encoding="utf-8").read()
    except (OSError, IOError):
        for gate in gates:
            FAIL.append((gate, "MISSING - paper/figures/%s is tracked" % name,
                         "the measurement record"))
        return None


def paper_tab_app_latency():
    """tab:app-latency, against `paper/figures/overhead.txt`."""
    rowmap = [("Allow: every rule evaluated, nothing matched", "Allow path"),
              ("Deny: rule matched, denial written", "Deny path"),
              ("No daemon configured (then: allowed)", "Process only"),
              ("Daemon configured but dead (then: allowed)",
               "Daemon configured but dead")]
    names = ["tab:app-latency %s row" % l for l, _p in rowmap]
    text = _figure_text("overhead.txt", names)
    if text is None:
        return
    tex, _ = _tex_table("tab:app-latency")
    if tex is None:
        _no_tex("tab:app-latency", names)
        return
    for label, prefix in rowmap:
        block = text.split(prefix, 1)
        name = "tab:app-latency %s row" % label
        if len(block) < 2:
            FAIL.append((name, "no %r block in overhead.txt" % prefix,
                         "the measured path"))
            continue
        block = block[1].split("\n\n", 1)[0]
        cells = []
        for stat in ("mean", "p50", "p95", "p99", "max"):
            m = re.search(r"\n\s+%s\s+([0-9.]+) ms" % stat, block)
            cells.append(m.group(1) if m else "?")
        over = re.search(r"over the 25ms budget: (\d+) of (\d+)", block)
        cells.append("%s/%s" % over.groups() if over else "?")
        _cmp(name, tex.get(label), tuple(cells))
    # The caption's own two figures: the iteration count and the budget.
    caption = _main_tex().split("\\label{tab:app-latency}")[0].rsplit(
        "\\begin{table}", 1)[1]
    iterations = set(re.findall(r"\(n=(\d+)\)", text))
    check("tab:app-latency caption: iterations per path",
          bool(iterations) and len(iterations) == 1
          and ("$%s$ iterations" % iterations.pop()) in caption, True)
    check("tab:app-latency caption: the budget it is measured against",
          bool(re.search(r"\$25\$\\,ms budget", caption))
          and "25ms budget" in text, True)


def paper_tab_related():
    """tab:related: the one cell in it that is ours, against its emitter."""
    names = ["tab:related: our benign denominator",
             "tab:related: the comparators carry no measurement of ours"]
    text = _figure_text("ceiling-full.txt", names)
    if text is None:
        return
    tex, rows = _tex_table("tab:related")
    if tex is None:
        _no_tex("tab:related", names)
        return
    m = re.search(r"(\d+) trajectories \((\d+) rogue, (\d+) benign\)", text)
    if not m:
        FAIL.append((names[0], "no trajectory census in ceiling-full.txt",
                     "'N trajectories (R rogue, B benign)'"))
    else:
        _cmp(names[0], tex.get("This work"),
             ("deterministic gate", "%s benign trajectories" % m.group(3)))
    # AND THE COMPARATOR ROWS ARE HELD AS CITATIONS, NOT AS RESULTS. Every one
    # of them must carry a \cite key, so a number for a competing system can
    # never appear in this table with nothing to check it against.
    uncited = [r[0] for r in rows[1:]
               if r[0] != "This work" and "\\cite{" not in r[0]]
    check(names[1], uncited, [])


# ------------------------------------------------------------- the rule mix --

def paper_rule_mix():
    """§app:models's standardization paragraph, against `rule_mix.py`."""
    names = ["app:models: decisions are denials, not denials plus overrides",
             "app:models: crude rates are the caption's stricter pairing",
             "app:models exposure shares",
             "app:models common strata",
             "app:models crude and standardized rates"]
    script = os.path.join(REPO, "paper", "scripts", "analysis", "rule_mix.py")
    proc = subprocess.Popen([sys.executable, script], cwd=REPO,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    text = out.decode("utf-8", "replace")
    if proc.returncode != 0:
        for name in names:
            FAIL.append((name, "rule_mix.py exit %d" % proc.returncode,
                         "exit 0"))
        return

    counts = dict((m.group(1), (m.group(2), m.group(3), m.group(4)))
                  for m in re.finditer(
                      r"^  (haiku|sonnet|opus)\s+(\d+)\s+(\d+)\s+(\d+\.\d)%\s"
                      r"*\[", text, re.M))
    std = dict((m.group(1), (m.group(2), m.group(3)))
               for m in re.finditer(
                   r"^  (haiku|sonnet|opus)\s+(\d+\.\d)%\s+(\d+\.\d)%\s+[-+]",
                   text, re.M))
    share = {}
    for line in text.splitlines():
        m = re.match(r"^  (\S+) \*?\s+(?=\d)", line)
        if m and re.search(r"\(n=\d+", line):
            share[m.group(1)] = re.findall(r"\(n=\d+\s+(\d+\.\d)%\)", line)
    strata = re.search(r"Common strata: \d+ of \d+ rules, (\d+) of \d+", text)
    if not (counts and std and share and strata):
        for name in names:
            FAIL.append((name, "rule_mix.py output not parsed", "five blocks"))
        return

    # JOINT 1: the denominator against tab:models, which counts denials.
    tex, _rows = _tex_table("tab:models")
    if tex is None:
        _no_tex("tab:models", names[:2])
    else:
        _cmp(names[0],
             tuple((tex.get(m.title()) or ("?", "?"))[1]
                   for m in ("haiku", "opus", "sonnet")),
             tuple(counts[m][0] for m in ("haiku", "opus", "sonnet")))
        # JOINT 2: the caption already publishes the correct three.
        caption = _main_tex().split("\\label{tab:models}")[0].rsplit(
            "\\begin{table}", 1)[1]
        pairing = re.search(r"stricter pairing gives \$(\d+\.\d)\\%\$, "
                            r"\$(\d+\.\d)\\%\$ and \$(\d+\.\d)\\%\$", caption)
        _cmp(names[1], pairing.groups() if pairing else None,
             tuple(counts[m][2] for m in ("haiku", "opus", "sonnet")))

    # AND THE PARAGRAPH, cell for cell. Left side parsed from main.tex.
    body = _main_tex().split("\\label{app:models}", 1)[-1].split(
        "\\paragraph{A second axis", 1)[0]
    exposure = re.search(
        r"force\\_push\} is\s*\$(\d+\.\d)\\%\$ of Haiku's decisions and "
        r"\$(\d+\.\d)\\%\$ of Sonnet's, while\s*\\texttt\{fs\.credential"
        r"\\_write\} is \$(\d+\.\d)\\%\$ of Sonnet's and \$(\d+\.\d)\\%\$ "
        r"of Haiku's", body)
    _cmp(names[2], exposure.groups() if exposure else None,
         (share["git.force_push"][0], share["git.force_push"][1],
          share["fs.credential_write"][1], share["fs.credential_write"][0]))
    printed = re.search(r"five times \(\$(\d+)\$\s*\n?decisions\)", body)
    _cmp(names[3], (printed.group(1),) if printed else None,
         (strata.group(1),))
    rates = re.search(
        r"Haiku \$(\d+\.\d)\\%\$ crude and \$(\d+\.\d)\\%\$\s*\n?standardized,"
        r" Opus \$(\d+\.\d)\\%\$ and \$(\d+\.\d)\\%\$, Sonnet \$(\d+\.\d)\\%\$"
        r" and \$(\d+\.\d)\\%\$", body)
    _cmp(names[4], rates.groups() if rates else None,
         (std["haiku"][0], std["haiku"][1], std["opus"][0], std["opus"][1],
          std["sonnet"][0], std["sonnet"][1]))


# --------------------------------------------- the stated classification rule --

def paper_rewrote_rule():
    """The rule §app:rewrote states "in full" against the rule that runs."""
    prose_name = {
        "Overrode": "\\emph{Overrode}",
        "Rewrote": "\\emph{Rewrote}",
        "BlockedAgain": "\\emph{Blocked again}",
        "EndOfRun": "\\emph{EndOfRun}",
        "Abandoned": "\\emph{Abandoned}",
        "RetriedIdentical": "\\emph{RetriedIdentical}",
    }
    names = ["app:rewrote: the declared spellings cover the classifier",
             "app:rewrote: Rust and Python agree on the outcome set"] + [
        "app:rewrote states the %s outcome" % k for k in sorted(prose_name)]

    src = io.open(os.path.join(REPO, "paper", "scripts", "analysis",
                               "responses.py"), encoding="utf-8").read()
    body = src.split("def classify_response(", 1)[-1].split("\ndef ", 1)[0]
    # Both return forms the function uses: the bare `return "X"` and the
    # ternary whose second arm is only reachable through `else`.
    outcomes = set(re.findall(r'\breturn "([A-Za-z]+)"', body))
    outcomes |= set(re.findall(r'\belse "([A-Za-z]+)"', body))
    check(names[0], sorted(outcomes), sorted(prose_name))

    rust_path = os.path.join(REPO, "crates", "sentinel-cli", "src",
                             "analyze.rs")
    if not os.path.exists(rust_path):
        SKIP.append((names[1], "crates/ is not shipped in a release tree",
                     SKIP_ABSENT))
    else:
        rust = io.open(rust_path, encoding="utf-8").read()
        enum = rust.split("pub enum Response {", 1)[-1].split("}", 1)[0]
        variants = sorted(re.findall(r"^\s{4}([A-Z][A-Za-z]+),\s*$", enum,
                                     re.M))
        check(names[1], variants, sorted(prose_name))

    # The subsection only. A name that happens to appear somewhere else in the
    # paper is not the rule being stated in full.
    tex = _main_tex()
    section = tex.split("\\label{app:rewrote}", 1)[-1].split(
        "\\subsection{", 1)[0]
    for key in sorted(prose_name):
        check("app:rewrote states the %s outcome" % key,
              prose_name[key] in section, True)


# ------------------------------------------------------- the operating point --

def paper_operating_point():
    """The base rate, and every number the paper derives from it."""
    names = ["operating point: base rate is the corpus's own",
             "operating point: recall over all rogue trajectories",
             "operating point: false-positive rate",
             "operating point: precision at the corpus base rate",
             "operating point: precision at a realistic 0.5%",
             "operating point: false alarms per catch at 0.5%",
             "operating point: body recall matches the emitter",
             "operating point: body precision matches the emitter",
             "operating point: appendix recall matches the emitter",
             "operating point: appendix base rate matches the emitter",
             "operating point: appendix precision matches the emitter",
             "operating point: appendix false-alarm share at 0.5%",
             "operating point: the base rate is measured, not a literal"]
    script = os.path.join(REPO, "paper", "scripts", "analysis", "baserate.py")
    if not os.path.exists(script):
        for name in names:
            FAIL.append((name, "baserate.py missing", "present"))
        return
    proc = subprocess.Popen([sys.executable, script], cwd=REPO,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    text = out.decode("utf-8", "replace")
    if proc.returncode != 0:
        for name in names:
            FAIL.append((name, "baserate.py exit %d" % proc.returncode,
                         "exit 0"))
        return
    # Only the full-corpus block. The held-out split is emitted beside it and
    # publishes nothing, so pinning it here would invent a claim.
    block = text.split("HELD-OUT SPLIT")[0]

    def grab(name, pattern, want):
        m = re.search(pattern, block)
        if m:
            check(name, m.group(1), want)
        else:
            FAIL.append((name, "not emitted by baserate.py", want))

    grab(names[0], r"base rate\s+(\S+  \[[^\]]+\]   \(\d+/\d+\))",
         "18.6%  [17.5, 19.9]   (747/4008)")
    grab(names[1], r"recall\s+(\S+  \[[^\]]+\]   \(\d+/\d+\))",
         "13.5%  [11.3, 16.2]   (101/747)")
    grab(names[2], r"FPR\s+(\S+  \[[^\]]+\]   \(\d+/\d+\))",
         "1.07%  [0.77, 1.49]   (35/3261)")
    grab(names[3], r"18\.6%\s+(\d+\.\d)%\s+\d+\.\d  <-", "74.3")
    grab(names[4], r"\n\s+0\.5%\s+(\d+\.\d)%", "6.0")
    grab(names[5], r"\n\s+0\.5%\s+\d+\.\d%\s+(\d+\.\d)", "15.8")

    # THE PAPER AGAINST THE EMITTER. Both sites, because the operating point
    # is stated twice and a partial correction leaving one of them behind is
    # this repository's most repeated failure.
    tex = _main_tex()
    body = ("recall $13.5\\%$ $[11.3, 16.2]$ and a false-positive rate of\n"
            "$1.07\\%$ $[0.77, 1.49]$")
    check(names[6], body in tex, True)
    check(names[7], "falling to $6.0\\%$ at a realistic $0.5\\%$ rogue" in tex,
          True)
    check(names[8], "Recall is $101/747$" in tex, True)
    check(names[9],
          "rogue rate of $18.6\\%$ ($747$ rogue trajectories of $4{,}008$"
          in tex, True)
    check(names[10],
          "$74.3\\%$ at this" in tex and "$6.0\\%$ at a realistic $0.5\\%$, "
          "which is $15.8$" in tex, True)
    # The complement of that precision, which the paper reads against the
    # ~30% at which developers abandon a static-analysis tool.
    share = re.search(r"false-alarm share is (\d+)%", block)
    quoted = re.search(r"At a \$0\.5\\%\$ rogue\nrate we are at \$(\d+)\\%\$",
                       tex)
    _cmp(names[11], quoted.groups() if quoted else None,
         share.groups() if share else None)

    src_path = os.path.join(REPO, "crates", "sentinel-cli", "src", "main.rs")
    if not os.path.exists(src_path):
        SKIP.append((names[12], "crates/ is not shipped in a release tree",
                     SKIP_ABSENT))
    else:
        src = io.open(src_path, encoding="utf-8").read()
        derived = ("let bench_base = rogue.len() as f64 "
                   "/ r.trajectories.len().max(1) as f64;" in src
                   and "for base in [bench_base," in src)
        literal = re.search(r"for base in \[\s*0\.\d", src)
        check(names[12], derived and not literal, True)


# ------------------------------------------------------ incident artifacts --

def paper_tab_app_artifacts():
    """tab:app-artifacts, and the three rows of it that nothing can emit."""
    inc = os.path.join(DATA, "incidents")
    tex, rows = _tex_table("tab:app-artifacts")
    names = ["tab:app-artifacts %s row" % l for l in
             ("Windows Startup folder entries",
              "Files written into the real home directory",
              "New application-data directory",
              "Harness settings file replaced")] + [
        "tab:app-artifacts total is the sum of its rows",
        "tab:app-artifacts: rows with no file to count are named"]
    if tex is None:
        _no_tex("tab:app-artifacts", names)
        return
    try:
        startup = sorted(os.listdir(os.path.join(inc, "startup-artifacts")))
        home = sorted(os.listdir(os.path.join(inc, "home-artifacts")))
    except OSError as exc:
        for name in names:
            FAIL.append((name, str(exc)[:50], "the incident tree"))
        return
    appdata = [n for n in startup if n.startswith("appdata-")]
    settings = os.path.join(inc, "settings-wiped-20260813-2044.json")
    for label, count in (
            ("Windows Startup folder entries", len(startup) - len(appdata)),
            ("Files written into the real home directory", len(home)),
            ("New application-data directory", len(appdata)),
            ("Harness settings file replaced",
             1 if os.path.isfile(settings) else 0)):
        _cmp("tab:app-artifacts %s row" % label, tex.get(label), (str(count),))

    # THE TOTAL, WHICH IS ARITHMETIC AND SO IS CHECKABLE WITHOUT AN EMITTER.
    # It is the one cell that would absorb a correction to any row above it.
    printed = [int(r[0]) for label, r in tex.items()
               if label not in ("Total",) and r and r[0].isdigit()]
    check("tab:app-artifacts total is the sum of its rows",
          int(tex["Total"][0]) if "Total" in tex else None, sum(printed))

    # The three rows this repository holds no file for, named so the set
    # cannot grow quietly. A fourth row appearing without evidence fails here.
    unbacked = ["User-scope registry Run keys", "User PATH truncations",
                "Shell-profile environment autoloader"]
    backed = ["Windows Startup folder entries",
              "Files written into the real home directory",
              "New application-data directory",
              "Harness settings file replaced", "Total"]
    check("tab:app-artifacts: rows with no file to count are named",
          sorted(l for l in tex if l not in backed and not l.startswith("{")),
          sorted(unbacked))
    note("tab:app-artifacts rows resting on forensics, not on a file",
         "%d of 7 (%s)" % (len(unbacked), "; ".join(unbacked)))


def session_denominator():
    """THE SESSION DENOMINATOR ITSELF WAS PINNED NOWHERE."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import models
    except ImportError as exc:
        FAIL.append(("models.py imports", str(exc), "ok"))
        return
    records, ran, n_auth, n_quota, other = models.census_facts(
        os.path.join(DATA, "denials-opus-max"))
    check("opus-max session records", records, 7291)
    check("opus-max sessions that ran", ran, 16)
    check("opus-max OAuth expiries", n_auth, 7215)
    check("opus-max weekly-limit stubs", n_quota, 60)
    check("opus-max records of unknown cause", other, 0)
    check("opus-max: --effort's denominator IS --census's 'ran'",
          models.arm_rows("denials-opus-max")[1], ran)



API_PREFIXES = ("denials-api-", "probe-api-", "probe-r2-", "armcheck-",
                "famcheck", "ovr-check-")

API_ARMS = ("defer", "explain", "full", "padded", "terse")


def _api_archives():
    """Every API-harness archive directory, by the prefixes the harness uses."""
    try:
        names = os.listdir(DATA)
    except OSError:
        return []
    return sorted(d for d in names
                  if d.startswith(API_PREFIXES)
                  and os.path.isdir(os.path.join(DATA, d)))



CENSUS_ABSENT = ("INPUT ABSENT - no paper/run-b-pilot-sessions.json in this tree,"
                 " so the pilot cannot be separated from Run B")


def _baseline_census():
    """Session logs that existed when Run B was declared, or None."""
    path = os.path.join(REPO, "paper", "run-b-pilot-sessions.json")
    if not os.path.exists(path):
        path = os.path.join(REPO, ".campaign", "api-run",
                            "run-b-pilot-sessions.json")
    if not os.path.exists(path):
        return None
    try:
        with io.open(path, encoding="utf-8") as fh:
            names = json.load(fh).get("sessions") or []
    except (IOError, OSError, ValueError):
        return None
    # stored relative to paper/data; the readers want the bare filename per
    # archive, so key by (archive, file).
    out = set()
    for rel in names:
        parts = rel.replace("\\", "/").split("/")
        if len(parts) >= 3:
            out.add((parts[0], parts[-1]))
    return out or None


CONTAM_LIST = os.path.join(REPO, "paper", "run-b-excluded-sessions.txt")


def _contam_keys():
    """The listed sessions as archive-relative paths, via archive.py's reader."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import archive as archive_mod
    return archive_mod.contaminated_sessions(CONTAM_LIST)


def _contaminated_log(path):
    """Is this session log off-instrument? archive.py's test, not a copy."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import archive as archive_mod
    return archive_mod.is_contaminated(path, CONTAM_LIST)


def contaminated_excluded():
    """The three assertions above, plus the control that makes (3) mean it."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import archive as archive_mod
    except ImportError as exc:
        FAIL.append(("archive.py imports (instrument exclusion)",
                     str(exc), "ok"))
        return

    # (1) The list is present and non-empty. It is committed, so its absence is
    # a defect in this tree and not a property of the machine.
    keys = archive_mod.contaminated_sessions(CONTAM_LIST)
    if not keys:
        FAIL.append(("off-instrument list is non-empty",
                     "0 sessions listed in %s"
                     % os.path.relpath(CONTAM_LIST, REPO), ">= 1"))
        return
    check("off-instrument list is non-empty", len(keys) >= 1, True)
    hw_path = os.path.join(REPO, "paper", "run-b-excluded-count.txt")
    try:
        hw = int([l.strip() for l in io.open(hw_path, encoding="utf-8")
                  if l.strip() and not l.startswith("#")][0])
    except (IOError, OSError, ValueError, IndexError):
        FAIL.append(("off-instrument high-water mark is readable",
                     "missing or unparseable", "an integer"))
        return
    check("off-instrument ledger has not shrunk below the high-water mark",
          len(keys) >= hw, True)
    # AND THE MARK ITSELF MUST BE CURRENT. A high-water file that lags the
    # ledger is the same defect one level up, so the gap is bounded: the
    # quarantine raises the mark in the same operation that adds entries.
    check("off-instrument high-water mark is current",
          hw >= len(keys), True)
    note("off-instrument sessions listed", len(keys))
    total_api = len(glob.glob(os.path.join(
        DATA, "denials-api-*", "events", "*.jsonl")))
    if total_api:
        check("off-instrument sessions are a small share of the corpus",
              len(keys) < 0.10 * total_api, True)
        note("off-instrument share",
             "%d of %d api session logs (%.2f%%)"
             % (len(keys), total_api, 100.0 * len(keys) / total_api))

    # (2) Every one of them is still on disk. Retention is the rule; a gap here
    # is evidence that was deleted, not a list that went stale.
    if not os.path.isdir(DATA):
        PASS.append(("off-instrument sessions retained on disk",
                     "INPUT ABSENT - no paper/data in this tree"))
    else:
        check("off-instrument sessions retained on disk",
              _contam_missing(keys, DATA), [])

    if not os.path.isdir(DATA):
        return

    # (3) Nothing any reader admits is on the list. Observed through the two
    # readers, not recomputed.
    admitted = []
    for name in sorted(os.listdir(DATA)):
        path = os.path.join(DATA, name)
        if not name.startswith("denials") or not os.path.isdir(path):
            continue
        admitted.extend(p for _s, p in archive_mod.session_files(path))
    leaked = _contam_intersection(admitted, archive_mod)
    check("archive.session_files admits no off-instrument session",
          leaked, [])

    api_admitted = []
    census = _baseline_census()
    for name in _api_archives():
        events = os.path.join(DATA, name, "events")
        if not os.path.isdir(events):
            continue
        for log in sorted(os.listdir(events)):
            if not log.endswith(".jsonl"):
                continue
            if (census is not None and name.startswith("denials-api-")
                    and (name, log) not in census):
                continue
            if _contaminated_log(os.path.join(events, log)):
                continue
            api_admitted.append(os.path.join(events, log))
    check("verify_all._api_read admits no off-instrument session",
          _contam_intersection(api_admitted, archive_mod), [])

    # The exclusion is a quantity, not a mood: how many were actually held back
    # in this tree. If the list is right and the corpus is intact these agree,
    # and a disagreement means a listed path matched no admitted walk.
    held = 0
    for name in sorted(os.listdir(DATA)):
        path = os.path.join(DATA, name)
        if name.startswith("denials") and os.path.isdir(path):
            held += len(archive_mod.contaminated_in(path, CONTAM_LIST))
    check("off-instrument sessions actually held back", held, len(keys))

    _contaminated_control(archive_mod)


def _contam_intersection(paths, archive_mod):
    """The admitted paths that are on the list. Sorted, for a readable diff."""
    return sorted(os.path.relpath(p, DATA) for p in paths
                  if archive_mod.is_contaminated(p, CONTAM_LIST))


def _contam_missing(keys, data):
    """Listed sessions that are NOT on disk, as archive-relative keys."""
    return sorted(k for k in keys
                  if not os.path.exists(os.path.join(data, k)))


def _contaminated_control(archive_mod):
    """POSITIVE CONTROL: build the leak, and require the gate to catch it."""
    import shutil
    import tempfile

    listed = sorted(archive_mod.contaminated_sessions(CONTAM_LIST))
    if not listed:
        FAIL.append(("off-instrument positive control",
                     "no listed session to build a leak from", ">= 1"))
        return
    sample = listed[0]
    cell, _sep, log = sample.rpartition("/")

    tmp = tempfile.mkdtemp(prefix="contam-control-")
    try:
        real = os.path.join(tmp, cell)
        os.makedirs(real)
        for name in (log, "admitted-control.jsonl"):
            with io.open(os.path.join(real, name), "w",
                         encoding="utf-8") as fh:
                fh.write('{"kind": "tool_call", "run_id": "r", "step": 1}\n')

        arch = os.path.join(tmp, cell.split("/")[0])

        unfiltered = [p for _s, p in
                      archive_mod.session_files(arch,
                                                exclude_contaminated=False)]
        check("positive control: unfiltered walk leaks the listed session",
              len([p for p in unfiltered
                   if archive_mod.is_contaminated(p, CONTAM_LIST)]), 1)

        # LEAK 2: the same walk with the exclusion on must not leak, and must
        # still return the sibling that is NOT on the list. A filter that
        # excluded everything would pass leak 1 and be useless.
        filtered = [p for _s, p in archive_mod.session_files(arch)]
        check("positive control: filtered walk drops it",
              [p for p in filtered
               if archive_mod.is_contaminated(p, CONTAM_LIST)], [])
        check("positive control: filtered walk keeps the clean sibling",
              sorted(os.path.basename(p) for p in filtered),
              ["admitted-control.jsonl"])

        check("positive control: retention check fires on a missing path",
              _contam_missing([cell + "/gone-from-disk.jsonl"], tmp),
              [cell + "/gone-from-disk.jsonl"])
        check("positive control: retention check passes a present path",
              _contam_missing([cell + "/admitted-control.jsonl"], tmp), [])
        check("positive control: a listed path is recognised by name",
              archive_mod.is_contaminated(
                  os.path.join("anywhere", sample), CONTAM_LIST), True)
        check("positive control: an unlisted path is not",
              archive_mod.is_contaminated(
                  os.path.join("anywhere", cell, "not-listed.jsonl"),
                  CONTAM_LIST), False)

        for label, text_ in (
                ("absent", None),
                ("unreadable", "*DIRECTORY*"),
                ("truncated below its own header", "*TRUNCATED*"),
                ("carrying no '# count' header", "*NOHEADER*")):
            path = os.path.join(tmp, "list-%s.txt" % label.split()[0])
            if text_ is None:
                pass                       # never created
            elif text_ == "*DIRECTORY*":
                os.makedirs(path)
            else:
                with io.open(CONTAM_LIST, encoding="utf-8") as fh:
                    body = fh.read()
                if text_ == "*TRUNCATED*":
                    keep = [l for l in body.splitlines()
                            if l.startswith("#") or not l.strip()]
                    ents = [l for l in body.splitlines()
                            if l.strip() and not l.startswith("#")]
                    body = "\n".join(keep + ents[:len(ents) // 2]) + "\n"
                else:
                    body = "\n".join(l for l in body.splitlines()
                                     if not l.strip().startswith("# count"))
                with io.open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
            check("positive control: a list %s is REFUSED, not read as empty"
                  % label, _contam_refuses(archive_mod, path), True)

        declared_empty = os.path.join(tmp, "list-declared-empty.txt")
        with io.open(declared_empty, "w", encoding="utf-8") as fh:
            fh.write("# a tree with no off-instrument sessions\n"
                     "# count   0\n")
        check("positive control: a list declaring '# count 0' is accepted",
              _contam_refuses(archive_mod, declared_empty), False)
        check("positive control: a declared-empty list excludes nothing",
              sorted(archive_mod.contaminated_sessions(declared_empty)), [])
        check("positive control: a declared-empty list is not the real one",
              archive_mod.is_contaminated(os.path.join("anywhere", sample),
                                          declared_empty), False)

        truncated = os.path.join(tmp, "list-half.txt")
        with io.open(CONTAM_LIST, encoding="utf-8") as fh:
            body = fh.read()
        ents = [l for l in body.splitlines()
                if l.strip() and not l.startswith("#")]
        with io.open(truncated, "w", encoding="utf-8") as fh:
            fh.write("\n".join([l for l in body.splitlines()
                                if l.startswith("#")] + ents[:48]) + "\n")
        check("positive control: 48 entries under a header of 97 is caught",
              _contam_refuses(archive_mod, truncated), True)
        # The header and the entries must agree EXACTLY - that is the
        # property archive.py refuses on, and it is what makes the floor
        # above safe: the list cannot be edited on one side only.
        check("positive control: the real list's header agrees with its "
              "entries",
              archive_mod.contaminated_declared(CONTAM_LIST),
              len(archive_mod.contaminated_sessions()))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _contam_refuses(archive_mod, path):
    """Does the reader REFUSE this exclusion list rather than read it empty?"""
    try:
        archive_mod.contaminated_sessions(path)
    except archive_mod.OffInstrumentListError:
        return True
    return False


def read_losses():
    """Nothing in the corpus is dropped unread, and the counter can see it."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import archive as archive_mod
    except ImportError as exc:
        FAIL.append(("archive.py imports (read census)", str(exc), "ok"))
        return

    import shutil
    import tempfile

    archive_mod.reset_read_census()
    tmp = tempfile.mkdtemp(prefix="readloss-")
    try:
        good = os.path.join(tmp, "denials-probe", "sess-1", "events.jsonl")
        os.makedirs(os.path.dirname(good))
        with io.open(good, "w", encoding="utf-8") as fh:
            fh.write('{"kind":"tool_call","run_id":"r","step":1}\n')
            fh.write('{"kind":"tool_call","run_id":"r","st\n')   # torn
            fh.write('{"kind":"tool_call","run_id":"r","step":3}\n')
        events, bad = archive_mod.read_log(good)
        check("positive control: a torn line is counted, not just dropped",
              (len(events), bad), (2, 1))
        check("positive control: the census sees the torn line",
              archive_mod.read_census(), (1, 1, 0))
        buf = io.StringIO()
        archive_mod.report_read_losses("positive control", buf)
        check("positive control: the loss is reported, not only counted",
              "DID NOT READ EVERYTHING IT WALKED" in buf.getvalue()
              and good in buf.getvalue(), True)

        # And a clean read must say nothing at all, or the report is noise and
        # gets ignored exactly when it is right.
        archive_mod.reset_read_census()
        archive_mod.read_log(os.path.join(tmp, "denials-probe", "sess-1",
                                          "no-such.jsonl"))
        check("positive control: an unreadable log is counted separately",
              archive_mod.read_census(), (0, 0, 1))
        archive_mod.reset_read_census()
        quiet = io.StringIO()
        archive_mod.report_read_losses("positive control", quiet)
        check("positive control: a clean read reports nothing",
              quiet.getvalue(), "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if not os.path.isdir(DATA):
        PASS.append(("corpus has no unparseable lines",
                     "INPUT ABSENT - no paper/data in this tree"))
        return

    archive_mod.reset_read_census()
    logs = events = 0
    for name in sorted(os.listdir(DATA)):
        path = os.path.join(DATA, name)
        if not name.startswith("denials") or not os.path.isdir(path):
            continue
        for _session, log in archive_mod.session_files(path):
            got, _bad = archive_mod.read_log(log)
            logs += 1
            events += len(got)
    dropped, bad_logs, unreadable = archive_mod.read_census()
    note("read census", "%d logs, %d events" % (logs, events))
    check("corpus has no unparseable lines", (dropped, bad_logs), (0, 0))
    check("every session log in the corpus can be opened", unreadable, 0)
    archive_mod.reset_read_census()


def _scoped(name, got, want, census):
    """An exact pin that only means anything once the pilot has been scoped."""
    if census is None:
        FAIL.append((name, CENSUS_ABSENT, want))
        return
    check(name, got, want)


def _at_least(name, got, floor, census):
    """A monotone floor while the run collects; INPUT ABSENT with no census."""
    if census is None:
        FAIL.append((name, CENSUS_ABSENT, ">= %d" % floor))
        return
    if got >= floor:
        PASS.append((name, "%d (>= baseline %d, run in progress)"
                     % (got, floor)))
    else:
        FAIL.append((name, "%d, BELOW baseline" % got,
                     ">= %d" % floor))


def _api_read(archive, census=None):
    """(session logs, usage rows) for one archive, read the way the readers do."""
    sessions = []
    events = os.path.join(DATA, archive, "events")
    if os.path.isdir(events):
        for name in sorted(os.listdir(events)):
            if not name.endswith(".jsonl"):
                continue
            # Only the archives a live run writes into. The scratch and
            # probe corpora are static, so filtering them by a census that
            # never listed them would erase them.
            if (census is not None
                    and archive.startswith("denials-api-")
                    and (archive, name) not in census):
                continue
            if _contaminated_log(os.path.join(events, name)):
                continue
            rows = []
            for line in io.open(os.path.join(events, name),
                                encoding="utf-8", errors="replace"):
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
            sessions.append(rows)
    usage = []
    path = os.path.join(DATA, archive, "usage.jsonl")
    if os.path.isfile(path):
        for line in io.open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if line:
                try:
                    usage.append(json.loads(line))
                except ValueError:
                    pass
    return sessions, usage


def _api_split(archives):
    """(pilot cells, scratch archives) out of one listing of API archives."""
    pilot = [a for a in archives if a.startswith("denials-api-")]
    return pilot, [a for a in archives if not a.startswith("denials-api-")]


def _api_arms_and_combos(pilot):
    """(arms, model x effort combinations) parsed out of the cell names."""
    arms, combos = set(), set()
    for name in pilot:
        rest = name[len("denials-api-"):]
        arm = rest.split("-")[0]
        arms.add(arm)
        combos.add(rest[len(arm) + 1:])
    return tuple(sorted(arms)), combos


def _api_census_control():
    """POSITIVE CONTROL for the scratch count and the arm tuple."""
    names = ["denials-api-defer-m1-high", "denials-api-defer-m2-low",
             "denials-api-terse-m1-high", "probe-api-x", "armcheck-y",
             "famcheck-z"]
    pilot, scratch = _api_split(names)
    check("positive control: a scratch archive is not counted as a pilot "
          "cell", (len(pilot), len(scratch)), (3, 3))
    arms, combos = _api_arms_and_combos(pilot)
    check("positive control: the arm is the first token and the rest is the "
          "cell", (arms, len(combos)), (("defer", "terse"), 2))
    # And an empty pilot list must not read as a clean roster: `()` is what
    # a walk that found nothing returns, and it is not a set of arms.
    check("positive control: no pilot cells yields no arms, not the roster",
          _api_arms_and_combos([])[0], ())


def api_census():
    """Session and cell census over the API archives."""
    archives = _api_archives()
    check("api archives", len(archives), 241)

    pilot, scratch = _api_split(archives)
    check("api pilot cells (denials-api-*)", len(pilot), 160)
    check("api scratch archives (probe, armcheck, famcheck, ovr-check)",
          len(scratch), 81)

    # 32 model x thinking-effort combinations run through all five arms is
    # 160 cells. Pinning the product and both factors means dropping a model
    # cannot be absorbed by adding an arm.
    arms, combos = _api_arms_and_combos(pilot)
    check("api pilot arms", arms, API_ARMS)
    check("api pilot model x effort cells", len(combos), 32)

    census = _baseline_census()
    logs = 0
    pilot_logs = 0
    usage_rows = 0
    banked = 0
    api_errors = 0
    per_arm = collections.defaultdict(lambda: [0, 0, 0])   # logs, refus, ovr
    for name in archives:
        sessions, usage = _api_read(name, census)
        logs += len(sessions)
        if not name.startswith("denials-api-"):
            continue
        pilot_logs += len(sessions)
        usage_rows += len(usage)
        arm = name[len("denials-api-"):].split("-")[0]
        slot = per_arm[arm]
        slot[0] += len(sessions)
        for rows in sessions:
            verdicts = [str((r.get("meta") or {}).get("verdict") or "")
                        for r in rows if r.get("kind") == "guard_decision"]
            slot[1] += sum(1 for v in verdicts if v in ("deny", "overridden"))
            slot[2] += sum(1 for v in verdicts if v == "overridden")
        for row in usage:
            if row.get("banked"):
                banked += 1
            if str(row.get("outcome") or "").startswith("api-error"):
                api_errors += 1

    _scoped("api session logs, all archives", logs, 886, census)
    _scoped("api session logs, pilot cells", pilot_logs, 631, census)
    # The scratch archives are static and are never census-filtered, so this
    # one is exact whether or not the pilot can be scoped.
    check("api session logs, scratch", logs - pilot_logs, 255)
    _at_least("api pilot usage rows", usage_rows, 716, census)

    _at_least("api banked usage rows == banked logs", banked, pilot_logs,
              census)
    _at_least("api banked usage rows", banked, 631, census)
    _at_least("api-error records among banked", api_errors, 27, census)
    _at_least("api real sessions (banked minus api-error)",
              banked - api_errors, 604, census)

    trunc_bank = trunc_n = 0
    for name in archives:
        if not name.startswith("denials-api-"):
            continue
        path = os.path.join(DATA, name, "usage.jsonl")
        if not os.path.isfile(path):
            continue
        for line in io.open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not row.get("banked"):
                continue
            trunc_n += 1
            if str(row.get("outcome") or "").split(":")[0] == "max-steps":
                trunc_bank += 1
    if trunc_n:
        rate = trunc_bank / float(trunc_n)
        check("api step cap binds in a majority of banked sessions",
              rate > 0.5, True)
        check("api step cap binds in a LARGE majority (>= 60%)",
              rate >= 0.60, True)
        check("api step cap binds at least 50x the Claude wall-clock cap",
              rate >= 50 * (5 / 661.0), True)
        note("api step-cap truncation, banked",
             "%d of %d = %.1f%% (live; the pinned claims are the two above)"
             % (trunc_bank, trunc_n, 100 * rate))

    for arm in API_ARMS:
        logs_, refusals, overrides = per_arm.get(arm, [0, 0, 0])
        _scoped("api arm %s: session logs" % arm, logs_,
                {"defer": 124, "explain": 127, "full": 127,
                 "padded": 124, "terse": 129}[arm], census)
        _scoped("api arm %s: refusals" % arm, refusals,
                {"defer": 25, "explain": 43, "full": 48,
                 "padded": 32, "terse": 41}[arm], census)
        _scoped("api arm %s: overrides" % arm, overrides,
                {"defer": 0, "explain": 0, "full": 9,
                 "padded": 0, "terse": 0}[arm], census)

    full_r, full_o = per_arm["full"][1], per_arm["full"][2]
    if census is None:
        FAIL.append(("api arm full: override %", CENSUS_ABSENT,
                     "%.2f +/- %.2f" % (18.75, 0.01)))
    else:
        near("api arm full: override %", 100.0 * full_o / full_r, 18.75, 0.01)

    other_r = sum(per_arm[a][1] for a in API_ARMS if a != "full")
    other_o = sum(per_arm[a][2] for a in API_ARMS if a != "full")
    _scoped("api non-full arms: refusals", other_r, 141, census)
    _scoped("api non-full arms: overrides", other_o, 0, census)
    _scoped("api pilot refusals, all arms", other_r + full_r, 189, census)
    _scoped("api pilot overrides, all arms", other_o + full_o, 9, census)


def api_layout():
    """The archive layout is the one the readers expect."""
    archives = _api_archives()
    no_events = [a for a in archives
                 if not os.path.isdir(os.path.join(DATA, a, "events"))]
    no_usage = [a for a in archives
                if not os.path.isfile(os.path.join(DATA, a, "usage.jsonl"))]
    check("api archives with an events/ directory",
          len(archives) - len(no_events), len(archives))
    check("api archives with a usage.jsonl",
          len(archives) - len(no_usage), len(archives))

    stray = 0
    nested = 0
    for name in archives:
        for root, _dirs, files in os.walk(os.path.join(DATA, name)):
            for fname in files:
                if os.path.basename(root) == "events":
                    if not fname.endswith(".jsonl"):
                        stray += 1
                elif fname == "events.jsonl":
                    nested += 1
    check("api non-.jsonl files under events/", stray, 0)
    check("api archives using the nested events.jsonl spelling", nested, 0)


# The names `api_intact` is accountable for, declared once so the roster in
# `api_corpus` and the failure path below cannot drift apart. `guarded` compares
# the two, and a block that returns early used to leave the roster undelivered.
API_INTACT_CHECKS = (
    "session logs torn (scan_torn_sessions)",
    "session logs empty and contradicted by result.json",
    "session logs empty and unexplained",
    "session logs empty, quarantined dead-guard",
    "session logs empty, explained by result.json",
    "scan_torn_sessions exit status",
    "api logs seen by the torn-session scanner",
    "api events seen by the torn-session scanner",
)


def api_intact():
    """No banked session log is torn - and empty is counted, not called torn."""
    script = os.path.join(REPO, "paper", "scripts", "api",
                          "scan_torn_sessions.py")
    if not os.path.exists(script):
        FAIL.append(("scan_torn_sessions.py exists", "MISSING", "present"))
        return
    proc = subprocess.Popen([sys.executable, script],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=REPO)
    out, _ = proc.communicate()
    text = out.decode("utf-8", "replace")
    counts = re.search(
        r"summary: torn (\d+), empty (\d+), explained (\d+), "
        r"quarantined (\d+), contradicted (\d+), unexplained (\d+)", text)
    seen = re.search(r"scanned (\d+) banked session log\(s\), (\d+) event",
                     text)
    if not counts or not seen:
        # Emit every declared name so the roster still balances and the whole
        # block is reported red, rather than half of it vanishing.
        for name in API_INTACT_CHECKS:
            FAIL.append((name, "no summary line from the scanner",
                         "summary: torn N, empty N, ..."))
        return
    torn, _empty, explained, quarantined, contradicted, unexplained = (
        int(g) for g in counts.groups())
    census = _baseline_census()
    check("session logs torn (scan_torn_sessions)", torn, 0)
    check("session logs empty and contradicted by result.json",
          contradicted, 0)
    check("session logs empty and unexplained", unexplained, 0)
    _at_least("session logs empty, quarantined dead-guard", quarantined, 79,
              census)
    _at_least("session logs empty, explained by result.json", explained, 764,
              census)
    # The exit status is read as well as the counts: a scanner that stopped
    # returning nonzero for a condition it still prints would otherwise be
    # caught by nothing. 0 clean, 1 torn, 2 empty that nothing explains.
    check("scan_torn_sessions exit status", proc.returncode,
          1 if torn else (2 if (contradicted or unexplained) else 0))
    _at_least("api logs seen by the torn-session scanner",
              int(seen.group(1)), 886, census)
    _at_least("api events seen by the torn-session scanner",
              int(seen.group(2)), 9148, census)


def api_corpus():
    """The three API blocks, each skipped by name if the archives are gone."""
    guarded("api census", ("api",), [
        "api archives",
        "api pilot cells (denials-api-*)",
        "api scratch archives (probe, armcheck, famcheck, ovr-check)",
        "api pilot arms",
        "api pilot model x effort cells",
        "api session logs, all archives",
        "api session logs, pilot cells",
        "api session logs, scratch",
        "api pilot usage rows",
        "api banked usage rows == banked logs",
        "api banked usage rows",
        "api-error records among banked",
        "api real sessions (banked minus api-error)",
        "api step cap binds in a majority of banked sessions",
        "api step cap binds in a LARGE majority (>= 60%)",
        "api step cap binds at least 50x the Claude wall-clock cap",
        "api arm full: override %",
        "api non-full arms: refusals",
        "api non-full arms: overrides",
        "api pilot refusals, all arms",
        "api pilot overrides, all arms",
    ] + ["api arm %s: %s" % (a, f)
         for a in API_ARMS
         for f in ("session logs", "refusals", "overrides")], api_census)

    guarded("api layout", ("api",), [
        "api archives with an events/ directory",
        "api archives with a usage.jsonl",
        "api non-.jsonl files under events/",
        "api archives using the nested events.jsonl spelling",
    ], api_layout)

    guarded("api integrity", ("api",), list(API_INTACT_CHECKS), api_intact)

    guarded("api denial onset", ("api",), [
        "api denial-onset quartiles",
        "api longest onset",
        "api runs reaching a denial",
    ], api_onset)


def api_onset():
    """The API side of §app:repro's onset comparison."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import responses
    except ImportError as exc:
        FAIL.append(("api denial-onset quartiles", str(exc), "ok"))
        FAIL.append(("api runs reaching a denial", str(exc), "ok"))
        return
    f = responses.onset_facts(os.path.join(DATA, "denials-api-*"))
    check("api denial-onset quartiles",
          (f["p25"], f["median"], f["p75"]), (2, 5, 8))
    if f["max"] >= 16:
        PASS.append(("api longest onset",
                     "%d (>= floor 16, the figure app:repro prints; a sample "
                     "maximum can only grow)" % f["max"]))
    else:
        FAIL.append(("api longest onset",
                     "%d, BELOW the floor the paper prints" % f["max"],
                     ">= 16"))
    if f["reached"] >= 802:
        PASS.append(("api runs reaching a denial",
                     "%d (>= floor 802; grows while a run collects)"
                     % f["reached"]))
    else:
        FAIL.append(("api runs reaching a denial",
                     "%d, BELOW floor" % f["reached"], ">= 802"))


# ------------------------------------------------ flat corpus integrity ---

def _torn_lines(path):
    """(non-empty lines, unparseable ones). The predicate, in one place."""
    n = bad = 0
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                n += 1
                try:
                    json.loads(line)
                except ValueError:
                    bad += 1
    except (IOError, OSError):
        return 0, 0
    return n, bad


def release_declares_its_failures():
    """The excuse list and the release README have to say the same thing."""
    path = os.path.join(REPO, "paper", "scripts", "make_artifact.py")
    if not os.path.exists(path):
        # The generator does not ship in what it generates. This gate reads its
        # SOURCE to pin the excuse roster against the README, so in a release
        # there is nothing to read and nothing to check - absence, not failure.
        SKIP.append(("release README declares every excused failure",
                     "make_artifact.py is not shipped in its own output",
                     SKIP_ABSENT))
        return
    text = io.open(path, encoding="utf-8").read()

    anchor = "Anything that fails and is not one of the above is a real finding"
    if anchor not in text:
        FAIL.append(("release README carries its declared-failure list",
                     "anchor sentence missing", "present"))
        return
    readme = " ".join(text[:text.index(anchor)].split())

    # The two scripts that genuinely are withheld must be named in the README.
    for needle, what in (
            ("anonymise_positive_control", "the anonymity battery"),
            ("anonymise_check", "the anonymity scanner"),
    ):
        check("release README names %s as withheld" % what,
              needle in readme, True)

    # The collection monitor is the opposite property - SHIPPED, not declared -
    # which is exactly what the first draft got backwards.
    check("accrual_monitor.py ships in the release",
          '"paper/scripts/api/accrual_monitor.py"' in text, True)
    check("accrual_monitor.py is shipped rather than excused",
          "accrual_monitor.py exists" in RELEASE_SUBSET, False)

    check("release excuse list is non-empty", len(RELEASE_SUBSET) >= 5, True)
    check("no anonymity row is excusable",
          sorted(k for k in RELEASE_SUBSET if "anonymis" in k.lower()), [])
    check("every release excuse carries a reason",
          sorted(k for k, v in RELEASE_SUBSET.items() if not (v or "").strip()),
          [])
    check("release excuses are scoped to the tree they are in",
          tree_is_export(),
          not os.path.exists(os.path.join(REPO, ".git")))


def session_durations():
    """The nine duration numbers in \\S app:cap, against their emitter."""
    path = os.path.join(REPO, "paper", "scripts", "analysis", "models.py")
    if not os.path.exists(path):
        FAIL.append(("models.py exists", "MISSING", "present"))
        return
    proc = subprocess.Popen([sys.executable, path, "--timeouts"], cwd=REPO,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    text = out.decode("utf-8", "replace")
    rows = {}
    for line in text.split("\n"):
        f = line.split()
        if len(f) >= 7 and f[0] in ("haiku", "sonnet", "opus"):
            rows[f[0]] = [t.rstrip("s") for t in f[2:]]
    if len(rows) != 3:
        SKIP.append(("session durations match the paper",
                     "models.py --timeouts printed no arm rows here",
                     SKIP_ABSENT))
        return

    tex = io.open(os.path.join(REPO, "paper", "main.tex"),
                  encoding="utf-8").read()
    # median, max, result-max per arm, in the order the sentence prints them.
    for arm, idx, what in (("haiku", 0, "median"), ("sonnet", 0, "median"),
                           ("opus", 0, "median"),
                           ("haiku", 4, "max"), ("sonnet", 4, "max"),
                           ("opus", 4, "max"),
                           ("haiku", 5, "result-max"),
                           ("sonnet", 5, "result-max"),
                           ("opus", 5, "result-max")):
        want = rows[arm][idx]
        check("session %s %s is in the paper" % (arm, what),
              ("$%s$" % want) in tex, True)


def analysis_reads_written_keys():
    """Every record key an analysis READS must be a key its producer WRITES."""
    try:
        sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
        import own_action_space as oas
    except Exception as exc:                       # noqa: BLE001
        FAIL.append(("own_action_space imports", str(exc)[:60], "ok"))
        return

    archive = os.path.join(DATA, "denials")
    if not os.path.isdir(archive):
        SKIP.append(("analysis consumers read only keys the producer writes",
                     _no_corpus(["cli"]), SKIP_ABSENT))
        return
    records, _n = oas.calls_in(archive)
    if not records:
        FAIL.append(("calls_in produced records", 0, ">= 1"))
        return
    produced = set()
    for r in records:
        produced |= set(r.keys())
    note("record keys produced by calls_in", ", ".join(sorted(produced)))

    # Consumers of those records, and the keys their source asks for.
    consumers = ["second_monitor.py", "own_action_space.py"]
    missing = []
    for name in consumers:
        path = os.path.join(REPO, "paper", "scripts", "analysis", name)
        if not os.path.exists(path):
            continue
        src = io.open(path, encoding="utf-8").read()
        for key in set(re.findall(r'\bcall\.get\(\s*["\']([A-Za-z_]+)["\']',
                                  src)):
            if key not in produced:
                missing.append("%s reads %r" % (name, key))
    check("analysis consumers read only keys the producer writes",
          sorted(missing), [])


def arm_integrity_is_reported():
    """`arm_integrity.py` runs, and what it finds is in the paper."""
    path = os.path.join(REPO, "paper", "scripts", "analysis", "arm_integrity.py")
    if not os.path.exists(path):
        FAIL.append(("arm_integrity.py exists", "MISSING", "present"))
        return
    if not os.path.isdir(os.path.join(DATA, "denials-terse")):
        SKIP.append(("arm integrity session totals are in the paper",
                     _no_corpus(["ablation"]), SKIP_ABSENT))
        return
    proc = subprocess.Popen([sys.executable, path], cwd=REPO,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    text = out.decode("utf-8", "replace")
    check("arm_integrity.py runs", proc.returncode in (0, 1), True)

    m = re.search(r"session totals:\s*(.+)", text)
    if not m:
        FAIL.append(("arm_integrity.py prints session totals",
                     "no totals line", "present"))
        return
    totals = dict(re.findall(r"([a-z]+)\s+(\d+)", m.group(1)))
    note("arm integrity session totals", m.group(1).strip()[:80])
    tex = io.open(os.path.join(REPO, "paper", "main.tex"),
                  encoding="utf-8").read()
    # Every achieved count the caption quotes must be the emitted one.
    for arm in ("terse", "explain", "padded", "defer", "full", "control"):
        if arm in totals:
            check("arm integrity %s total is in the paper" % arm,
                  ("$%s$" % totals[arm]) in tex, True)



_RUNA_MEASURED = {}


def _runa_measured():
    """`run_a_report.measure` over the corpus the emitter itself points at."""
    if "got" not in _RUNA_MEASURED:
        sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
        import run_a_report as ra
        _RUNA_MEASURED["got"] = (ra, ra.measure(ra.CORPUS))
    return _RUNA_MEASURED["got"]


def _opus_arms_measured():
    """`opus_arms.measure` for each of the five arms, keyed by label."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import opus_arms as oa
    return oa, dict((label, oa.measure(os.path.join(DATA, name)))
                    for label, name, _offers in oa.ARMS)


def _runa_body():
    """The prose of §app:runa, whitespace flattened so wrapping is invisible."""
    body = _main_tex().split("\\label{app:runa}", 1)[-1].split(
        "\\subsection{The 2026-08-21 pilot", 1)[0]
    return re.sub(r"\s+", " ", body)


def paper_tab_app_runa():
    """tab:app-runa, both panels, each against its own emitter and corpus."""
    pools = ["tab:app-runa %s row" % r for r in
             ("events/", "events.recovered/", "events.errored/", "naive sum",
              "deduplicated")]
    arms = ["tab:app-runa %s arm row" % a for a in
            ("terse", "explain", "padded", "defer", "pooled")]

    def _pools():
        _ra, m = _runa_measured()
        tex, _rows = _tex_table("tab:app-runa", 0)
        if tex is None:
            _no_tex("tab:app-runa", pools)
            return
        for label, key in (("events/", "events"),
                           ("events.recovered/", "events.recovered"),
                           ("events.errored/", "events.errored")):
            _cmp("tab:app-runa %s row" % label, tex.get(label),
                 (str(m["pool"][key]), str(m["pool_over"][key]),
                  str(m["pool_logs"][key])))
        _cmp("tab:app-runa naive sum row", tex.get("naive sum"),
             (str(m["raw_denials"]), str(m["raw_over"]), str(m["raw_logs"])))
        _cmp("tab:app-runa deduplicated row", tex.get("deduplicated"),
             (str(m["dedup_denials"]), str(m["dedup_overrides"]),
              str(m["dedup_logs"])))

    def _arms():
        oa, measured = _opus_arms_measured()
        tex, _rows = _tex_table("tab:app-runa", 1)
        if tex is None:
            _no_tex("tab:app-runa", arms)
            return
        pooled_deny = pooled_over = 0
        for label, _name, offers in oa.ARMS:
            if offers:                       # `full` is not in this panel
                continue
            f = measured[label]
            deny, over = f["denials"], f["override_events"]
            pooled_deny += deny
            pooled_over += over
            _cmp("tab:app-runa %s arm row" % label, tex.get(label),
                 (str(deny), str(over), str(deny + over)))
        _cmp("tab:app-runa pooled arm row", tex.get("pooled"),
             (str(pooled_deny), str(pooled_over),
              str(pooled_deny + pooled_over)))

    guarded("tab:app-runa pool panel", ("runa",), pools, _pools)
    guarded("tab:app-runa arm panel", ("opus-arms",), arms, _arms)


def paper_runa_prose():
    """Every number the §app:runa prose and caption state, against the data."""
    names = ["app:runa the published figure is the quarantined one",
             "app:runa the unquarantined comparison rates",
             "app:runa the quarantine widens the bound and says by how much",
             "app:runa the departure from the house rule is stated with D4-3",
             "app:runa naive sum is named as wrong",
             "app:runa vendor split", "app:runa contaminated log count",
             "app:runa contamination is split by what it exposed",
             "app:runa the affordance-hunting session is inside that count",
             "app:runa caption duplication shape",
             "app:runa caption deduplicated denominator",
             "app:runa caption names the quarantined figure as published"]

    def _body():
        ra, m = _runa_measured()
        text = _runa_body()
        caption = _main_tex().split("\\label{tab:app-runa}")[0].rsplit(
            "\\begin{table}", 1)[1]
        caption = re.sub(r"\s+", " ", caption)

        got = re.search(
            r"published figure is the \\emph\{quarantined\} one, \$0\$ of "
            r"\$(\d+)\$ guard decisions,\s+Wilson \$\[([\d.]+), ([\d.]+)\]\$",
            text)
        _cmp("app:runa the published figure is the quarantined one",
             got.groups() if got else None,
             (str(m["quarantined_decisions"]),)
             + _ci_pair(m["quarantined_overrides"],
                        m["quarantined_decisions"]))

        # The two denominators the paper quotes as the UNQUARANTINED reading.
        got = re.search(
            r"\$0\$ of\s+\$(\d+)\$ deduplicated guard decisions, Wilson "
            r"\$\[([\d.]+), ([\d.]+)\]\$, and \$0\$ of \$(\d+)\$ in\s+the "
            r"primary \\texttt\{events/\} pool alone, \$\[([\d.]+), "
            r"([\d.]+)\]\$", text)
        _cmp("app:runa the unquarantined comparison rates",
             got.groups() if got else None,
             (str(m["dedup_denials"]),) + _ci_pair(0, m["dedup_denials"])
             + (str(m["pool"]["events"]),) + _ci_pair(0, m["pool"]["events"]))

        got = re.search(
            r"removing \$(\d+)\$ logs removes \$(\d+)\$ denials,\s+\$n\$ "
            r"falls, and the upper bound \\emph\{widens\} from "
            r"\$([\d.]+)\\%\$ to \$([\d.]+)\\%\$", text)
        _cmp("app:runa the quarantine widens the bound and says by how much",
             got.groups() if got else None,
             (str(m["touched_logs"]), str(m["touched_denials"]),
              _ci_pair(0, m["dedup_decisions"])[1],
              _ci_pair(m["quarantined_overrides"],
                       m["quarantined_decisions"])[1]))

        got = re.search(
            r"D4-3 found the discarded pool denial-rich, \$([\d.]+)\\%\$ of "
            r"its logs carrying a\s+denial against \$([\d.]+)\\%\$ of the "
            r"banked ones", text)
        _cmp("app:runa the departure from the house rule is stated with D4-3",
             got.groups() if got else None,
             ("%.1f" % (100.0 * m["discarded_deny_logs"]
                        / m["discarded_logs"]),
              "%.1f" % (100.0 * m["banked_deny_logs"] / m["banked_logs"])))

        got = re.search(r"Quoting the naive \$(\d+)\$ instead would report "
                        r"\$\[([\d.]+), ([\d.]+)\]\$", text)
        _cmp("app:runa naive sum is named as wrong",
             got.groups() if got else None,
             (str(m["raw_denials"]),) + _ci_pair(0, m["raw_denials"]))

        vendors = collections.Counter(ra.vendor_of(c) for c in m["cells"])
        got = re.search(r"Across (\w+) Google cells, (\w+) Anthropic and "
                        r"(\w+) OpenAI", text)
        _cmp("app:runa vendor split", got.groups() if got else None,
             (_numeral(vendors["Google"]), _numeral(vendors["Anthropic"]),
              _numeral(vendors["OpenAI"])))

        got = re.search(r"one of \$(\d+)\$ of the \$(\d+)\$ logs that reach "
                        r"outside their scratch checkout", text)
        _cmp("app:runa contaminated log count",
             got.groups() if got else None,
             (str(m["touched_logs"]), str(m["dedup_logs"])))

        got = re.search(r"[Aa]ll \$(\d+)\$ reached the paper artifact "
                        r"or the source tree.*?\$(\d+)\$ "
                        r"touched only the task table and the seed script",
                        text)
        _cmp("app:runa contamination is split by what it exposed",
             got.groups() if got else None,
             (str(m["touched_artifact"]), str(m["touched_tasklist_only"])))

        check("app:runa the affordance-hunting session is inside that count",
              (m["touched_hunting"] > 0
               and "That session is one of" in text
               and re.search(r"A further \$\d+\$ of the \$\d+\$ logs", text)
               is None), True)

        got = re.search(r"\$(\d+)\$ of the \$(\d+)\$ logs in "
                        r"\\texttt\{events\.errored/\} are byte-identical",
                        caption)
        _cmp("app:runa caption duplication shape",
             got.groups() if got else None,
             (str(m["identical_pairs"]),
              str(m["pool_logs"]["events.errored"])))

        got = re.search(r"counts \$(\d+)\$ denials twice; collapsing by "
                        r"session name and by content hash independently "
                        r"give \$(\d+)\$", caption)
        _cmp("app:runa caption deduplicated denominator",
             got.groups() if got else None,
             (str(m["raw_denials"] - m["dedup_denials"]),
              str(m["dedup_denials"])))

        got = re.search(r"published Run A figure is neither the naive row nor "
                        r"the deduplicated one but\s+the quarantined \$(\d+)\$"
                        r" --- that deduplicated row less the \$(\d+)\$ logs",
                        caption)
        _cmp("app:runa caption names the quarantined figure as published",
             got.groups() if got else None,
             (str(m["quarantined_decisions"]), str(m["touched_logs"])))

    guarded("app:runa prose", ("runa",), names, _body)


def paper_runa_opus_prose():
    """The four-arm sentences of §app:runa, against `opus_arms.py`."""
    names = ["app:runa pooled override events", "app:runa classified is named "
             "as the wrong variable", "app:runa the override's step trace",
             "app:runa the step the response window closed on",
             "app:runa history_rewrite fires in defer though the task mix "
             "lacks it",
             "app:runa divergent design exposure",
             "app:runa the full comparator is quoted on EVENTS",
             "app:runa 31/97 is named as the CLASSIFIED distribution",
             "app:runa the three override variables are named as three "
             "questions",
             "app:runa the emitter attribution names arm_integrity"]

    def _body():
        oa, measured = _opus_arms_measured()
        text = _runa_body()
        pooled_deny = sum(measured[l]["denials"] for l, _n, o in oa.ARMS
                          if not o)
        pooled_over = sum(measured[l]["override_events"] for l, _n, o in oa.ARMS
                          if not o)
        pooled_cls = sum(measured[l]["classified"] for l, _n, o in oa.ARMS
                         if not o)
        n = pooled_deny + pooled_over

        got = re.search(r"let one command through in \$(\d+)\$ guard "
                        r"decisions, \$([\d.]+)\\%\$ \$\[([\d.]+), "
                        r"([\d.]+)\]\$", text)
        _cmp("app:runa pooled override events", got.groups() if got else None,
             (str(n), "%.2f" % (100.0 * pooled_over / n))
             + _ci_pair(pooled_over, n, places=2))

        # The CLASSIFIED count, stated in the paper as the wrong variable.
        got = re.search(r"reconstruction reads \$(\d+)\$ of \$(\d+)\$ here "
                        r"and that is the wrong variable", text)
        _cmp("app:runa classified is named as the wrong variable",
             got.groups() if got else None,
             (str(pooled_cls), str(pooled_deny)))

        # The single override, walked out of the archive rather than trusted.
        # Paper first, emitter second: `_cmp` labels its two arguments and a
        # swap here reports the recomputed value as the published one.
        _cmp("app:runa the override's step trace",
             _paper_override_steps(text), _override_steps())

        # AND THE STEP THE CLASSIFIER STOPPED AT, which is the number that
        # makes the wrong-variable paragraph true rather than merely stated.
        # `ls -a .sentinel/` at 37 is why CLASSIFIED never reaches step 70.
        got = re.search(r"\\texttt\{ls -a \.sentinel/\} at step \$(\d+)\$, "
                        r"long before the override at step \$(\d+)\$", text)
        _cmp("app:runa the step the response window closed on",
             got.groups() if got else None, _window_steps())

        fam = _defer_families()
        fired = _defer_rule_denials("git.history_rewrite")
        got = re.search(r"\\texttt\{git\.history\\_rewrite\} is absent from "
                        r"\\emph\{defer\}'s task mix, though \$(\d+)\$ of "
                        r"that arm's denials fire under the rule", text)
        check("app:runa history_rewrite fires in defer though the task mix "
              "lacks it",
              fam is None or (fam.get("git.history_rewrite", 0) == 0
                              and got is not None
                              and got.group(1) == str(fired)), True)

        # The divergence that bars the matched-design reading, from
        # `arm_integrity.py`'s own share arithmetic and the campaign records.
        _cmp("app:runa divergent design exposure", _paper_divergence(text),
             _measured_divergence())

        full = measured["full"]
        full_over = full["override_events"]
        full_n = full["deny_events"] + full_over
        got = re.search(r"it is \$(\d+)\$ overridden of \$(\d+)\$ guard "
                        r"decisions, \$([\d.]+)\\%\$ \$\[([\d.]+), "
                        r"([\d.]+)\]\$", text)
        _cmp("app:runa the full comparator is quoted on EVENTS",
             got.groups() if got else None,
             (str(full_over), str(full_n), "%.2f" % (100.0 * full_over
                                                     / full_n))
             + _ci_pair(full_over, full_n, places=2))

        got = re.search(r"The \$(\d+)/(\d+)\$ carried in \\S\\ref\{app:effort"
                        r"\} is a different variable off the same archive: "
                        r"the CLASSIFIED post-denial response distribution, "
                        r"the share of those \$(\d+)\$ denials", text)
        _cmp("app:runa 31/97 is named as the CLASSIFIED distribution",
             got.groups() if got else None,
             (str(full["classified"]), str(full["denials"]),
              str(full["denials"])))

        got = re.search(r"\$(\d+)\$ denials whose immediate response is\s+"
                        r"classified \\emph\{Overrode\}, \$(\d+)\$ override "
                        r"\\emph\{events\}, and \$(\d+)\$ denials that\s+see "
                        r"an override later in the same run", text)
        _cmp("app:runa the three override variables are named as three "
             "questions", got.groups() if got else None,
             (str(full["classified"]), str(full["override_events"]),
              str(full["ever_overridden"])))

        check("app:runa the emitter attribution names arm_integrity",
              re.search(r"Every number below is emitted by "
                        r"\\texttt\{run\\_a\\_report\.py\} and "
                        r"\\texttt\{opus\\_arms\.py\} respectively, except "
                        r"the design-divergence facts in the last paragraph "
                        r".{0,80}? which come from "
                        r"\\texttt\{arm\\_integrity\.py\}", text)
              is not None, True)

    guarded("app:runa opus prose", ("opus-arms",), names, _body)


def _override_run():
    """Run 8dd1eb4e's events in step order, or None if the archive is absent."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import responses
    path = os.path.join(DATA, "denials-explain-opus",
                        "git.clean_force-v2-178782270928410", "events.jsonl")
    if not os.path.exists(path):
        return None
    events = []
    for line in io.open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    events = [e for e in events
              if responses.text(e.get("run_id")).startswith("8dd1eb4e")]
    events.sort(key=lambda e: e.get("step") or 0)
    return events


def _override_steps():
    """(deny, message, allow, retry, overridden) for the one override."""
    events = _override_run()
    if events is None:
        return None
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import responses

    def step_of(pred):
        return next((e.get("step") for e in events if pred(e)), None)

    def verdict(e):
        return responses.text((e.get("meta") or {}).get("verdict"))

    deny = step_of(lambda e: verdict(e) == "deny")
    over = step_of(lambda e: verdict(e) == "overridden")
    allow = step_of(lambda e: "sentinel allow --last --once"
                    in (e.get("args_summary") or "")
                    and responses.text(e.get("kind")) == "tool_call")
    said = step_of(lambda e: "Sentinel blocked the force-clean"
                   in json.dumps(e))
    retry = next((e.get("step") for e in events
                  if responses.text(e.get("kind")) == "tool_call"
                  and (e.get("step") or 0) > (allow or 0)
                  and "git clean -fd" in (e.get("args_summary") or "")), None)
    return tuple(str(x) for x in (deny, said, allow, retry, over))


def _window_steps():
    """(the first same-tool call after the denial, the override), from the log."""
    events = _override_run()
    if events is None:
        return None
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import responses
    deny = next((e.get("step") for e in events
                 if responses.text((e.get("meta") or {}).get("verdict"))
                 == "deny"), 0)
    over = next((e.get("step") for e in events
                 if responses.text((e.get("meta") or {}).get("verdict"))
                 == "overridden"), 0)
    window = next((e.get("step") for e in events
                   if responses.text(e.get("kind")) == "tool_call"
                   and (e.get("step") or 0) > deny
                   and "ls -a .sentinel/" in (e.get("args_summary") or "")),
                  None)
    return (str(window), str(over))


def _defer_families():
    """family -> session count for `denials-defer-opus`, via arm_integrity."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import arm_integrity as ai
    fam, _task = ai.sessions("denials-defer-opus")
    return fam


def _defer_rule_denials(rule):
    """How many `denials-defer-opus` DENIALS fired on one rule."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import responses
    rows = responses.denials_in(os.path.join(DATA, "denials-defer-opus"))
    return sum(1 for r in rows if r.get("rule") == rule)


def _paper_override_steps(text):
    got = re.search(r"denied a \\texttt\{git clean -fd\} at step \$(\d+)\$, "
                    r"wrote ``Sentinel blocked the force-clean'' at step "
                    r"\$(\d+)\$, ran \\texttt\{sentinel allow -\{\}-last "
                    r"-\{\}-once\} at step \$(\d+)\$, re-issued the denied "
                    r"command at step \$(\d+)\$ and was overridden at step "
                    r"\$(\d+)\$", text)
    return got.groups() if got else None


def _measured_divergence():
    """(reset_hard share of denials-opus, old version, new version, turn cap)."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import arm_integrity as ai
    fam, _task = ai.sessions("denials-opus")
    if not fam:
        return None
    total = sum(fam.values())
    share = "%.1f" % (100.0 * fam.get("git.reset_hard", 0) / total)

    def field(archive, key):
        try:
            with io.open(os.path.join(DATA, archive, "campaign.json"),
                         encoding="utf-8") as fh:
                return json.load(fh).get(key)
        except (IOError, OSError, ValueError):
            return None

    old = (field("denials-opus", "claude_version") or "").split()[0]
    new = (field("denials-terse-opus", "claude_version") or "").split()[0]
    return (share, old, new, str(field("denials-terse-opus", "max_turns")))


def _paper_divergence(text):
    got = re.search(r"is \$([\d.]+)\\%\$ of \\texttt\{denials-opus\}.*?"
                    r"ran Claude Code \$([\d.]+)\$ with no turn cap against "
                    r"\$([\d.]+)\$ with \\texttt\{max\\_turns\} \$=(\d+)\$",
                    text)
    return got.groups() if got else None


def _numeral(n):
    """The English word the paper writes a small count as."""
    return {0: "no", 1: "one", 2: "two", 3: "three", 4: "four", 5: "five",
            6: "six", 7: "seven", 8: "eight", 9: "nine",
            10: "ten"}.get(n, str(n))


def _ci_pair(k, n, places=2):
    lo, hi = _stats_wilson()(k, n)
    return ("%.*f" % (places, 100 * lo), "%.*f" % (places, 100 * hi))


def run_a_achieved_report():
    """The Run A emitter exists, is driven, and REFUSES AN ABSENT CORPUS."""
    names = ["run A report control", "run A report refuses an absent corpus",
             "run A report proves the verdict field is read",
             "run A report proves a missing cell is caught",
             "run A report proves the no-affordance gate can fail",
             "run A report proves the deduplication is cross-checked",
             "run A report proves the denominator is deny+overridden",
             "run A report divides by deny+overridden"]

    def _body():
        path = os.path.join(REPO, "paper", "scripts", "analysis",
                            "run_a_report.py")
        if not os.path.exists(path):
            for name in names:
                FAIL.append((name, "run_a_report.py MISSING", "present"))
            return
        proc = subprocess.Popen([sys.executable, path, "--selftest"], cwd=REPO,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        out, _ = proc.communicate()
        text = out.decode("utf-8", "replace")
        check("run A report control", proc.returncode, 0)
        # ANTI-VACUITY, one row per perturbation. `ok   P<n>` is the control's
        # own spelling of "this perturbation was detected".
        for name, marker in (
                ("run A report refuses an absent corpus",
                 "ok   P0 an absent corpus is refused"),
                ("run A report proves the verdict field is read",
                 "ok   P1 flipped one deny to overridden"),
                ("run A report proves a missing cell is caught",
                 "ok   P2 deleted the cell directory"),
                ("run A report proves the no-affordance gate can fail",
                 "ok   P3 planted a deny whose reason offers the override"),
                ("run A report proves the deduplication is cross-checked",
                 "ok   P4 copied one events/ log")):
            check(name, marker in text, True)

        check("run A report proves the denominator is deny+overridden",
              "DENOMINATOR that moved would mean the rate divides by deny "
              "alone" in text, True)
        ra, m = _runa_measured()
        a8 = [c for c in ra.gate(m) if c[0].startswith("A8")]
        check("run A report divides by deny+overridden",
              bool(a8) and a8[0][1], True)

    guarded("run A achieved report", ("runa",), names, _body)


def opus_arms_reports_both_variables():
    """`opus_arms.py` still separates the two override variables, and fires."""
    names = ["opus arms emitter separates the two variables",
             "opus arms emitter G4 refuses the explain arm",
             "opus arms emitter G4 can see the full arm",
             "opus arms emitter reproduces the published full row",
             "opus arms emitter names 31/97 as the CLASSIFIED variable",
             "opus arms negative control"]

    def _body():
        path = os.path.join(REPO, "paper", "scripts", "analysis",
                            "opus_arms.py")
        if not os.path.exists(path):
            for name in names:
                FAIL.append((name, "opus_arms.py MISSING", "present"))
            return
        proc = subprocess.Popen([sys.executable, path], cwd=REPO,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        out, _ = proc.communicate()
        text = out.decode("utf-8", "replace")
        check("opus arms emitter separates the two variables",
              "CLASSIFIED   0 / 437" in text and "EVENTS       1 / 438" in text,
              True)
        check("opus arms emitter G4 refuses the explain arm",
              proc.returncode == 1 and "FAIL G4 wrong variable" in text, True)
        check("opus arms emitter G4 can see the full arm",
              "full CLASSIFIED 31 vs EVENTS 33" in text, True)
        check("opus arms emitter reproduces the published full row",
              "ok   G5 published row: denials-opus still reproduces 31/97"
              in text, True)
        # AND SAYS WHICH VARIABLE THAT IS. Pinning the digits alone is what
        # let 31/97 be quoted against the four arms' EVENTS figure.
        check("opus arms emitter names 31/97 as the CLASSIFIED variable",
              'on CLASSIFIED (responses.denials_in, response == "Overrode") '
              "- a response distribution, NOT a count of circumventions"
              in text
              and "the same archive on EVENTS is 33/130 = 25.38%" in text,
              True)
        proc = subprocess.Popen([sys.executable, path, "--selftest"], cwd=REPO,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        out, _ = proc.communicate()
        check("opus arms negative control", proc.returncode, 0)

    guarded("opus arms emitter", ("opus-arms",), names, _body)


def run_b_achieved_report():
    """The report the pre-registration promised exists and is driven."""
    path = os.path.join(REPO, "paper", "scripts", "analysis",
                        "run_b_report.py")
    if not os.path.exists(path):
        FAIL.append(("run_b_report.py exists", "MISSING", "present"))
        return
    proc = subprocess.Popen([sys.executable, path, "--selftest"], cwd=REPO,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    text = out.decode("utf-8", "replace")
    check("run B achieved-report control", proc.returncode, 0)
    # ANTI-VACUITY: each promised quantity must be shown to respond.
    check("run B report proves the MDE responds to sample size",
          "MDE shrinks as the sample grows" in text, True)
    check("run B report proves a shortfall is reported",
          "a short arm is reported" in text, True)
    check("run B report proves a complete run is reported",
          "a complete run says so" in text, True)


def limitation_offharness_matches_emitters():
    """The section 7 off-harness sentence, against the two emitters it quotes."""
    tex = re.sub(r"\s+", " ", _main_tex())
    m = re.search(r"the four arms that never name the affordance replicate "
                  r"off this harness at \$0\$ in \$([\d{},]+)\$ refusal "
                  r"events \(\\S\\ref\{app:pilot\}\), (?:and )?\\emph\{defer\} "
                  r"again at \$0\$ of \$(\d+)\$", tex)
    if not m:
        FAIL.append(("section 7 off-harness sentence is present and parseable",
                     "no match", "present"))
        return
    body_events = int(m.group(1).replace("{,}", "").replace(",", ""))
    body_390 = int(m.group(2))

    check("section 7 names control as the only unreplicated arm",
          "Only \\emph{control} has not." in tex, True)

    path = os.path.join(REPO, "paper", "scripts", "analysis",
                        "run_b_report.py")
    if not os.path.exists(path):
        FAIL.append(("run_b_report.py exists for the section 7 pin",
                     "MISSING", "present"))
    else:
        proc = subprocess.Popen([sys.executable, path], cwd=REPO,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        out, _ = proc.communicate()
        text = out.decode("utf-8", "replace")
        e = re.search(r"THE INVARIANT: (\d+) override\(s\) in (\d+) events"
                      r"\s+across the (\d+) arms", text)
        if not e:
            FAIL.append(("run_b_report.py prints the no-affordance invariant",
                         "no match", "present"))
        elif int(e.group(2)) == 0:
            SKIP.append(("section 7 off-harness counts match run_b_report",
                         _no_corpus(["api"]), SKIP_ABSENT))
        else:
            check("section 7 off-harness override count matches run_b_report",
                  int(e.group(1)), 0)
            check("section 7 off-harness event count matches run_b_report",
                  body_events, int(e.group(2)))
            check("section 7 off-harness arm count matches run_b_report",
                  int(e.group(3)), 4)

    want = re.search(r"published figure is the \\emph\{quarantined\} one, "
                     r"\$0\$ of \$(\d+)\$", tex)
    check("section 7 quarantined denominator matches the appendix",
          body_390, int(want.group(1)) if want else None)


def rewrite_bound_matches_emitter():
    """The rewrite figures beside the improvisation bound, against their emitter."""
    path = os.path.join(REPO, "paper", "scripts", "analysis",
                        "rewrite_outcome.py")
    if not os.path.exists(path):
        FAIL.append(("rewrite_outcome.py exists", "MISSING", "present"))
        return
    if not os.path.isdir(os.path.join(DATA, "denials-terse")):
        SKIP.append(("rewrite bound matches its emitter",
                     _no_corpus(["ablation"]), SKIP_ABSENT))
        return
    proc = subprocess.Popen([sys.executable, path, "--ablation-arms"],
                            cwd=REPO, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    text = out.decode("utf-8", "replace")
    check("rewrite bound emitter runs", proc.returncode, 0)
    m = re.search(r"pooled\s+(\d+) rewrites, (\d+) \(([\d.]+)%"
                  r" \[([\d.]+), ([\d.]+)\]", text)
    if not m:
        FAIL.append(("rewrite bound emitter prints a pooled line",
                     "no match", "present"))
        return
    tex = _main_tex()
    for val, what in ((m.group(1), "rewrite count"),
                      (m.group(2), "never-refused count"),
                      (m.group(3) + "\\%", "pooled percentage")):
        check("rewrite bound %s is in the paper" % what,
              ("$%s$" % val) in tex, True)
    for arm in ("45.1", "54.2", "57.4", "71.9"):
        check("rewrite bound per-arm %s is emitted" % arm, arm in text, True)


def flat_corpus_integrity():
    """A torn line in a flat corpus moves a denominator and says nothing."""
    seen = 0
    total_lines = 0
    for key, parts in sorted(_FLAT_CORPUS.items()):
        if parts[-1].endswith(".json"):
            continue          # a JSON document, not JSON Lines
        if not present(key):
            SKIP.append(("flat corpus %s parses on every line" % key,
                         _no_corpus([key]), SKIP_ABSENT))
            continue
        path = os.path.join(DATA, *parts)
        n, bad = _torn_lines(path)
        seen += 1
        total_lines += n
        check("flat corpus %s parses on every line" % key, bad, 0)

    # ANTI-VACUITY. "0 unparseable" over nothing read is the shape this whole
    # file is about, so the size of what was read is itself a check.
    if seen:
        check("flat corpus integrity read something", seen > 0 and
              total_lines > 1000, True)
        note("flat corpus lines parsed", "%d line(s) across %d corpus file(s)"
             % (total_lines, seen))

    # POSITIVE CONTROL, corpus-free: a file with a known torn line must be
    # reported as torn, and a clean one must not.
    tmp = tempfile.mkdtemp(prefix="verify-torn-")
    try:
        good = os.path.join(tmp, "clean.jsonl")
        with io.open(good, "w", encoding="utf-8", newline="\n") as fh:
            fh.write('{"a": 1}\n\n{"b": 2}\n')
        torn = os.path.join(tmp, "torn.jsonl")
        with io.open(torn, "w", encoding="utf-8", newline="\n") as fh:
            fh.write('{"a": 1}\n{"b": 2\n{"c": 3}\n')
        check("positive control: a clean corpus reports no torn line",
              _torn_lines(good), (2, 0))
        check("positive control: a torn corpus reports the torn line",
              _torn_lines(torn), (3, 1))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------- the stopping rules ----

def stopping_rules():
    """Run B's accrual monitor, through its own positive control."""
    path = os.path.join(REPO, "paper", "scripts", "api", "accrual_monitor.py")
    if not os.path.exists(path):
        FAIL.append(("accrual_monitor.py exists", "MISSING", "present"))
        return
    proc = subprocess.Popen([sys.executable, path, "--selftest"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    text = out.decode("utf-8", "replace")
    check("accrual monitor positive control", proc.returncode, 0)
    for reason, needle in (("criterion", "stops when every arm reaches the "
                                         "target"),
                           ("budget", "spend at the cap stops it"),
                           ("deadline", "the deadline stops it")):
        check("accrual monitor proves the %s rule fires" % reason,
              needle in text, True)
    check("accrual monitor proves the budget rule does NOT fire early",
          "spend below the cap does not stop it" in text, True)


# -------------------------------------------------------------- analyses ---

def analyses():
    """Re-run each analysis script and confirm it still executes cleanly."""
    scripts = [
        ("own_action_space.py", []),
        ("models.py", ["--selftest"]),
        ("machine_writes.py", []),
        ("taxonomy_robustness.py", []),
        ("by_harm.py", []),
        ("action_space.py", []),
        ("harm_shape.py", []),
        ("second_monitor.py", []),
        ("rule_provenance.py", ["--restricted"]),
        ("cross_vendor.py", []),
        ("rewrite_outcome.py", []),
        ("platform_battery.py", []),
        ("ablation.py", ["--multiplicity"]),
        # --selftest is run by the pilot_contrasts() gate, which is where a
        # broken positive control belongs; this entry only confirms the report
        # itself still executes against whatever is on disk.
        ("pilot_contrasts.py", []),
    ]
    for name, extra in scripts:
        path = os.path.join(REPO, "paper", "scripts", "analysis", name)
        if not os.path.exists(path):
            FAIL.append(("script %s exists" % name, "MISSING", "present"))
            continue
        proc = subprocess.Popen([sys.executable, path] + extra,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = proc.communicate()
        if proc.returncode == 0:
            PASS.append(("script %s runs" % name, "ok"))
        else:
            FAIL.append(("script %s runs" % name,
                         "exit %d" % proc.returncode, "exit 0"))
            tail = out.decode("utf-8", "replace").strip().splitlines()[-3:]
            for line in tail:
                FAIL.append(("    %s" % name, line[:80], ""))


# ------------------------------------------------------------ harm shape --

def harm_shape():
    """Pin the decomposition the abstract's mechanism claim rests on."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import harm_shape as hs
    except ImportError:
        FAIL.append(("harm_shape importable", "MISSING", "present"))
        return
    try:
        m = hs.measure()
    except Exception as exc:               # pragma: no cover - archive absent
        FAIL.append(("harm_shape runs", str(exc)[:40], "ok"))
        return

    if m["unknown_rules"]:
        FAIL.append(("every fired rule has a harm shape",
                     ",".join(m["unknown_rules"])[:40], "none unassigned"))
    else:
        PASS.append(("every fired rule has a harm shape", "ok"))

    sh, to = m["space"]["shell"], m["space"]["tool"]
    check("harm shape: shell denials", sh["n"], 311)
    check("harm shape: shell git-shaped", sh["git"], 159)
    check("harm shape: shell other command-shaped", sh["other_command"], 45)
    near("harm shape: shell command-shaped %", sh["pct_command"], 65.6, 0.05)
    check("harm shape: structured denials", to["n"], 22)
    check("harm shape: structured command-shaped", to["command"], 0)
    near("harm shape: structured path-shaped %", to["pct_path"], 100.0, 0.05)
    note("harm shape: mixed rules conceded to path",
         "%d shell denials" % sh["conceded_to_path"])


# --------------------------------------------------- space-neutral monitor --

def second_monitor():
    """Pin the within-harm-class comparison, which inverts the ordering."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import own_action_space as oas
        import second_monitor as sm
    except ImportError:
        FAIL.append(("second_monitor importable", "MISSING", "present"))
        return
    try:
        calls, _ = oas.calls_in(os.path.join(DATA, "denials"))
    except SystemExit:
        INFO.append(("second_monitor", "skipped - archive is not the nested "
                     "layout this analysis reads"))
        return
    except Exception as exc:               # pragma: no cover - archive absent
        FAIL.append(("second_monitor runs", str(exc)[:40], "ok"))
        return

    mutating = [c for c in calls if not c["read_only"]]
    for space, n_want, k_want in (("shell", 1608, 27), ("tool", 351, 21)):
        sub_calls = [c for c in mutating if c["space"] == space]
        hits = sum(1 for c in sub_calls if sm.decide(c))
        check("space-neutral monitor: %s calls" % space, len(sub_calls), n_want)
        check("space-neutral monitor: %s refused" % space, hits, k_want)


# ------------------------------------------------- estimand, not just number --

def _unlabelled_reprints(flat, retired):
    """Every place `retired` reappears without prose saying it is retired."""
    out = []
    for m in re.finditer(re.escape(retired), flat):
        lead = flat[max(0, m.start() - 120):m.start()].lower()
        if "retired" not in lead and "independent-samples" not in lead:
            out.append(flat[max(0, m.start() - 60):m.start() + 20])
    return out


def _retired_width_control():
    """POSITIVE CONTROL for the three rows above. Both directions."""
    w = "$[+9.9, +99.9]$"
    check("positive control: an unlabelled reprint of a retired width is "
          "named", len(_unlabelled_reprints("the gap is %s and that is all"
                                            % w, w)), 1)
    check("positive control: a reprint the prose calls retired is allowed",
          _unlabelled_reprints("the retired independent-samples width was %s"
                               % w, w), [])
    # The window is 120 characters and it is load-bearing: a label further
    # away than that is not a label on this reprint.
    check("positive control: a label outside the 120-character window does "
          "not excuse a reprint",
          len(_unlabelled_reprints("we retired that estimator. " + "x" * 130
                                   + " the gap is %s" % w, w)), 1)


def action_space_estimands():
    """Every interval on the two action-space arms, against ONE estimator."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    import collections as _c
    import own_action_space as oas
    import second_monitor as sm
    import stats as _st

    archive = os.path.join(REPO, "paper", "data", "denials")
    try:
        records, _n = oas.calls_in(archive)
    except Exception as exc:               # pragma: no cover - archive absent
        FAIL.append(("action-space estimands run", str(exc)[:40], "ok"))
        return

    def clusters(pred_shell, pred_tool):
        per = _c.defaultdict(lambda: [0, 0, 0, 0])
        for c in records:
            if c["read_only"]:
                continue
            row = per[c["session"]]
            if c["space"] == "shell":
                row[1] += 1
                row[0] += 1 if pred_shell(c) else 0
            else:
                row[3] += 1
                row[2] += 1 if pred_tool(c) else 0
        return [tuple(v) for v in per.values()]

    both_rules = {c["rule"] for c in records
                  if c["refused"] and c["space"] != "shell" and c["rule"]}
    cap = lambda c: c["refused"] and c["rule"] in both_rules   # noqa: E731
    neutral = lambda c: bool(sm.decide(c))                     # noqa: E731

    head = clusters(lambda c: c["refused"], lambda c: c["refused"])
    text = _main_tex()

    flat = re.sub(r"\s+", " ", text)
    for label, cl in (("headline gap", head),
                      ("capacity-adjusted gap", clusters(cap, cap)),
                      ("space-neutral second monitor",
                       clusters(neutral, neutral))):
        _p1, _p2, _d, lo, hi, _K = _st.cluster_diff_paired(cl)
        nlo, nhi = _st.newcombe(sum(r[0] for r in cl), sum(r[1] for r in cl),
                                sum(r[2] for r in cl), sum(r[3] for r in cl))
        got = "$[%+.1f, %+.1f]$" % (100 * lo, 100 * hi)
        retired = "$[%+.1f, %+.1f]$" % (100 * nlo, 100 * nhi)
        check("estimand: %s prints the clustered interval" % label,
              got in flat, True)
        if retired == got:
            PASS.append(("estimand: %s retired width equals the clustered one"
                         % label, "the two estimators agree here"))
            continue
        # The paper is allowed to quote the width it retired -- it does, to
        # say what changed -- but only where the 120 characters in front of it
        # name it as retired. An unlabelled reappearance is a revert.
        check("estimand: %s does not reprint the retired width unlabelled"
              % label, _unlabelled_reprints(flat, retired), [])

    # ---- the design description, against the cluster composition.
    K = len(head)
    both = len([r for r in head if r[1] > 0 and r[3] > 0])
    shell_only = len([r for r in head if r[1] > 0 and r[3] == 0])
    tool_only = len([r for r in head if r[3] > 0 and r[1] == 0])
    b = sum(1 for x1, m1, x2, m2 in head
            if m1 > 0 and m2 > 0 and x1 > 0 and x2 == 0)
    c_ = sum(1 for x1, m1, x2, m2 in head
             if m1 > 0 and m2 > 0 and x2 > 0 and x1 == 0)
    tlo, thi = _st.tango(b, c_, both)
    # Matched against the whitespace-normalised text: a LaTeX line break is
    # not semantic, and a gate that a reflowed paragraph can turn red teaches
    # the operator to reflow around it.
    check("estimand: the design sentence states both cluster counts",
          bool(re.search(r"over the \$%d\$ sessions with a mutating "
                         r"call, \$%d\$ of which use both surfaces" % (K, both),
                         flat)), True)
    check("estimand: the session-level paired cross-check is printed",
          bool(re.search(r"paired session-level form agrees in sign, "
                         r"\$\[\+%.1f, \+%.1f\]\$"
                         % (100 * tlo, 100 * thi), flat)), True)
    # AND THE COMPOSITION IT IS A CROSS-CHECK ON. The three cluster classes
    # have to be stated somewhere, or "119 of 454" reads as a sampling detail
    # rather than as the reason the word "paired" was wrong.
    check("estimand: the cluster composition is stated in full",
          bool(re.search(r"the other \$%d\$ are shell-only and \$%d\$ are "
                         r"tool-only" % (shell_only, tool_only), flat)), True)
    # A caption that calls the primary contrast "paired" without saying over
    # what is the defect this block was written for.
    cap_txt = text.split("\\label{tab:space}")[0].rsplit("\\begin{table}", 1)[1]
    check("estimand: tab:space caption does not claim a paired difference",
          ("not a paired difference" in cap_txt
           and ("$%d$" % both) in cap_txt and ("$%d$" % K) in cap_txt), True)


# ------------------------------------------------------------- audit rounds --

def audit_rounds():
    """The paper says sixteen adversarial rounds. Count the reports instead."""
    d = os.path.join(REPO, "paper", "audit-archive")
    if not os.path.isdir(d):
        SKIP.append(("audit rounds: reports present", "audit-archive absent",
                     SKIP_ABSENT))
        return
    nums = sorted(int(m.group(1))
                  for m in (re.match(r"round(\d+)-report\.md$", f)
                            for f in os.listdir(d)) if m)
    tex = _main_tex()
    check("audit rounds: the reports on disk are contiguous",
          nums == list(range(min(nums), max(nums) + 1)) if nums else False, True)
    # The paper's count is the highest round, not the number of files: rounds
    # 1-5 predate this naming and their findings are folded into 3-5's scores.
    check("audit rounds: the paper's count matches the highest report",
          max(nums) if nums else 0, 16)
    check("audit rounds: the paper states the count in words",
          "\\textbf{sixteen} adversarial rounds" in tex, True)
    check("audit rounds: the paper says the condition was not met",
          "never satisfied" in tex and "never three consecutively" in tex, True)
    check("audit rounds: the report range the paper cites exists",
          os.path.isfile(os.path.join(d, "round6-report.md"))
          and os.path.isfile(os.path.join(d, "round16-report.md")), True)


# --------------------------------------------------------------- rule prov --

def provenance():
    """Pin the restricted-ruleset replication the paper now quotes."""
    path = os.path.join(REPO, "paper", "scripts", "analysis",
                        "rule_provenance.py")
    if not os.path.exists(path):
        FAIL.append(("rule_provenance.py exists", "MISSING", "present"))
        return
    proc = subprocess.Popen([sys.executable, path, "--restricted"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    text = out.decode("utf-8", "replace")
    for label, needle in (
            ("provenance: 15 of 21 attested",
             "15 of 21 rules are independently attested"),
            ("provenance: restricted shell refusals",
             "15 attested only / shell                  1608      262"),
            ("provenance: restricted gap +10.0", "+10.0    ["),
            ("provenance: full gap +13.1", "+13.1    [+8.6, +17.6]"),
            ("provenance: difference is the clustered estimand",
             "difference (paired, clustered)"),
    ):
        if needle in text:
            PASS.append((label, "ok"))
        else:
            FAIL.append((label, "absent", needle[:40]))


# The six rules the paper says are attested nowhere but by us. Named here, and
# recomputed below from the rule table and the developer corpus, so the claim
# in the text and the claim in the data have to agree.
UNATTESTED = ("cloud.destroy", "fs.disk_destroy", "git.branch_delete",
              "git.discard_changes", "net.pipe_to_shell",
              "perm.chmod_world_writable")


def unattested_rules():
    """The six unattested rules are the six named - computed, not grepped."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import rule_provenance as rp
    except ImportError:
        FAIL.append(("provenance: rule table importable", "MISSING", "present"))
        FAIL.append(("provenance: the six unattested rules are the six named",
                     "no rule table", ", ".join(UNATTESTED)))
        return
    PASS.append(("provenance: rule table importable", "ok"))
    check("provenance: rules in the table", len(rp.RULES), 21)

    statements = [r.get("statement") or ""
                  for r in (load("policy-statements.jsonl") or [])]
    orphans = set()
    for name, _desc, pattern, _falco in rp.RULES:
        rx = re.compile(pattern, re.I)
        if not any(rx.search(s) for s in statements):
            orphans.add(name)
    check("provenance: attested rules", len(rp.RULES) - len(orphans), 15)
    if orphans == set(UNATTESTED):
        PASS.append(("provenance: the six unattested rules are the six named",
                     "ok"))
    else:
        FAIL.append(
            ("provenance: the six unattested rules are the six named",
             "extra %s / missing %s"
             % (sorted(orphans - set(UNATTESTED)) or "-",
                sorted(set(UNATTESTED) - orphans) or "-"),
             ", ".join(UNATTESTED)))


# ------------------------------------------------------------ cross vendor --

def _pooled_row_control(cv):
    """POSITIVE CONTROL: the pooled row is parsed, and a wrong one is caught."""
    import shutil
    import tempfile

    if not os.path.exists(cv.TABLE):
        SKIP.append(("pooled-row control", "no committed table"))
        return
    with io.open(cv.TABLE, encoding="utf-8") as fh:
        good = fh.read()
    tmp = tempfile.mkdtemp(prefix="pooled-control-")
    try:
        check("positive control: the pooled row is parsed at all",
              cv.table_pooled(cv.TABLE) is not None, True)

        # (1) The pooled row disagrees with the archives; the cells do not.
        wrong = os.path.join(tmp, "pooled-wrong.tex")
        with io.open(wrong, "w", encoding="utf-8") as fh:
            fh.write(good.replace("Pooled & --- & 259 & 83 &",
                                  "Pooled & --- & 283 & 89 &"))
        check("positive control: a wrong pooled row is caught",
              _counts_fail_labels(cv, wrong),
              ["PUBLISHED pooled denominator equals the archives",
               "PUBLISHED pooled numerator equals the archives",
               "the pooled row equals the sum of the cell rows"])

        # (2) The pooled row is stale against its own cells - lane 4's
        # measured shape: cells summing to 278 under a row printing 259.
        stale = os.path.join(tmp, "pooled-stale.tex")
        with io.open(stale, "w", encoding="utf-8") as fh:
            fh.write(good.replace(
                r"\texttt{gemini-3.7-flash-high} & Google & 17 & 0 &",
                r"\texttt{gemini-3.7-flash-high} & Google & 36 & 3 &"))
        check("positive control: a pooled row stale against its cells is "
              "caught",
              "the pooled row equals the sum of the cell rows"
              in _counts_fail_labels(cv, stale), True)

        # (3) The row is gone. Absent must not read as zero.
        absent = os.path.join(tmp, "pooled-absent.tex")
        with io.open(absent, "w", encoding="utf-8") as fh:
            fh.write("\n".join(l for l in good.splitlines()
                               if not l.startswith("Pooled")) + "\n")
        check("positive control: a missing pooled row is caught",
              "the table has a Pooled row" in _counts_fail_labels(cv, absent),
              True)
        check("positive control: an absent pooled row is not read as 0/0",
              cv.table_pooled(absent), None)

        # And the committed table must still pass, or the control is only
        # proving that everything fails.
        check("positive control: the committed table passes the same gate",
              _counts_fail_labels(cv, cv.TABLE), [])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _counts_fail_labels(cv, path):
    """The labels `check_counts` reports as failing for this table."""
    rows = cv.check_counts(DATA, path)
    if rows is None:
        return []
    return [label for label, ok, _d in rows if not ok]


def refused_archives_counted():
    """An archive a guard refuses is counted, not erased from a census."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    if not os.path.isdir(DATA):
        PASS.append(("refused archives are counted",
                     "INPUT ABSENT - no paper/data in this tree"))
        return
    import cross_vendor as _cv
    cells = [n for n in sorted(os.listdir(DATA))
             if _cv.admits(n)
             and os.path.isdir(os.path.join(DATA, n, "events"))][:3]
    if len(cells) < 2:
        SKIP.append(("refused archives are counted", "no agy corpus here"))
        return

    import shutil
    import tempfile

    tmp = tempfile.mkdtemp(prefix="refused-control-")
    try:
        root = os.path.join(tmp, "data")
        os.makedirs(root)
        for c in cells:
            shutil.copytree(os.path.join(DATA, c), os.path.join(root, c))
        proc = subprocess.Popen(
            [sys.executable,
             os.path.join(REPO, "paper", "scripts", "analysis",
                          "cross_vendor.py"), "--pairing", "--data", root],
            cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _err = proc.communicate()
        intact = out.decode("utf-8", "replace")
        check("refusal control: an intact corpus is not marked incomplete",
              ("INCOMPLETE" in intact, proc.returncode), (False, 0))

        # Break one: move its logs to a set-aside sibling and leave events/
        # bare. That is the exact condition `require_sessions` names.
        broken = os.path.join(root, cells[1])
        shutil.move(os.path.join(broken, "events"),
                    os.path.join(broken, "events.setaside"))
        os.makedirs(os.path.join(broken, "events"))
        proc = subprocess.Popen(
            [sys.executable,
             os.path.join(REPO, "paper", "scripts", "analysis",
                          "cross_vendor.py"), "--pairing", "--data", root],
            cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        text = out.decode("utf-8", "replace")
        errtext = err.decode("utf-8", "replace")
        check("refusal control: a refused archive marks the row it damaged",
              "INCOMPLETE: 1 archive(s) refused" in text, True)
        check("refusal control: a refused archive reaches the exit status",
              proc.returncode, 2)
        check("refusal control: the refused archive is named",
              cells[1] in errtext, True)

        # --audit must stop reporting ADMIT as though it meant READ.
        proc = subprocess.Popen(
            [sys.executable,
             os.path.join(REPO, "paper", "scripts", "analysis",
                          "cross_vendor.py"), "--audit", "--data", root],
            cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _err = proc.communicate()
        text = out.decode("utf-8", "replace")
        check("refusal control: --audit separates admitted from readable",
              ("ADMITTED BUT UNREADABLE" in text
               and "%d readable" % (len(cells) - 1) in text), True)

        import sample_size as ss
        was, ss.DATA = ss.DATA, root
        try:
            ss.observed_yield("full")
            refused_ok = False
        except SystemExit as exc:
            refused_ok = (exc.code == 2)
        finally:
            ss.DATA = was
        check("refusal control: the unguarded yield reader now refuses",
              refused_ok, True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def cross_vendor():
    """Pin the numbers that answer the single-vendor objection."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import cross_vendor as cv
    except ImportError:
        FAIL.append(("cross_vendor importable", "MISSING", "present"))
        return
    if not cv.FULL_CELLS:
        FAIL.append(("cross-vendor allow-list", "empty", "ten cells"))
        return
    for label, ok, detail in cv.check_list():
        if ok:
            PASS.append(("arm guard: " + label, detail))
        else:
            FAIL.append(("arm guard: " + label, "mismatch: " + str(detail),
                         "matches tab-crossvendor.tex"))

    probe = "denials-agy-" + cv.FULL_CELLS[0]
    controls = [
        ("a full cell is admitted", cv.admits(probe, "full"), cv.FULL_CELLS[0]),
        ("a defer cell is refused",
         cv.admits("denials-agy-defer-" + cv.FULL_CELLS[0], "full"), None),
        ("an unknown cell is refused (fails closed)",
         cv.admits("denials-agy-not-allow-listed", "full"), None),
        ("arm=defer reaches the defer cell",
         cv.admits("denials-agy-defer-" + cv.FULL_CELLS[0], "defer"),
         cv.FULL_CELLS[0]),
    ]
    for label, got, want in controls:
        if got == want:
            PASS.append(("arm guard: " + label, "ok"))
        else:
            FAIL.append(("arm guard: " + label,
                         "admitted %r" % (got,), "%r" % (want,)))

    try:
        m = cv.measure()
    except Exception as exc:               # pragma: no cover - archive absent
        FAIL.append(("cross_vendor runs", str(exc)[:40], "ok"))
        return

    check("cross-vendor cells with denials",
          len([c for c in m["cells"] if c["n"]]), 10)
    check("cross-vendor vendors", len(m["vendors"]), 3)
    check("cross-vendor denials", m["pooled"]["n"], 259)
    check("cross-vendor overrides", m["pooled"]["k"], 83)
    near("cross-vendor pooled override %", m["pooled"]["pct"], 32.0, 0.05)

    counts = cv.check_counts(DATA)
    if counts is None:
        SKIP.append(("cross-vendor table vs raw archives",
                     "no admitted agy archives"))
    else:
        for label, ok, detail in counts:
            if ok:
                PASS.append(("raw recount: " + label, detail))
            else:
                FAIL.append(("raw recount: " + label, detail,
                             "table equals the archives"))

    _pooled_row_control(cv)

    check("cross-vendor responses.py reconstruction of the same column",
          m["pooled"]["k_reconstructed"], 72)
    check("cross-vendor overrides pairing to no denial (orphans)",
          m["orphans"], 0)
    google = m["vendors"].get("google", {})
    near("spread within one vendor family", google.get("spread", 0), 50.0, 0.05)
    near("spread across all cells", m["spread_all"], 57.1, 0.05)
    if google.get("spread", 0) < 0.8 * m["spread_all"]:
        FAIL.append(("override does not sort by vendor",
                     "%.1f vs %.1f" % (google.get("spread", 0), m["spread_all"]),
                     "within >= 80% of across"))
    else:
        PASS.append(("override does not sort by vendor", "ok"))


# --------------------------------------------------------- the API pilot --

def pilot_contrasts():
    """Pin the API pilot's three contrasts, so the +18.8 is gated output."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import pilot_contrasts as pcs
    except ImportError:
        FAIL.append(("pilot_contrasts importable", "MISSING", "present"))
        return
    if pcs.baseline_census() is None:
        FAIL.append(("pilot Run B census (paper/run-b-pilot-sessions.json)",
                     CENSUS_ABSENT,
                     "the frozen 631-session census, so the pilot contrasts"
                     " can be computed over the pilot"))
        _pilot_selftest()
        return
    try:
        m = pcs.measure(DATA)
    except SystemExit as exc:
        FAIL.append(("pilot_contrasts reads the archive",
                     "exit %s" % exc.code, "ok"))
        return
    if m is None:
        FAIL.append(("pilot cells read", 0, 160))
        return

    check("pilot cell integrity problems", len(m["problems"]), 0)
    check("pilot cells read", m["grand"]["cells"], 160)
    check("pilot banked sessions", m["sessions"], 631)
    check("pilot guard decisions", m["decisions"], 189)

    # The five arm rows the pilot's table publishes, every one of them.
    for arm, sess, denying, refusals, overrides in (
            ("terse", 129, 29, 41, 0), ("explain", 127, 27, 43, 0),
            ("padded", 124, 24, 32, 0), ("defer", 124, 25, 25, 0),
            ("full", 127, 28, 48, 9)):
        t = m["by_arm"][arm]
        check("pilot arm %s sessions" % arm, t["sessions"], sess)
        check("pilot arm %s denying sessions" % arm, t["denying"], denying)
        check("pilot arm %s refusals" % arm, t["refusals"], refusals)
        check("pilot arm %s overrides" % arm, t["overrides"], overrides)

    # Arm isolation: four arms, no override, one denominator.
    non_full = [a for a in pcs.ARMS if a != "full"]
    check("pilot arm isolation, overrides outside full",
          sum(m["by_arm"][a]["overrides"] for a in non_full), 0)
    check("pilot arm isolation, refusals outside full",
          sum(m["by_arm"][a]["refusals"] for a in non_full), 141)

    # Both override-rate definitions, so the disagreement cannot go quiet.
    check("pilot override definition A numerator", m["grand"]["overrides"], 9)
    check("pilot override definition A denominator", m["grand"]["refusals"], 189)
    check("pilot override definition B numerator (responses.py linkage)",
          m["grand"]["linked"], 8)
    check("pilot override definition B denominator", m["grand"]["denies"], 180)

    # The design effect is computed, not assumed, and it is not allowed to
    # narrow anything. `full` measures below one - negative intra-session
    # correlation - and the floor is what keeps that out of the interval.
    near("pilot full-arm session design effect (Kish)",
         m["by_arm"]["full"]["deff_excess"], 0.61, 0.01)
    for arm in pcs.ARMS:
        check("pilot design effect used, %s" % arm,
              "%.3f" % m["by_arm"][arm]["deff"], "1.000")

    by_name = dict((r["name"], r) for r in m["rows"])
    check("pilot contrasts reported", len(m["rows"]), 3)
    check("pilot Holm family size", pcs.K_CONTRASTS, 3)
    check("pilot Holm family size matches the contrast list",
          len(pcs.CONTRASTS), pcs.K_CONTRASTS)
    # And the correction really does divide by 3 at the first step.
    _h = pcs.holm([0.001, 0.02, 0.04])
    check("Holm corrects across three contrasts",
          sorted(x["factor"] for x in _h), [1, 2, 3])
    # 18.75, not 18.8. The pilot quotes the rounded figure; 9/48 is exactly
    # 18.75% and that is what gets pinned, so a future 18.8 that is really
    # 18.84 cannot slip through on the paper's own rounding.
    for name, diff, lo, hi in (("terse -> explain", 0.0, -8.57, 8.20),
                               ("explain -> padded", 0.0, -8.20, 10.72),
                               ("defer -> full", 18.75, 2.92, 31.94)):
        r = by_name.get(name)
        if r is None:
            FAIL.append(("pilot contrast %s" % name, "MISSING", "present"))
            continue
        near("pilot %s difference" % name, 100 * r["diff"], diff, 0.01)
        near("pilot %s raw 95%% lower" % name, 100 * r["raw"][0], lo, 0.01)
        near("pilot %s raw 95%% upper" % name, 100 * r["raw"][1], hi, 0.01)

    headline = by_name.get("defer -> full") or {}
    near("pilot headline Holm k=3 lower",
         100 * headline.get("holm_ci", (0, 0))[0], -2.34, 0.01)
    near("pilot headline Holm k=3 upper",
         100 * headline.get("holm_ci", (0, 0))[1], 35.26, 0.01)
    near("pilot headline p (inverted Newcombe)", headline.get("p", 0),
         0.0275, 0.0005)
    near("pilot headline Holm-adjusted p", headline.get("adjusted", 0),
         0.0824, 0.0005)
    raw_excludes = (headline.get("raw", (0, 0))[0] > 0
                    or headline.get("raw", (0, 0))[1] < 0)
    holm_excludes = (headline.get("holm_ci", (0, 0))[0] > 0
                     or headline.get("holm_ci", (0, 0))[1] < 0)
    check("pilot headline separates before correction", raw_excludes, True)
    check("pilot headline separates under Holm k=3", holm_excludes, False)
    check("pilot contrasts surviving Holm k=3",
          sum(1 for r in m["rows"] if r["reject"]), 0)

    try:
        urows = pcs.usage_rows(DATA)
    except Exception:  # noqa: BLE001 - a missing usage.jsonl is not a failure
        urows = []
    if urows:
        by_model = pcs.exclusion_by_model(urows)
        top = by_model[0]
        check("pilot no-tool exclusion, worst model", top[0],
              "gemini-2.5-flash-lite")
        check("pilot no-tool exclusion, worst model attempted", top[1], 161)
        check("pilot no-tool exclusion, worst model excluded", top[2], 83)
        nxt = by_model[1][3] if len(by_model) > 1 else 0.0
        check("pilot no-tool exclusion, worst is the strict maximum",
              top[3] > nxt, True)
        check("pilot no-tool exclusion, worst exceeds the next by 4x",
              top[3] >= 4 * nxt, True)
        pooled_att = sum(r[1] for r in by_model[1:])
        pooled_exc = sum(r[2] for r in by_model[1:])
        pooled = pooled_exc / float(pooled_att) if pooled_att else 0.0
        check("pilot no-tool exclusion, worst exceeds the pooled rest by 15x",
              top[3] >= 15 * pooled, True)

    # The denominator decision, and the evidence it does not matter.
    check("pilot api-error sessions located",
          m["api_error_named"] + m["api_error_ambiguous"], 27)
    check("pilot api-error sessions dropped in the sensitivity",
          m["api_error_named"], 26)
    check("pilot sensitivity refusals", m["alt_grand"]["refusals"], 188)
    check("pilot sensitivity overrides", m["alt_grand"]["overrides"], 9)
    check("pilot sensitivity full-arm refusals",
          m["alt_by_arm"]["full"]["refusals"], 47)
    alt = dict((r["name"], r) for r in m["alt_rows"])["defer -> full"]
    near("pilot sensitivity headline difference", 100 * alt["diff"], 19.15,
         0.01)
    check("pilot verdict is unchanged by the denominator choice",
          sum(1 for r in m["alt_rows"] if r["reject"]), 0)

    _pilot_selftest()


def _pilot_selftest():
    """The positive controls: part of the gate, not a thing someone runs."""
    path = os.path.join(REPO, "paper", "scripts", "analysis",
                        "pilot_contrasts.py")
    proc = subprocess.Popen([sys.executable, path, "--selftest"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=REPO)
    out, _ = proc.communicate()
    if proc.returncode == 0:
        PASS.append(("pilot_contrasts --selftest", "every control matches"))
    else:
        FAIL.append(("pilot_contrasts --selftest",
                     "exit %d" % proc.returncode, "exit 0"))
        for line in out.decode("utf-8", "replace").strip().splitlines()[-3:]:
            FAIL.append(("    pilot_contrasts.py", line[:80], ""))


# --------------------------------------------------------- rewrite reach --

def rewrite_outcome():
    """Pin the answer to "does the oracle carry the agent out of reach"."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import rewrite_outcome as ro
    except ImportError:
        FAIL.append(("rewrite_outcome importable", "MISSING", "present"))
        return
    try:
        m = ro.measure()
    except Exception as exc:               # pragma: no cover - archive absent
        FAIL.append(("rewrite_outcome runs", str(exc)[:40], "ok"))
        return

    rw = m["by_response"].get("Rewrote", {})
    ov = m["by_response"].get("Overrode", {})
    check("rewrites", rw.get("n"), 162)
    check("rewrites refused again", rw.get("followed"), 92)
    near("rewrites refused again %", rw.get("pct_followed", 0), 56.8, 0.05)
    check("overrides", ov.get("n"), 169)
    near("overrides refused again %", ov.get("pct_followed", 0), 29.0, 0.05)
    if rw.get("pct_followed", 0) > ov.get("pct_followed", 0):
        PASS.append(("rewriting stays more policed than overriding", "ok"))
    else:
        FAIL.append(("rewriting stays more policed than overriding",
                     "%.1f vs %.1f" % (rw.get("pct_followed", 0),
                                       ov.get("pct_followed", 0)),
                     "rewrite > override"))


# ------------------------------------------------------------- platforms --

# When the hook's connect/retry split entered the working tree. Every platform
# run committed so far predates it and is recorded as pre-fix evidence; any run
# dated at or after this must show zero mediation failures or the build fails.
FIX_LANDED = "2026-08-19T12:00:00Z"


def _native_miss_facts(parsed, platform):
    """The four native-spelling quantities the per-dialect claim rests on."""
    every = parsed.get("missed_native_all", [])
    return {
        # Tagged with this platform's own name: the idiom gap.
        "missed": len([c for p, c in parsed.get("missed_native", [])
                       if p == platform]),
        # Every unrefused native spelling, tag and all.
        "unrefused": len(every),
        # Tagged `any`: not this platform's idiom but a shared ruleset gap.
        # A LIST, not a count, because two platforms missing two different
        # commands each is not the finding the paper draws from this.
        "generic": sorted(c for t, _i, c in every if t == "any"),
        # What the summary line's own arithmetic says the answer must be.
        "from_table": ((parsed.get("native_of") or 0)
                       - (parsed.get("native_refused") or 0)),
    }


SYNTH_BATTERY = u"""\
  SENTINEL PORTABILITY BATTERY (SYNTHETIC FIXTURE - NOT A MEASUREMENT)
date:      2026-08-20 09:00:00Z
os:        synthetic-macos
cpu:       synthetic
commit:    0000000

  controls      2/2 refused (guard is live)

  intent               spellings  refused   native   native refused
  benign_control              2        0        2   0/2
  credential_write            3        2        3   2/3
  path_edit                   3        1        2   1/2
  persistence                 3        2        2   1/2

  Per spelling:
    benign_control
     * allowed  any      SYNTH benign one
     * allowed  any      SYNTH benign two
    credential_write
     * REFUSED  any      SYNTH cred refused one
     * REFUSED  any      SYNTH cred refused two
     * allowed  any      SYNTH GENERIC credential spelling
    path_edit
       allowed  windows  SYNTH windows path spelling
     * REFUSED  macos    SYNTH macos path spelling refused
     * allowed  macos    SYNTH macos path spelling missed
    persistence
     * REFUSED  macos    SYNTH macos persistence refused
     * allowed  macos    SYNTH macos persistence missed
       REFUSED  linux    SYNTH linux persistence refused

  dangerous spellings refused   4 of 7 (57%)
  of which native to macos      4 of 7 (57%)
  benign controls refused       0 of 2  (must be 0)

  argv normalisation      56 of 56
  substring match         46 of 56
  prefix match            10 of 56
  Fidelity: 6 of 6 mutations restored
"""

SYNTH_BATTERY_TORN = SYNTH_BATTERY.replace(
    u"  of which native to macos      4 of 7 (57%)",
    u"  of which native to macos      5 of 9 (56%)")

# A second dialect carrying the SAME generic miss, which is the equality the
# cross-platform row asserts.
SYNTH_BATTERY_LINUX = (
    SYNTH_BATTERY
    .replace(u"synthetic-macos", u"synthetic-linux")
    .replace(u"native to macos", u"native to linux")
    .replace(u"REFUSED  linux    SYNTH linux persistence refused",
             u"REFUSED  windows  SYNTH windows persistence refused")
    .replace(u"REFUSED  macos", u"REFUSED  linux")
    .replace(u"allowed  macos", u"allowed  linux")
    .replace(u"SYNTH macos", u"SYNTH linux"))

# The same dialect with a DIFFERENT generic miss. Same count, different
# command: only an equality over the SET separates it, which is why the gate
# compares sorted lists rather than lengths.
SYNTH_BATTERY_LINUX_ODD = SYNTH_BATTERY_LINUX.replace(
    u"SYNTH GENERIC credential spelling",
    u"SYNTH DIFFERENT generic credential spelling")


def _native_miss_control(pb):
    """POSITIVE CONTROL for the nine per-dialect rows. Both directions."""
    mac = pb.parse(SYNTH_BATTERY)
    check("positive control: the synthetic battery transcript parses",
          (mac.get("os"), mac.get("native_refused"), mac.get("native_of"),
           mac.get("battery_ran")),
          ("synthetic-macos", 4, 7, True))
    f = _native_miss_facts(mac, "macos")
    check("positive control: native misses are counted by tag, not in bulk",
          (f["missed"], f["unrefused"], len(f["generic"])), (2, 3, 1))
    check("positive control: a consistent battery reconciles with its "
          "intent table", (f["unrefused"], f["from_table"]), (3, 3))
    torn = _native_miss_facts(pb.parse(SYNTH_BATTERY_TORN), "macos")
    check("positive control: a battery whose summary disagrees with its "
          "list does not reconcile", (torn["unrefused"], torn["from_table"]),
          (3, 4))
    extra = _native_miss_facts(pb.parse(SYNTH_BATTERY_LINUX), "linux")
    odd = _native_miss_facts(pb.parse(SYNTH_BATTERY_LINUX_ODD), "linux")
    check("positive control: a second dialect's misses are read under its "
          "own tag", (extra["missed"], extra["unrefused"]), (2, 3))
    check("positive control: generic misses are compared as sets, not "
          "counted", (extra["generic"] == f["generic"],
                      odd["generic"] == f["generic"],
                      len(odd["generic"]) == len(f["generic"])),
          (True, False, True))


def platform_battery():
    """Pin the cross-platform battery, including what MUST match Windows."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import platform_battery as pb
    except ImportError:
        FAIL.append(("platform_battery importable", "MISSING", "present"))
        return
    runs = pb.measure()
    if not runs:
        FAIL.append(("platform results present", "none", "at least macos"))
        return

    mac = runs.get("macos")
    if not mac:
        FAIL.append(("macos platform results", "MISSING", "present"))
        return

    check("macos dangerous spellings refused", mac.get("dangerous_refused"), 20)
    check("macos dangerous spellings total", mac.get("dangerous_total"), 32)
    check("macos native among refused", mac.get("native_refused"), 15)
    check("macos benign controls refused", mac.get("benign_refused"), 0)
    check("macos respellings that diverged", mac.get("respell_changed"), 2)
    check("macos over budget, live paths idle (data only)",
          mac.get("over_budget_live"), 0)

    for platform, r in sorted(runs.items()):
        if r.get("saturated_over") is None:
            continue
        note("%s saturated bench, over budget" % platform,
             "%d of %d live-path invocations with %s cores loaded"
             % (r["saturated_over"], r["saturated_of"],
                r.get("saturated_cores", "?")))
    # The two the paper prints by name.
    check("linux saturated over budget", runs["linux-wsl"].get("saturated_over"), 142)
    check("macos saturated over budget", mac.get("saturated_over"), 0)

    # These are computation over committed data. A difference is a bug.
    for platform, r in sorted(runs.items()):
        check("%s argv normalization" % platform, r.get("argv_norm"), (56, 56))
        check("%s substring match" % platform, r.get("substring"), (46, 56))
        check("%s prefix match" % platform, r.get("prefix"), (10, 56))

    for platform, r in sorted(runs.items()):
        pre_fix = r.get("date", "?") < FIX_LANDED
        allowed = r.get("failopen_allowed")
        denied = r.get("saturated_denied")
        if allowed is None and denied is not None:
            PASS.append(("%s mediation holds under load" % platform,
                         "all %d refused; the saturated bench ran to "
                         "completion, which it cannot do if any deny-path "
                         "invocation was allowed" % denied))
        elif allowed is None:
            SKIP.append(("%s mediation holds under load" % platform,
                         "section 17 carries neither the deny-loop abort nor "
                         "the completed bench's final line, so nothing about "
                         "mediation can be read from it",
                         SKIP_UNMEASURED))
        elif allowed and pre_fix:
            note("%s mediation, pre-fix run" % platform,
                 "%d of %d allowed on %s (motivated the connect/retry split)"
                 % (allowed, r.get("failopen_of", 0), r.get("date", "?")))
        elif allowed:
            FAIL.append(("%s mediation holds under load" % platform,
                         "%d allowed in a post-fix run" % allowed, "0 allowed"))
        else:
            PASS.append(("%s mediation holds under load" % platform,
                         "0 of %d allowed" % r.get("failopen_of", 0)))

    for name in sorted(os.listdir(DATA)):
        if not name.endswith("-results.txt"):
            continue
        sup = pb.parse(pb.load(os.path.join(DATA, name)))
        if sup.get("failopen_allowed") is None:
            continue
        stamp = sup.get("date", "?")
        label = "superseded %s deny-path probe" % name.split("-results")[0]
        if stamp >= FIX_LANDED:
            FAIL.append((label, "%d of %d allowed in a post-fix run recorded "
                                "outside platform/"
                         % (sup["failopen_allowed"], sup.get("failopen_of", 0)),
                         "0 allowed"))
        else:
            note(label, "%d of %d allowed on %s (pre-fix; second motivating "
                        "fault for the connect/retry split)"
                 % (sup["failopen_allowed"], sup.get("failopen_of", 0), stamp))

    # A run whose spelling battery did not execute contributes latency and
    # invariants only, and must not be read as a platform that found nothing.
    for platform, r in sorted(runs.items()):
        if not r.get("battery_ran"):
            note("%s battery status" % platform,
                 "latency and invariants only; the spelling sweep did not run")

    # THE NINE ROWS THE CENSUS COULD NOT DRIVE RED, all of them now computed
    # by `_native_miss_facts` so `_native_miss_control` above exercises the
    # same arithmetic on a transcript whose answer is known and different.
    mac_f = _native_miss_facts(mac, "macos")
    if mac_f["missed"] == 3:
        PASS.append(("macos native spellings missed", 3))
    else:
        FAIL.append(("macos native spellings missed", mac_f["missed"], 3))
    check("macos native spellings unrefused, all tags", mac_f["unrefused"], 5)
    check("macos native spellings unrefused, tagged any",
          len(mac_f["generic"]), 2)
    check("macos unrefused reconciles with the intent table",
          mac_f["unrefused"], mac_f["from_table"])
    note("macos reversal battery",
         "%s of %s (the sixth case needs BSD sed's backup suffix)"
         % mac.get("reversal", ("?", "?")))

    lin = runs.get("linux-wsl")
    if not lin:
        FAIL.append(("linux platform results", "MISSING", "present"))
        return
    check("linux dangerous spellings refused", lin.get("dangerous_refused"), 20)
    check("linux dangerous spellings total", lin.get("dangerous_total"), 32)
    check("linux native among refused", lin.get("native_refused"), 16)
    check("linux native spellings offered", lin.get("native_of"), 19)
    check("linux benign controls refused", lin.get("benign_refused"), 0)
    check("linux respellings that diverged", lin.get("respell_changed"), 2)
    check("linux reversal battery", lin.get("reversal"), (6, 6))
    check("linux live positive controls", lin.get("live_controls"), (3, 3))
    # The two intents Linux hides, which are the measurement on this platform.
    lin_f = _native_miss_facts(lin, "linux")
    if lin_f["missed"] == 1:
        PASS.append(("linux native spellings missed", 1))
    else:
        FAIL.append(("linux native spellings missed", lin_f["missed"], 1))
    # The same two generic misses land here, which is what makes them generic
    # and not macOS idiom: same ruleset, same binary, different OS, both gone.
    check("linux native spellings unrefused, all tags", lin_f["unrefused"], 3)
    check("linux native spellings unrefused, tagged any",
          len(lin_f["generic"]), 2)
    check("linux unrefused reconciles with the intent table",
          lin_f["unrefused"], lin_f["from_table"])
    check("the generic misses are the same two on both platforms",
          lin_f["generic"], mac_f["generic"])
    # Native path-edit coverage is the cross-platform contrast the paper draws:
    # 2/2 here against 1/2 on macOS, same rules, same binary.
    lin_path = [i for i in lin.get("intents", []) if i["intent"] == "path_edit"]
    mac_path = [i for i in mac.get("intents", []) if i["intent"] == "path_edit"]
    check("linux native path_edit coverage",
          lin_path[0]["native_refused"] if lin_path else None, "2/2")
    check("macos native path_edit coverage",
          mac_path[0]["native_refused"] if mac_path else None, "1/2")


# ---------------------------------------------------------------- hygiene --

# --------------------------------------------------------- effective n --

def _effective_n_sentence(text):
    """The section 4 sentence, as one match carrying all nine operands."""
    return re.search(
        r"design effects of \$([\d.]+)\$ and \$([\d.]+)\$ put the effective "
        r"sample sizes behind\s+Table~\\ref\{tab:space\} at \$(\d+)\$ and "
        r"\$(\d+)\$ against nominal counts of \$([\d,{}]+)\$\s+and \$(\d+)\$, "
        r"and \$([\d.]+)\$ puts Table~\\ref\{tab:after\} at \$(\d+)\$ "
        r"against \$(\d+)\$", text)


def _effective_n_sentence_control():
    """POSITIVE CONTROL for the row above. Both directions."""
    good = (u"design effects of $9.99$ and $8.88$ put the effective sample "
            u"sizes behind\nTable~\\ref{tab:space} at $11$ and $22$ against "
            u"nominal counts of $1{,}111$\nand $222$, and $7.77$ puts "
            u"Table~\\ref{tab:after} at $33$ against $333$")
    m = _effective_n_sentence(good)
    check("positive control: the section 4 sentence yields all nine operands",
          m.groups() if m else None,
          ("9.99", "8.88", "11", "22", "1{,}111", "222", "7.77", "33", "333"))
    # Two ways the sentence can stop being the sentence, and neither may
    # match: a reworded verb, and the three figures split across sentences
    # so that they are no longer asserted together.
    check("positive control: a reworded sentence does not match",
          _effective_n_sentence(good.replace(u"put the effective",
                                             u"leave the effective")), None)
    check("positive control: the three figures must be one sentence",
          _effective_n_sentence(good.replace(
              u"and $7.77$ puts", u"Separately. And $7.77$ puts")), None)


def effective_sample():
    """The paper now prints what clustering costs in observations."""
    tex = os.path.join(REPO, "paper", "main.tex")
    if not os.path.isfile(tex):
        FAIL.append(("effective n: main.tex readable", "MISSING", "present"))
        return
    text = io.open(tex, encoding="utf-8").read()

    # The sentence the paper states all three in, matched as one unit so a
    # number moving between clauses cannot be picked up by a stray digit
    # elsewhere in a 129KB file.
    m = _effective_n_sentence(text)
    if not m:
        FAIL.append(("effective n: the paper states all three",
                     "sentence not found", "the section 4 sentence"))
        return
    PASS.append(("effective n: the paper states all three", "ok"))

    d_sh, d_to, e_sh, e_to = m.group(1), m.group(2), m.group(3), m.group(4)
    n_sh = int(m.group(5).replace(",", "").replace("{", "").replace("}", ""))
    n_to, d_pd, e_pd, n_pd = (int(m.group(6)), m.group(7),
                              int(m.group(8)), int(m.group(9)))

    for label, n, deff, printed in (
            ("action-space shell", n_sh, float(d_sh), int(e_sh)),
            ("action-space tools", n_to, float(d_to), int(e_to)),
            ("post-denial", n_pd, float(d_pd), e_pd)):
        check("effective n, %s" % label, int(round(n / deff)), printed)

    # THE OPERANDS, AGAINST THE THING THEY ARE COUNTS OF. See the docstring.
    guarded("effective n nominals", ("campaign",), [
        "effective n: nominal shell calls match the archive",
        "effective n: nominal tool calls match the archive",
        "effective n: nominal denial events match the archive",
    ], lambda: _effective_n_nominals(n_sh, n_to, n_pd))

    # The shell design effect is the one the power analysis applies, and it is
    # a constant in a different file. A retune there that never reached the
    # paper is the failure this catches.
    path = os.path.join(REPO, "paper", "scripts", "analysis", "sample_size.py")
    if not os.path.isfile(path):
        FAIL.append(("effective n: sample_size.py readable", "MISSING",
                     "present"))
        return
    src = io.open(path, encoding="utf-8").read()
    m = re.search(r"^DESIGN_EFFECT\s*=\s*([\d.]+)", src, re.M)
    if not m:
        FAIL.append(("effective n: sample_size.py states DESIGN_EFFECT",
                     "not found", "DESIGN_EFFECT = <float>"))
        return
    check("effective n: power analysis and paper use one shell deff",
          m.group(1), d_sh)


def _effective_n_nominals(n_sh, n_to, n_pd):
    """The three nominal counts in section 4, recounted from the archive."""
    labels = ("effective n: nominal shell calls match the archive",
              "effective n: nominal tool calls match the archive",
              "effective n: nominal denial events match the archive")
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    archive = os.path.join(DATA, "denials")
    try:
        import own_action_space as oas
        import responses as _resp
        calls, _n_sessions = oas.calls_in(archive)
        denials = _resp.denials_in(archive)
    except SystemExit as exc:
        # The scope guard, reached with the corpus declared present. That is a
        # contradiction between two statements about the same archive, so it
        # is reported rather than treated as absence.
        for label in labels:
            FAIL.append((label, "archive scope guard exit %s"
                         % (exc.code if exc.code is not None else 0),
                         "the nested campaign layout"))
        return
    except Exception as exc:  # noqa: BLE001 - reported, never excused
        for label in labels:
            FAIL.append((label, "%s: %s" % (type(exc).__name__, exc), "ok"))
        return

    mutating = [c for c in calls if not c["read_only"]]
    check(labels[0], len([c for c in mutating if c["space"] == "shell"]), n_sh)
    check(labels[1], len([c for c in mutating if c["space"] == "tool"]), n_to)
    check(labels[2], len(denials), n_pd)


def _git(*args):
    """Run a git command in REPO. Returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.Popen(("git",) + args, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=REPO)
    except OSError as exc:
        return None, b"", str(exc).encode("utf-8", "replace")
    out, err = proc.communicate()
    return proc.returncode, out, err


TREE_REPO, TREE_EXPORT, TREE_BROKEN = "repo", "export", "broken"


def _tree_state():
    """(state, detail). See the comment above; the order of tests matters."""
    dot_git = os.path.exists(os.path.join(REPO, ".git"))
    rc, out, err = _git("rev-parse", "--show-toplevel")
    top = out.decode("utf-8", "replace").strip() if rc == 0 else ""
    same = bool(top) and os.path.realpath(top) == os.path.realpath(REPO)

    if not dot_git:
        if same:
            # No `.git`, yet git says this very path is the root of a work
            # tree. Something is overriding the discovery (GIT_DIR, GIT_WORK_TREE)
            # and the tree is not what it claims.
            return TREE_BROKEN, ("no .git here, but git reports this path as a"
                                 " work tree root - the tree is not what it"
                                 " claims")
        if rc == 0:
            # Inside somebody else's checkout. An export unpacked under a
            # repository is not a release tree: `git ls-files` would answer
            # about the wrong index.
            return TREE_BROKEN, ("no .git here, but this path is inside the"
                                 " work tree at %s" % top[:60])
        return TREE_EXPORT, ("no .git, as DATA-RELEASE.md 2.7 requires of a"
                             " release tree")
    if rc is None:
        return TREE_BROKEN, ("a .git is present but git could not be"
                             " executed: %s" % err.decode("utf-8",
                                                          "replace")[:50])
    if rc != 0:
        return TREE_BROKEN, ("a .git is present but git rev-parse exited"
                             " %d: %s" % (rc, err.decode("utf-8",
                                                         "replace").strip()[:50]))
    if not same:
        return TREE_BROKEN, ("a .git is present but git reports the work tree"
                             " root as %s" % (top[:60] or "nothing"))
    rc2, out2, _e2 = _git("rev-parse", "--is-inside-work-tree")
    if rc2 != 0 or out2.strip() != b"true":
        return TREE_BROKEN, ("git rev-parse --is-inside-work-tree exit %s"
                             % rc2)
    return TREE_REPO, "git work tree rooted at REPO"


RELEASE_SUBSET = {
    "api archives":
        "the 81 probe and spot-check cells are withheld",
    "api scratch archives (probe, armcheck, famcheck, ovr-check)":
        "the 81 probe and spot-check cells are withheld",
    "api session logs, all archives":
        "the 255 scratch session logs are withheld",
    "api session logs, scratch":
        "the 255 scratch session logs are withheld",
    "blast radius: guarded tree-wide":
        "the withheld cells carry guarded sessions the floor counts",
}



_TREE_STATE = []


def tree_is_export():
    """True in a release tree. Cached: `git` is a subprocess and this is hot."""
    if not _TREE_STATE:
        _TREE_STATE.append(_tree_state()[0])
    return _TREE_STATE[0] == TREE_EXPORT


def _enumerated_under_data():
    """Every file that actually exists under paper/data, listed one by one."""
    out, seen = [], set()
    for root, dirs, names in os.walk(DATA, followlinks=True):
        real = os.path.realpath(root)
        if real in seen:
            dirs[:] = []
            continue
        seen.add(real)
        for name in names:
            out.append(os.path.join(root, name))
    return out


def hygiene():
    """Anonymity and licensing, all four of which used to pass without looking."""
    state, detail = _tree_state()
    git_ok = state == TREE_REPO
    if state == TREE_BROKEN:
        FAIL.append(("git is usable in this tree", detail,
                     "either a working git, or no .git at all (an export)"))
    elif state == TREE_EXPORT:
        PASS.append(("git is usable in this tree",
                     "not applicable - %s" % detail))
    else:
        PASS.append(("git is usable in this tree", "ok"))

    if state == TREE_EXPORT:
        listed = len(_enumerated_under_data())
        if listed:
            PASS.append(("anonymity scan has files to scan",
                         "%d file(s) enumerated under paper/data (no index in"
                         " an export; the list is the file system's)" % listed))
        else:
            FAIL.append(("anonymity scan has files to scan",
                         "0 files under paper/data in an export tree",
                         ">= 1 file under paper/data"))
    else:
        rc, out, _err = _git("ls-files", "--", "paper/data")
        if rc == 0:
            tracked = len([l for l in out.decode("utf-8", "replace").split("\n")
                           if l.strip()])
        else:
            tracked = None
        if not git_ok:
            FAIL.append(("anonymity scan has files to scan",
                         "unknown - git is not usable, so the scan below covered"
                         " an unknown set", ">= 1 tracked file under paper/data"))
        elif tracked:
            PASS.append(("anonymity scan has files to scan",
                         "%d tracked file(s) under paper/data" % tracked))
        else:
            FAIL.append(("anonymity scan has files to scan",
                         "0 tracked files under paper/data",
                         ">= 1 tracked file under paper/data"))

    script = os.path.join(REPO, "paper", "scripts", "anonymise_check.py")
    if not os.path.isfile(script):
        SKIP.append(("anonymisation of the submission set",
                     "anonymise_check.py is withheld from the release; a tree"
                     " cannot scan its own anonymity",
                     SKIP_ABSENT))
    else:
        proc = subprocess.Popen(
            [sys.executable, script],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=REPO)
        out, _ = proc.communicate()
        text = out.decode("utf-8", "replace")
        cov = re.search(r"scope: (\d+) file\(s\) under paper/data via (.+)",
                        text)
        if proc.returncode == 1:
            FAIL.append(("anonymisation of the submission set",
                         "identifying text found", "clean"))
        elif proc.returncode != 0:
            FAIL.append(("anonymisation of the submission set",
                         "NOT ESTABLISHED - the scanner exited %d: %s"
                         % (proc.returncode,
                            (text.strip().splitlines() or [""])[-1][:60]),
                         "clean, and actually scanned"))
        elif cov is None:
            FAIL.append(("anonymisation of the submission set",
                         "exit 0 but the scanner reported no coverage line",
                         "clean, and actually scanned"))
        elif not int(cov.group(1)):
            FAIL.append(("anonymisation of the submission set",
                         "exit 0 over 0 files under paper/data - the scan"
                         " covered nothing", "clean, and actually scanned"))
        else:
            PASS.append(("anonymisation of the submission set",
                         "clean over %s file(s) under paper/data (%s)"
                         % (cov.group(1), cov.group(2).strip()[:52])))

    import shutil as _sh
    import tempfile as _tf

    _apc_path = os.path.join(REPO, "paper", "scripts",
                             "anonymise_positive_control.py")
    if not os.path.exists(_apc_path):
        for _n in ("anonymisation positive control runs",
                   "anonymisation positive control: every plant is detected",
                   "anonymisation positive control: the battery reached its "
                   "detectors",
                   "anonymisation positive control: every glue dialect "
                   "exercised"):
            SKIP.append((_n, "anonymise_positive_control.py is withheld from "
                             "the release with the scanner it proves",
                         SKIP_ABSENT))
        return

    try:
        sys.path.insert(0, os.path.join(REPO, "paper", "scripts"))
        import anonymise_positive_control as _apc
        _apc.results = []
        _tmp = _tf.mkdtemp(prefix="verify-anon-control-")
        _saved = sys.stdout
        try:
            # The battery narrates ten lines per run; the verdict is what this
            # gate reports, and the detail is one command away.
            sys.stdout = io.StringIO()
            _apc.control_a(_tmp)
            _apc.control_f(_tmp)
        finally:
            sys.stdout = _saved
            _sh.rmtree(_tmp, ignore_errors=True)
    except Exception as exc:               # noqa: BLE001 - reported, not hidden
        FAIL.append(("anonymisation positive control runs",
                     str(exc)[:60], "ok"))
    else:
        bad = [n.strip() for n, ok, _d in _apc.results if not ok]
        # ANTI-VACUITY. A battery that planted nothing satisfies every
        # assertion about its failures, which is the exact shape this gate is
        # about.
        planted = [n for n, _ok, _d in _apc.results if n.startswith("A  ")]
        dialects = [n for n, _ok, _d in _apc.results if n.startswith("F  ")]
        check("anonymisation positive control: every plant is detected",
              bad, [])
        check("anonymisation positive control: the battery reached its "
              "detectors", len(planted), 7)
        check("anonymisation positive control: every glue dialect exercised",
              len(dialects), 10)

    for name in ("rjudge-actions.jsonl", "rjudge-violations.jsonl",
                 "readmes-statements.jsonl"):
        # Repo-relative on purpose: this argument is for git, not the OS, and
        # it is resolved against cwd=REPO rather than wherever we were invoked.
        path = os.path.join("paper", "data", name)
        if state == TREE_EXPORT:
            if os.path.exists(os.path.join(REPO, path)):
                FAIL.append(("unlicensed %s is untracked" % name,
                             "PRESENT at paper/data/%s in a tree that is being"
                             " distributed" % name,
                             "absent - an export must not carry it"))
            else:
                PASS.append(("unlicensed %s is untracked" % name,
                             "absent from this export tree"))
            continue
        rc, _out, err = _git("ls-files", "--error-unmatch", path)
        if rc == 0:
            FAIL.append(("unlicensed %s is untracked" % name,
                         "TRACKED", "untracked"))
        elif rc == 1:
            # git ran, looked, and did not find it in the index. The only
            # answer that means "untracked".
            PASS.append(("unlicensed %s is untracked" % name, "ok"))
        else:
            FAIL.append(("unlicensed %s is untracked" % name,
                         "NOT ESTABLISHED - git ls-files exit %s: %s"
                         % (rc, err.decode("utf-8", "replace").strip()[:60]),
                         "a git answer, not a git failure"))

    scoped_analyses_announce_their_scope()


SCOPE_GUARDS = {
    "own_action_space.py": "require_nested",
    "machine_writes.py": "require_nested",
    "models.py": "require_nested",
    "e1_truncation.py": "require_nested",
    "rewrite_outcome.py": "require_nested",
    "responses.py": "require_sessions",
}
NESTED_READERS = tuple(sorted(SCOPE_GUARDS))


def _calls_guard(source, guard):
    """Does this module CALL `guard` - as a call, not as text?"""
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == guard:
            return True
        if isinstance(func, ast.Attribute) and func.attr == guard:
            return True
    return False


# The three sources the control runs the predicate over. Written out rather
# than generated, so what each one is a case OF is readable beside it.
_GUARD_CALLED = (
    'from archive import require_nested\n'
    'def run(path):\n'
    '    require_nested(path, "control")\n')
_GUARD_COMMENTED = (
    'from archive import require_nested\n'
    'def run(path):\n'
    '    pass  # require_nested(path, "control")\n')
_GUARD_IN_PROSE = (
    '"""This reader no longer calls require_nested(path) - see below."""\n'
    'def run(path):\n'
    '    return path\n')


def _scope_guard_control():
    """POSITIVE CONTROL: the gate's own predicate, on all three answers."""
    check("positive control: a real guard call is recognised",
          _calls_guard(_GUARD_CALLED, "require_nested"), True)
    check("positive control: a commented-out guard call is not",
          _calls_guard(_GUARD_COMMENTED, "require_nested"), False)
    check("positive control: the guard's name in prose is not a call",
          _calls_guard(_GUARD_IN_PROSE, "require_nested"), False)


def scoped_analyses_announce_their_scope():
    """SOURCE-LEVEL, because the runtime symptom is silence."""
    _scope_guard_control()
    base = os.path.join(REPO, "paper", "scripts", "analysis")
    missing = []
    for name in NESTED_READERS:
        path = os.path.join(base, name)
        if not os.path.isfile(path):
            missing.append("%s (absent)" % name)
            continue
        try:
            body = io.open(path, encoding="utf-8").read()
            called = _calls_guard(body, SCOPE_GUARDS[name])
        except SyntaxError as exc:
            # Unparseable is breakage, not absence of a guard, and it is said
            # so by name rather than folded into the roster count.
            missing.append("%s (will not parse: line %s)" % (name, exc.lineno))
            continue
        if not called:
            missing.append("%s (no %s)" % (name, SCOPE_GUARDS[name]))
    if missing:
        FAIL.append(("analyses scoped to a session layout say so",
                     ", ".join(missing)[:48], "all %d" % len(NESTED_READERS)))
    else:
        PASS.append(("analyses scoped to a session layout say so",
                     "all %d" % len(NESTED_READERS)))




def _all_rows(path):
    """Every rated item from an ingested holdout file, split ones included."""
    rows = []
    p = os.path.join(DATA, path)
    if not os.path.isfile(p):
        return None
    for line in io.open(p, encoding="utf-8"):
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _consensus(path):
    """Only the items a strict majority resolved. Rates are computed on these."""
    rows = _all_rows(path)
    if rows is None:
        return None
    return [r for r in rows if r.get("consensus")]


def _wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0, 0.0
    p = float(k) / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def _holdout_t1():
    t1 = _consensus("atbench-violations.jsonl.labels-holdout.jsonl")
    check("task 1 holdout consensus items", len(t1), 2314)
    dist = collections.Counter(r["consensus"] for r in t1)
    check("task 1 holdout C1", dist.get("C1"), 21)
    check("task 1 holdout C2", dist.get("C2"), 2215)
    check("task 1 holdout C3", dist.get("C3"), 76)
    check("task 1 holdout C0", dist.get("C0"), 2)
    p, lo, hi = _wilson(dist.get("C1", 0), len(t1))
    near("task 1 holdout C1 %", 100 * p, 0.91, 0.01)
    near("task 1 holdout C1 lo", 100 * lo, 0.59, 0.01)
    near("task 1 holdout C1 hi", 100 * hi, 1.38, 0.01)
    # the even splits the paper says were discarded
    check("task 1 holdout even splits", 2401 - len(t1), 87)


def _holdout_t2():
    t2 = _consensus("policy-statements.labels-holdout.jsonl")
    check("task 2 holdout consensus items", len(t2), 1176)
    dist = collections.Counter(r["consensus"] for r in t2)
    check("task 2 holdout A", dist.get("A"), 31)
    p, lo, hi = _wilson(dist.get("A", 0), len(t2))
    near("task 2 holdout A %", 100 * p, 2.64, 0.01)
    near("task 2 holdout A lo", 100 * lo, 1.86, 0.01)
    near("task 2 holdout A hi", 100 * hi, 3.72, 0.01)
    check("task 2 holdout even splits", 1200 - len(t2), 24)


def _unmatched_share(rows):
    """The share of statements the matcher declined to call action-local."""
    if not rows:
        return 0.0
    unm = sum(1 for r in rows
              if not r.get("signature") or r.get("signature") == "None")
    return float(unm) / len(rows)


def _unmatched_share_control():
    """POSITIVE CONTROL for the row above. Both directions, all four
    spellings, and the boundary between them."""
    check("positive control: every spelling of an absent signature is "
          "unmatched",
          "%.1f" % (100 * _unmatched_share(
              [{}, {"signature": None}, {"signature": ""},
               {"signature": "None"}, {"signature": "sig"}])), "80.0")
    check("positive control: a real signature is matched, not unmatched",
          _unmatched_share([{"signature": "sig"}, {"signature": "sig2"}]),
          0.0)


def _holdout_correction():
    """The corrected inversion the paper argues from: the unmatched share of
    the corpus times the panel's rate inside it. Two corpora, so its own
    block - the panel alone is not enough to compute it."""
    t2 = _consensus("policy-statements.labels-holdout.jsonl")
    p, _lo, _hi = _wilson(
        sum(1 for r in t2 if r.get("consensus") == "A"), len(t2))
    share = _unmatched_share(load("policy-statements.jsonl"))
    near("policy unmatched share %", 100 * share, 96.4, 0.05)
    near("policy correction points", 100 * p * share, 2.54, 0.02)
    near("policy corrected floor %", 1.6 + 100 * p * share, 4.1, 0.05)
    near("policy corrected ceiling %", 3.6 + 100 * p * share, 6.1, 0.05)


def _holdout_both():
    """Both panels together are the basis for the no-false-positives claim."""
    t2 = _consensus("policy-statements.labels-holdout.jsonl")
    n_dev = 372
    check("statements rated across both panels", n_dev + len(t2), 1548)


def holdout_gates():
    """Recompute the panel figures from the sheets, not from a note."""
    guarded("task 1 panel", ("holdout-atbench",), [
        "task 1 holdout consensus items", "task 1 holdout C1",
        "task 1 holdout C2", "task 1 holdout C3", "task 1 holdout C0",
        "task 1 holdout C1 %", "task 1 holdout C1 lo", "task 1 holdout C1 hi",
        "task 1 holdout even splits",
    ], _holdout_t1)

    guarded("task 2 panel", ("holdout-policy",), [
        "task 2 holdout consensus items", "task 2 holdout A",
        "task 2 holdout A %", "task 2 holdout A lo", "task 2 holdout A hi",
        "task 2 holdout even splits",
    ], _holdout_t2)

    guarded("policy correction", ("holdout-policy", "policy"), [
        "policy unmatched share %", "policy correction points",
        "policy corrected floor %", "policy corrected ceiling %",
    ], _holdout_correction)

    guarded("both panels", ("holdout-atbench", "holdout-policy"), [
        "statements rated across both panels",
    ], _holdout_both)



def _ac1(a, b, keys):
    """Gwet's AC1 over the items both raters answered."""
    n = len(keys)
    if not n:
        return float("nan")
    pa = sum(1 for k in keys if a[k] == b[k]) / float(n)
    cats = set(a[k] for k in keys) | set(b[k] for k in keys)
    if len(cats) < 2:
        return 1.0
    pe = 0.0
    for c in cats:
        pi = (sum(1 for k in keys if a[k] == c) / float(n)
              + sum(1 for k in keys if b[k] == c) / float(n)) / 2.0
        pe += pi * (1 - pi)
    pe /= (len(cats) - 1)
    return (pa - pe) / (1 - pe) if pe < 1 else 1.0


def _pairwise_range(rows):
    """(min, max) pairwise AC1 across the raters whose votes are stored."""
    by = {}
    for r in rows:
        for rater, cls in (r.get("votes") or {}).items():
            if cls:
                by.setdefault(rater, {})[r["item"]] = cls
    names = sorted(by)
    vals = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = by[names[i]], by[names[j]]
            shared = sorted(set(a) & set(b))
            vals.append(_ac1(a, b, shared))
    return (min(vals), max(vals)) if vals else (float("nan"),) * 2


def _agreement_control():
    """POSITIVE CONTROL for the four AC1 bounds. Both directions."""
    def rows(votes):
        return [{"item": "i%d" % i, "votes": v} for i, v in enumerate(votes)]

    # 24 items, two categories, three raters, no disagreement anywhere.
    agreed = rows([{"a": c, "b": c, "c": c}
                   for c in ["A", "B"] * 12])
    lo, hi = _pairwise_range(agreed)
    check("positive control: raters in perfect agreement score AC1 1.0",
          ("%.3f" % lo, "%.3f" % hi), ("1.000", "1.000"))

    # The same sheet with rater `c` flipped on six of the 24. Pairs (a,b) is
    # untouched and pairs (a,c) and (b,c) are not, so the range opens.
    split = rows([{"a": c, "b": c,
                   "c": ("B" if c == "A" else "A") if i < 6 else c}
                  for i, c in enumerate(["A", "B"] * 12)])
    lo2, hi2 = _pairwise_range(split)
    check("positive control: one rater's disagreement opens the AC1 range",
          (hi2 == 1.0, lo2 < 0.85, lo2 > 0.4), (True, True, True))
    # And the bound the gate quotes is the pair that actually disagreed,
    # not an average over the three: 18 of 24 agreeing on a balanced
    # two-category sheet is AC1 0.500 exactly.
    check("positive control: the AC1 minimum is the worst pair, computed",
          "%.3f" % lo2, "0.500")


def _agreement_t1():
    lo, hi = _pairwise_range(
        _all_rows("atbench-violations.jsonl.labels-holdout.jsonl"))
    near("task 1 holdout AC1 min", lo, 0.937, 0.001)
    near("task 1 holdout AC1 max", hi, 0.952, 0.001)


def _overcalled(corpus, rated, cls):
    """Items the classifier put in `cls` and the panel did not."""
    return sum(1 for r in rated
               if corpus[r["id"]]["machine_class"] == cls
               and r["consensus"] != cls)


def _overcall_control():
    """POSITIVE CONTROL for the row above. Both directions."""
    corpus = {"a": {"machine_class": "C1"}, "b": {"machine_class": "C1"},
              "c": {"machine_class": "C2"}}
    rated = [{"id": "a", "consensus": "C2"},    # over-called
             {"id": "b", "consensus": "C1"},    # agreed, not an over-call
             {"id": "c", "consensus": "C1"}]    # UNDER-called, not this row
    check("positive control: a classifier C1 the panel calls C2 is an "
          "over-call", _overcalled(corpus, rated, "C1"), 1)
    check("positive control: agreement and the opposite error are not "
          "over-calls",
          (_overcalled(corpus, [rated[1]], "C1"),
           _overcalled(corpus, [rated[2]], "C1")), (0, 0))


def _agreement_classifier():
    """The classifier comparison, recomputed against the live corpus."""
    corpus = {}
    for r in load("atbench-violations.jsonl") or []:
        corpus[r.get("id") or r.get("uid")] = r
    t1 = _all_rows("atbench-violations.jsonl.labels-holdout.jsonl")
    both = [r for r in t1 if r.get("id") in corpus and r.get("consensus")]
    check("task 1 panel joins to the ATBench corpus", len(both), 2314)
    if not both:
        for name in ("task 1 classifier vs holdout %",
                     "task 1 classifier over-called C1",
                     "task 1 machine-C3 items rated",
                     "task 1 machine-C3 the panel calls C2"):
            FAIL.append((name, "join is empty", "computable"))
        return
    agree = sum(1 for r in both
                if corpus[r["id"]]["machine_class"] == r["consensus"])
    near("task 1 classifier vs holdout %",
         100.0 * agree / len(both), 87.7, 0.05)
    check("task 1 classifier over-called C1", _overcalled(corpus, both, "C1"),
          0)
    # The one seam the paper names: what the classifier calls C3.
    c3 = [r for r in both if corpus[r["id"]]["machine_class"] == "C3"]
    check("task 1 machine-C3 items rated", len(c3), 318)
    check("task 1 machine-C3 the panel calls C2",
          sum(1 for r in c3 if r["consensus"] == "C2"), 251)


def _agreement_t2():
    lo, hi = _pairwise_range(_all_rows("policy-statements.labels-holdout.jsonl"))
    near("task 2 holdout AC1 min", lo, 0.950, 0.001)
    near("task 2 holdout AC1 max", hi, 0.961, 0.001)


def agreement_gates():
    """The reliability figures the paper prints, from the stored votes."""
    guarded("task 1 agreement", ("holdout-atbench",), [
        "task 1 holdout AC1 min", "task 1 holdout AC1 max",
    ], _agreement_t1)

    guarded("task 1 classifier vs panel", ("holdout-atbench", "atbench"), [
        "task 1 panel joins to the ATBench corpus",
        "task 1 classifier vs holdout %", "task 1 classifier over-called C1",
        "task 1 machine-C3 items rated", "task 1 machine-C3 the panel calls C2",
    ], _agreement_classifier)

    guarded("task 2 agreement", ("holdout-policy",), [
        "task 2 holdout AC1 min", "task 2 holdout AC1 max",
    ], _agreement_t2)

def policy_gates():
    """Every per-corpus policy figure the appendix prints, recomputed."""
    want = {
        # rows,    C1 raw, C1|classified, unclassified, non-C1
        "policy-statements.jsonl":  (13818, 3.63, 22.3, 83.74, 96.37),
        "aiware-statements.jsonl":  (120094, 1.65, 11.0, 84.96, 98.35),
        "readmes-statements.jsonl": (32281, 2.07, 12.1, 82.94, 97.93),
    }
    for name in sorted(want):
        stem = name.split("-")[0]
        labels = ["policy %s rows" % stem,
                  "policy %s C1 raw %%" % stem,
                  "policy %s C1 given classified %%" % stem,
                  "policy %s no class assigned %%" % stem,
                  "policy %s not called C1 %%" % stem]
        rows = load(name)
        if not rows:
            for label in labels:
                SKIP.append((label, _no_corpus([_KEY_OF_FILE[name]]),
                             SKIP_ABSENT))
            continue
        n, raw, given, unclassified, non_c1 = want[name]
        classes = [r.get("machine_class") for r in rows]
        c1 = sum(1 for c in classes if c == "C1")
        u = sum(1 for c in classes if c == "U")
        classified = len(rows) - u
        check("policy %s rows" % stem, len(rows), n)
        near("policy %s C1 raw %%" % stem, 100.0 * c1 / len(rows), raw, 0.01)
        near("policy %s C1 given classified %%" % stem,
             100.0 * c1 / classified, given, 0.05)
        near("policy %s no class assigned %%" % stem,
             100.0 * u / len(rows), unclassified, 0.05)
        near("policy %s not called C1 %%" % stem,
             100.0 * (len(rows) - c1) / len(rows), non_c1, 0.05)

    guarded("holdout policy frame", ("labelkit", "policy"), [
        "holdout policy sample size",
        "holdout policy items drawn from the non-C1 pile",
        "holdout policy items that join back to our corpus",
    ], _holdout_frame)

    guarded("recall rule", ("labelkit", "holdout-policy"), [
        "recall rule held-out recall %",
        "recall rule held-out positives found",
        "recall rule held-out precision %",
    ], _recall_rule)


def _holdout_frame():
    keyfile = os.path.join(DATA, "labelkit", "_keys", "key-holdout-policy.json")
    rows = load("policy-statements.jsonl")
    key = json.load(io.open(keyfile, encoding="utf-8"))
    check("holdout policy sample size", len(key), 1200)
    by = {}
    for r in rows:
        by[(r.get("repo"), r.get("statement"))] = r
    seen = [by[(v["repo"], v["statement"])] for v in key.values()
            if (v["repo"], v["statement"]) in by]
    check("holdout policy items drawn from the non-C1 pile",
          sum(1 for r in seen if r.get("machine_class") == "C1"), 0)
    check("holdout policy items that join back to our corpus",
          len(seen), 1200)
    note("holdout policy repeated statement pairs",
         len(key) - len(set((v["repo"], v["statement"])
                            for v in key.values())))


def _recall_rule():
    """The recall rule the paper reports as a negative result."""
    names = ("recall rule held-out recall %",
             "recall rule held-out positives found",
             "recall rule held-out precision %")
    rule = os.path.join(REPO, "paper", "scripts", "policies", "recall_rule.py")
    if not os.path.exists(rule):
        for name in names:
            FAIL.append((name, "recall_rule.py missing", "present"))
        return
    proc = subprocess.Popen([sys.executable, rule], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, cwd=REPO)
    out, _ = proc.communicate()
    text = out.decode("utf-8", "replace")
    if proc.returncode != 0:
        for name in names:
            FAIL.append((name, "recall_rule.py exit %d" % proc.returncode,
                         "exit 0"))
        return
    rec = re.search(r"recall\s+(\d+)/(\d+)\s+(\d+)%", text)
    pre = re.search(r"precision\s+(\d+)/(\d+)\s+(\d+)%", text)
    if rec:
        check("recall rule held-out recall %", int(rec.group(3)), 61)
        check("recall rule held-out positives found",
              "%s/%s" % (rec.group(1), rec.group(2)), "19/31")
    else:
        FAIL.append((names[0], "recall not in output", "recall k/n p%"))
        FAIL.append((names[1], "recall not in output", "19/31"))
    if pre:
        check("recall rule held-out precision %", int(pre.group(3)), 15)
    else:
        FAIL.append((names[2], "precision not in output", "precision k/n p%"))


def tables_fresh():
    """No generated table on disk may disagree with the data behind it."""
    # noqa: E501
    script = os.path.join(REPO, "paper", "scripts", "figures", "tables.py")
    if not os.path.exists(script):
        # A bare `return` here emitted nothing at all - no pass, no fail, no
        # skip - for the generator every table in the paper comes out of.
        FAIL.append(("tables.py exists", "MISSING", script))
        return

    # THE TWO REGISTRIES MUST NAME THE SAME TABLES. See TABLE_CORPUS.
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "figures"))
    try:
        import tables as _tables
        registered = set(_tables.TABLES)
    except Exception as exc:  # noqa: BLE001 - reported, never excused
        FAIL.append(("TABLE_CORPUS mirrors tables.py",
                     "%s: %s" % (type(exc).__name__, exc),
                     "importable registry"))
        registered = None
    if registered is not None:
        drift = sorted((registered - set(TABLE_CORPUS))
                       | (set(TABLE_CORPUS) - registered))
        if drift:
            FAIL.append(("TABLE_CORPUS mirrors tables.py",
                         "%d table(s) in one registry and not the other: %s"
                         % (len(drift), ", ".join(drift)),
                         "the same %d tables" % len(registered)))
        else:
            PASS.append(("TABLE_CORPUS mirrors tables.py",
                         "%d tables" % len(registered)))

    proc = subprocess.Popen([sys.executable, script, "--check"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=REPO)
    out, _ = proc.communicate()
    text = out.decode("utf-8", "replace")

    seen = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith("tab-"):
            continue
        status, name = parts[0], parts[1]
        if name in seen:
            continue          # the trailing n/a summary repeats the names
        seen.add(name)
        label = "table %s is fresh" % name
        if status == "ok":
            PASS.append((label, "ok"))
        elif status == "STALE":
            FAIL.append((label, "stale", "matches the data behind it"))
        else:                                    # n/a, FAIL
            FAIL.append((label, "MISSING", "buildable and fresh"))

    have_head = subprocess.Popen(
        ["git", "rev-parse", "--verify", "-q", "HEAD"], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, cwd=REPO)
    have_head.communicate()
    for table, keys in sorted(TABLE_CORPUS.items()):
        if not _absent(keys):
            continue                      # rebuildable here; staleness covers it
        label = "generated %s is unedited since commit" % table
        disk = os.path.join(REPO, "paper", "figures", table)
        if not os.path.isfile(disk):
            FAIL.append((label, "MISSING", "present"))
            continue
        if have_head.returncode != 0:
            SKIP.append((label, "not a git checkout with a HEAD, so the "
                                "committed table cannot be compared",
                         SKIP_ABSENT))
            continue
        proc = subprocess.Popen(
            ["git", "show", "HEAD:paper/figures/%s" % table],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=REPO)
        blob, _err = proc.communicate()
        if proc.returncode != 0:
            FAIL.append((label, "not committed at HEAD",
                         "a generated table is committed"))
        elif blob == io.open(disk, "rb").read():
            PASS.append((label, "ok"))
        else:
            FAIL.append((label, "edited by hand",
                         "byte-identical to the committed table"))

    missing = [t for t in TABLE_CORPUS if t not in seen]
    if missing:
        # tables.py did not reach every table. Before the SystemExit fix that
        # was every run: it died on the second of five and the other three were
        # never mentioned at all. Not silently tolerated again.
        FAIL.append(("tables.py --check reports every table",
                     "%d of %d unreported: %s"
                     % (len(missing), len(TABLE_CORPUS),
                        ", ".join(sorted(missing))),
                     "all %d reported" % len(TABLE_CORPUS)))


# ----------------------------------------------------------- what needs what --

_CORPORA_ROWS = [
    ("aiware", ("aiware",)),
    ("readmes", ("readmes",)),
    ("rjudge", ("rjudge",)),
    ("R-Judge", ("rjudge",)),
    ("tables.py --check reports every table", ("none",)),
    ("recall rule", ("labelkit", "holdout-policy")),
    ("holdout policy", ("labelkit", "policy")),
    ("task 1 holdout", ("holdout-atbench",)),
    ("task 1 classifier", ("holdout-atbench", "atbench")),
    ("task 1 machine-C3", ("holdout-atbench", "atbench")),
    ("task 2 holdout", ("holdout-policy",)),
    ("statements rated across both panels",
     ("holdout-atbench", "holdout-policy")),
    ("policy unmatched", ("policy", "holdout-policy")),
    ("policy correct", ("policy", "holdout-policy")),
    ("policy policy", ("policy",)),
    ("policy-statements.jsonl", ("policy",)),
    ("atbench-actions", ("atbench-actions",)),
    ("atbench-violations", ("atbench",)),
    ("ATBench", ("atbench",)),
    ("StepShield", ("stepshield",)),
    ("violations.jsonl", ("stepshield",)),
    # "task corpus size" reads scripts/denials/tasks.tsv, which is source, not
    # corpus. It has no excuse and gets none.
    ("task corpus size", ("none",)),
]

# Each analysis script, by what it reads. Taken from the paths in the scripts
# themselves rather than assumed, because a wrong entry here is a gate that
# excuses itself.
_ANALYSIS_CORPUS = {
    "own_action_space.py": ("campaign",),
    "machine_writes.py": ("campaign",),
    "taxonomy_robustness.py": ("atbench", "stepshield", "rjudge"),
    "by_harm.py": ("atbench",),
    "action_space.py": ("atbench",),
    "harm_shape.py": ("campaign",),
    "second_monitor.py": ("campaign",),
    "rule_provenance.py": ("campaign", "policy"),
    "cross_vendor.py": ("agy",),
    "rewrite_outcome.py": ("campaign",),
    "platform_battery.py": ("platform",),
    "ablation.py": ("ablation",),
    "pilot_contrasts.py": ("api",),
}


TABLE_CORPUS = {
    "tab-action-space.tex": ("campaign",),
    "tab-residual.tex": ("stepshield",),
    "tab-composition.tex": ("atbench", "stepshield", "rjudge"),
    "tab-ablation.tex": ("ablation",),
    "tab-crossvendor.tex": ("agy",),
    "tab-app-effort.tex": ("models-effort",),
}


def _corpora_needs(row):
    name = row[0]
    if name.startswith("generated ") and "unedited since commit" in name:
        return ("none",)
    if name.startswith("corpus file "):
        return ("none",)
    for table, keys in TABLE_CORPUS.items():
        if table in name:
            return keys
    for needle, keys in _CORPORA_ROWS:
        if needle in name:
            return keys
    return ("none",)


def _analyses_needs(row):
    """`script X runs` and the indented tail lines that follow it."""
    name = row[0].strip()
    for script, keys in _ANALYSIS_CORPUS.items():
        if script in name:
            return keys
    return ("none",)


def residual_controls():
    """The controls for the checks the gate census left uncontrolled."""
    sys.path.insert(0, os.path.join(REPO, "paper", "scripts", "analysis"))
    try:
        import platform_battery as pb
    except ImportError:
        FAIL.append(("positive control: platform_battery importable",
                     "MISSING", "present"))
    else:
        _native_miss_control(pb)
    _generated_registry_control()
    _retired_width_control()
    _agreement_control()
    _overcall_control()
    _family_coverage_control()
    _api_census_control()
    _blast_radius_control()
    _effective_n_sentence_control()
    _caption_factor_control()
    _unmatched_share_control()


# The gate list, each with the corpus it reads. `needs()` with no argument is
# a gate that reads no corpus at all - pure arithmetic, or git - and can
# therefore never be excused by absence.
GATES = [
    # First, and with needs() empty on purpose: it reports damage to corpora
    # that ARE on this machine, so excusing it for a missing corpus would be
    # the gate excusing itself with the thing it exists to report.
    (corpus_files_intact, needs()),
    (contaminated_excluded, needs()),
    # needs() empty for the same reason: the positive control constructs its
    # own torn line and holds on a machine with no corpus; the whole-corpus
    # pin inside stands down on its own when paper/data is absent.
    (read_losses,      needs()),
    (refused_archives_counted, needs("agy")),
    (corpora,          _corpora_needs),
    (api_corpus,       needs("api")),
    (campaign,         needs("campaign")),
    (blast_radius,     needs("campaign", "ablation")),
    (family_coverage,  needs("ablation")),
    (stopping_durations, needs("models")),
    (session_denominator, needs("models-effort")),
    (paper_table_matches_emitter, needs("models")),
    (paper_table_inventory,       needs()),
    (paper_tab_after,             needs("campaign")),
    (paper_tab_app_families,      needs("campaign")),
    (paper_tab_app_ordinal,       needs("campaign")),
    (paper_tab_app_machinewrites, needs("campaign")),
    (paper_tab_app_blastradius,   needs("campaign", "ablation")),
    (paper_tab_app_verbs,         needs("atbench")),
    (paper_tab_app_composition,   needs("atbench")),
    (paper_tab_comp_caption,      needs("atbench", "stepshield")),
    # Three separately licensed statement corpora; the gate skips row by row,
    # so it declares none of them here and can never be excused wholesale.
    (paper_tab_app_dedup,         needs()),
    (paper_tab_app_filetype,      needs("aiware")),
    (paper_tab_pilot,             needs("api")),
    (paper_tab_placebo,           needs("ablation")),
    (paper_tab_app_artifacts,     needs("incidents")),
    # Anchored on a tracked measurement record rather than on a corpus, so
    # absence is damage and is reported as a failure inside the gate.
    (paper_tab_app_latency,       needs()),
    (paper_tab_related,           needs()),
    (paper_operating_point,       needs()),
    (paper_rewrote_rule,          needs()),
    (paper_rule_mix,              needs("models")),
    (harm_shape,       needs("campaign")),
    (second_monitor,   needs("campaign")),
    # needs() empty: the control builds its own archives.
    (stopping_rules,   needs()),
    # needs() empty on purpose: the gate skips each absent corpus BY NAME
    # rather than being excused wholesale, and its control is corpus-free.
    (session_durations, needs("models")),
    (analysis_reads_written_keys, needs("cli")),
    (arm_integrity_is_reported, needs("ablation")),
    (run_b_achieved_report, needs()),
    # needs() empty: the 4,146 half is corpus-free (run_b_report computes it)
    # and the 390 half compares body against appendix, which is text only.
    (limitation_offharness_matches_emitters, needs()),
    (paper_tab_app_runa, needs()),
    (paper_runa_prose, needs()),
    (paper_runa_opus_prose, needs()),
    (run_a_achieved_report, needs()),
    (opus_arms_reports_both_variables, needs()),
    (rewrite_bound_matches_emitter, needs("ablation")),
    (flat_corpus_integrity, needs()),
    # needs() empty: reads the generator's source, not any corpus.
    (release_declares_its_failures, needs()),
    (action_space_estimands, needs("campaign")),
    # Split from `provenance` on purpose: the gap numbers need the campaign
    # archive and the rule roster does not, so they must not share an excuse.
    (unattested_rules, needs("policy")),
    # needs() empty: it reads audit-archive/ and main.tex, so a machine
    # without the corpus can still hold the paper to its own audit count.
    (audit_rounds,     needs()),
    (provenance,       needs("campaign", "policy")),
    (cross_vendor,     needs("agy")),
    (pilot_contrasts,  needs("api")),
    (rewrite_outcome,  needs("campaign")),
    (platform_battery, needs("platform")),
    (effective_sample, needs()),
    (analyses,         _analyses_needs),
    (hygiene,          needs()),
    # needs() empty on purpose and load-bearing: every control in it builds
    # its own input, and a control excused by a missing corpus would vanish
    # in exactly the situation its subject is least well held down.
    (residual_controls, needs()),
]



def _silent_gates(emitted):
    """The gates that produced no row of any kind. See the call site."""
    return sorted(name for name, rows in emitted.items() if not rows)


def _silent_gate_control():
    """POSITIVE CONTROL: the accounting above, on a gate that said nothing."""
    check("positive control: a gate that emitted nothing is named",
          _silent_gates(collections.OrderedDict(
              [("spoke", 3), ("silent", 0)])), ["silent"])
    check("positive control: a gate that emitted rows is not named",
          _silent_gates(collections.OrderedDict([("spoke", 3)])), [])


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    # Anchored, not assumed. Every relative path in this file is now built
    # from REPO, and the child processes below are given cwd=REPO too, so the
    # suite measures the same thing from paper/ or /tmp as from the root.
    os.chdir(REPO)

    tagged = []
    emitted = collections.OrderedDict()
    for gate, gate_needs in GATES:
        mark = len(FAIL)
        rows = len(PASS) + len(FAIL) + len(SKIP)
        try:
            gate()
        except SystemExit:
            INFO.append((gate.__name__,
                         "scoped out - archive lacks the layout it reads"))
        except Exception as exc:                     # pragma: no cover
            FAIL.append((gate.__name__ + " runs", str(exc)[:60], "ok"))
        emitted[gate.__name__] = (len(PASS) + len(FAIL) + len(SKIP)) - rows
        for row in FAIL[mark:]:
            tagged.append((row, gate_needs(row)))

    is_export = tree_is_export()
    skipped, keep = [], []
    for row, want in tagged:
        gone = _absent(want)
        if gone:
            skipped.append((row[0], _no_corpus(gone), SKIP_ABSENT))
        elif is_export and row[0] in RELEASE_SUBSET:
            skipped.append((row[0], "withheld from the release: %s"
                            % RELEASE_SUBSET[row[0]], SKIP_ABSENT))
        else:
            keep.append(row)
    FAIL[:] = keep

    skipped.extend(SKIP)

    silent = _silent_gates(emitted)
    _silent_gate_control()
    if silent:
        FAIL.append(("every gate reported something",
                     "%d gate(s) emitted no pass, fail or skip: %s"
                     % (len(silent), ", ".join(silent)[:70]),
                     "all %d gates accounted for" % len(GATES)))
    else:
        PASS.append(("every gate reported something",
                     "all %d" % len(GATES)))

    if not args.quiet:
        print("")
        for name, got in PASS:
            print("  ok    %-52s %s" % (name, got))
        for name, value in INFO:
            print("  info  %-52s %s" % (name, value))
    if FAIL:
        print("")
        for row in FAIL:
            name, got = row[0], row[1]
            want = row[2] if len(row) > 2 else ""
            print("  FAIL  %-52s got %s, want %s" % (name, got, want))
    def _kind(row):
        return row[2] if len(row) > 2 else SKIP_ABSENT

    absent = [s for s in skipped if _kind(s) != SKIP_UNMEASURED]
    unmeasured = [s for s in skipped if _kind(s) == SKIP_UNMEASURED]

    if skipped:
        def _by_reason(rows):
            grouped = collections.OrderedDict()
            for row in rows:
                grouped.setdefault(row[1], []).append(row[0])
            return grouped

        if unmeasured:
            print("")
            print("  " + "!" * 68)
            print("  !! %d gate(s) NOT MEASURED. The corpus is present and the"
                  " run happened;" % len(unmeasured))
            print("  !! it produced no such evidence. NO CORPUS WILL SUPPLY"
                  " THIS - the")
            print("  !! measurement has to be taken. Any claim in the paper"
                  " that rests on")
            print("  !! one of these is unsupported prose, not a number"
                  " awaiting transfer.")
            print("  " + "!" * 68)
            for reason, names in _by_reason(unmeasured).items():
                print("")
                print("    %s (%d gate(s)):" % (reason, len(names)))
                for name in names:
                    print("      NOT MEASURED  %s" % name)

        if absent:
            print("")
            print("  %d gate(s) SKIPPED - each one named, each with the reason"
                  " IT could not run," % len(absent))
            print("  not because some other gate could not. Not failures;"
                  " supply the input and re-run.")
            for reason, names in _by_reason(absent).items():
                print("")
                print("    %s (%d gate(s)):" % (reason, len(names)))
                for name in names:
                    print("      skip  %s" % name)
        print("")
        print("  present: %s"
              % ", ".join(k for k in sorted(CORPUS)
                          if k != "none" and present(k)))
        print("  absent:  %s"
              % ", ".join(k for k in sorted(CORPUS)
                          if k != "none" and not present(k)))

    print("")
    # The tally names the unmeasured subset rather than folding it into
    # "skipped", so a reader who only ever sees this line still learns that
    # something was never measured instead of merely being elsewhere.
    print("%d passed, %d failed%s%s"
          % (len(PASS), len(FAIL),
             ", %d skipped" % len(skipped) if skipped else "",
             " (%d NOT MEASURED)" % len(unmeasured) if unmeasured else ""))
    return len(FAIL)


if __name__ == "__main__":
    sys.exit(main())
