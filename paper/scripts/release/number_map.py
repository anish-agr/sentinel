#!/usr/bin/env python3
"""The second file DATA-RELEASE.md section 4 requires, in both directions."""

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
AUDIT = os.path.join(REPO, "paper", "audit-archive", "number-map-r1.md")
MAIN_TEX = os.path.join(REPO, "paper", "main.tex")
OUT_MD = os.path.join(REPO, "paper", "NUMBER-MAP.md")
OUT_JSON = os.path.join(REPO, "paper", "number-map.json")

# What the release ships, from make_artifact.ARCHIVE_GLOB_PREFIX.
SHIPPED_PREFIX = "denials"

FAMILIES = [
    {"id": "post-denial-distribution",
     "published": "39.9 / 38.2 / 10.1 / 9.0 / 1.9 / 0.9 % "
                  "(override / argue / comply / reroute / stop / other)",
     "command": "python paper/scripts/analysis/responses.py",
     "needs": "deny_decisions",
     "needs_text": "at least one `guard_decision` event with "
                   "`meta.verdict == deny`"},
    {"id": "own-action-space",
     "published": "+13.1 pts [+8.6, +17.6] shell vs structured refusal",
     "command": "python paper/scripts/analysis/own_action_space.py",
     "needs": "deny_and_tool_calls",
     "needs_text": "deny decisions and `tool_call` events in the same archive"},
    {"id": "override-by-arm",
     "published": "48.0% (full, 47/98); exactly 0.0% on terse / explain / "
                  "padded / defer, on 125 / 108 / 105 / 78 events",
     "command": "python paper/scripts/figures/tables.py "
                "(emits paper/figures/tab-ablation.tex)",
     "command_note":
         "`python paper/scripts/analysis/ablation.py` is the analysis behind "
         "this family, but its default output POOLS THE FAMILY-COVERAGE "
         "SUPPLEMENT (terse +56, explain +42, defer +14, full +21) and "
         "therefore prints 51.3% (61/119) and denominators 181 / 150 / 105 / "
         "92. That is the same contrast over a wider population, not a "
         "different answer; the published table is the main arms alone. "
         "`tables.py --check` re-derives the published table from the corpus "
         "and `verify_all.py`'s `table tab-ablation.tex is fresh` gate holds "
         "it against the data.",
     "needs": "deny_and_arm",
     "needs_text": "deny decisions and an arm the records or the archive name "
                   "identify"},
    {"id": "override-by-model",
     "published": "48.0 / 32.0 / 7.3 % (haiku / opus / sonnet)",
     "command": "python paper/scripts/analysis/models.py",
     "needs": "deny_and_model",
     "needs_text": "deny decisions and a model identifier in the records"},
    {"id": "denial-yield-per-session",
     "published": "0.66 denial events per session",
     "command": "python paper/scripts/analysis/rigor.py",
     "needs": "deny_and_sessions",
     "needs_text": "deny decisions and at least one data-carrying session "
                   "record"},
    {"id": "machine-write-rate",
     "published": "4.2% of sessions write outside the checkout",
     "command": "python paper/scripts/analysis/machine_writes.py",
     "needs": "file_mutations",
     "needs_text": "at least one `file_mutation` event"},
    {"id": "truncation-exposure",
     "published": "51 / 391 = 13.0%; longest denied command 1,512 chars",
     "command": "python paper/scripts/analysis/e1_truncation.py",
     "needs": "result_json",
     "needs_text": "at least one `result.json`"},
    {"id": "thought-token-sweep",
     "published": "per-level thought tokens per model (appendix sweep tables)",
     "command": "python paper/scripts/analysis/precision.py",
     "needs": "thought_tokens",
     "needs_text": "at least one record carrying a `thought_tokens` field; a "
                   "zero at the `off` and `minimal` levels is the measurement "
                   "for those levels, not an absence"},
]

ARMS = ("terse", "explain", "padded", "defer", "full", "control", "main")


# --------------------------------------------------------------------------
# Direction A


ROW = re.compile(r"^\|(.*)\|\s*$")


def split_row(line):
    inner = ROW.match(line)
    if not inner:
        return None
    cells = [c.strip() for c in inner.group(1).split("|")]
    if all(set(c) <= set("-: ") for c in cells):
        return None
    return cells


def parse_audit(path):
    """Parse the round-1 audit's three table shapes. Mechanical, not retyped."""
    contradicted, untraceable, mapped = [], [], []
    section = None
    try:
        with io.open(path, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return contradicted, untraceable, mapped, False
    for line in lines:
        if line.startswith("## 1.1"):
            section = "C"
            continue
        if line.startswith("## 1.2"):
            section = "U"
            continue
        if line.startswith("## 2."):
            section = "M"
            continue
        if line.startswith("# ") or (line.startswith("## ")
                                     and not line.startswith("## 2.")):
            if not line.startswith("## 1."):
                section = None
        cells = split_row(line)
        if not cells or section is None:
            continue
        if section == "C" and len(cells) >= 6 and cells[0].startswith("C"):
            contradicted.append({"id": cells[0], "value": cells[1],
                                 "lines": cells[2], "claim": cells[3],
                                 "what_the_tree_says": cells[4],
                                 "why": cells[5], "status": "CONTRADICTED"})
        elif section == "U" and len(cells) >= 5 and cells[0].startswith("U"):
            untraceable.append({"id": cells[0], "value": cells[1],
                                "lines": cells[2], "claim": cells[3],
                                "note": cells[4], "status": "UNTRACEABLE"})
        elif section == "M" and len(cells) >= 5 and cells[0] != "value":
            mapped.append({"value": cells[0], "lines": cells[1],
                           "claim": cells[2], "emitting_command": cells[3],
                           "status": cells[4]})
    return contradicted, untraceable, mapped, True


NUMTOK = re.compile(r"-?\d[\d,]*(?:\.\d+)?")


def normalise_tex(tex):
    """LaTeX spells a thousands separator `2{,}847`, not `2,847`."""
    flat = tex.replace("{,}", ",").replace("{}", "")
    for junk in ("\\,", "\\!", "\\;", "~", "$", "{", "}"):
        flat = flat.replace(junk, "")
    return flat, flat.replace(",", "")


def still_in_main_tex(value, tex_pair):
    """Does the literal value still appear in `main.tex`?"""
    flat, nocomma = tex_pair
    raw = value.strip().strip("`")
    toks = [t for t in NUMTOK.findall(raw) if t]
    for tok in toks:
        if tok in flat or tok.replace(",", "") in nocomma:
            return True
    if raw and raw in flat:
        return True
    if not toks:
        return None
    return False


def direction_a():
    contradicted, untraceable, mapped, ok = parse_audit(AUDIT)
    try:
        with io.open(MAIN_TEX, encoding="utf-8") as fh:
            tex = fh.read()
    except OSError:
        tex = ""
    pair = normalise_tex(tex) if tex else None
    for row in contradicted + untraceable + mapped:
        row["present_in_main_tex_today"] = still_in_main_tex(row["value"], pair) \
            if pair else None
    return {
        "source": "paper/audit-archive/number-map-r1.md",
        "source_parsed": ok,
        "source_note": (
            "the round-1 provenance audit, 2026-08-22: it tokenised main.tex "
            "(1,325 numeric tokens, 518 distinct values), executed every "
            "candidate emitter in paper/scripts/, and adjudicated 154 distinct "
            "numeric claims. Its tables are parsed here, not retyped."),
        "recheck": "every row is re-checked against paper/main.tex as it is "
                   "today; `present_in_main_tex_today` is that check",
        "totals": {"mapped_rows": len(mapped),
                   "contradicted_entries": len(contradicted),
                   "untraceable_entries": len(untraceable)},
        "orphans": {
            "definition": "a published number with no command that emits it "
                          "(UNTRACEABLE), or one a command contradicts "
                          "(CONTRADICTED). Both are unsupported as printed.",
            "contradicted": contradicted,
            "untraceable": untraceable,
        },
        "mapped": mapped,
    }


# --------------------------------------------------------------------------
# Direction B


def scan_archive(base):
    """Which published-number inputs does this archive actually carry?"""
    caps = {"deny_decisions": 0, "tool_calls": 0, "file_mutations": 0,
            "result_json": 0, "sessions_carrying": 0, "thought_tokens": 0,
            "thought_tokens_nonzero": 0, "guard_events": 0, "records": 0}
    models, arms, rules = set(), set(), set()
    name = os.path.basename(base)
    for arm in ARMS:
        if ("-" + arm + "-") in name or name.endswith("-" + arm):
            arms.add(arm)
    for root, dirs, names in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for fname in names:
            p = os.path.join(root, fname)
            if fname == "result.json":
                caps["result_json"] += 1
                rec = _load(p)
                if isinstance(rec, dict):
                    mu = rec.get("modelUsage")
                    if isinstance(mu, dict):
                        models |= {k for k in mu if isinstance(k, str)}
                continue
            if not fname.endswith(".jsonl"):
                continue
            try:
                with io.open(p, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            # Cheap prefilter: most event logs carry no guard decision at all.
            has_guard = "guard_decision" in text
            for line in text.split("\n"):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict):
                    continue
                caps["records"] += 1
                kind = rec.get("kind")
                if kind == "tool_call":
                    caps["tool_calls"] += 1
                elif kind == "file_mutation":
                    caps["file_mutations"] += 1
                elif kind == "guard_decision" and has_guard:
                    caps["guard_events"] += 1
                    meta = rec.get("meta") or {}
                    if str(meta.get("verdict") or rec.get("decision")
                           or "").lower() == "deny":
                        caps["deny_decisions"] += 1
                        if meta.get("rule"):
                            rules.add(meta["rule"])
                if kind is None:
                    # a session record rather than an event
                    if _carries(rec):
                        caps["sessions_carrying"] += 1
                    if "thought_tokens" in rec:
                        caps["thought_tokens"] += 1
                        if (rec.get("thought_tokens") or 0) > 0:
                            caps["thought_tokens_nonzero"] += 1
                    m = rec.get("model")
                    if isinstance(m, str) and m:
                        models.add(m)
                    a = rec.get("arm") or rec.get("message")
                    if isinstance(a, str) and a:
                        arms.add(a)
    return caps, sorted(models), sorted(arms), sorted(rules)


def _load(p):
    try:
        with io.open(p, encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def _carries(rec):
    u = rec.get("usage")
    if isinstance(u, dict):
        if u.get("api_error"):
            return False
        total = u.get("total_tokens") or 0
        if not total:
            total = (u.get("input_tokens") or 0) + (u.get("output_tokens") or 0)
    else:
        total = rec.get("total_tokens") or 0
    outcome = str(rec.get("outcome") or rec.get("status") or "")
    if outcome.startswith("api-error") or outcome == "ERROR":
        return False
    if rec.get("is_error"):
        return False
    return bool(total)


def satisfies(need, caps, models, arms):
    if need == "deny_decisions":
        return caps["deny_decisions"] > 0
    if need == "deny_and_tool_calls":
        return caps["deny_decisions"] > 0 and caps["tool_calls"] > 0
    if need == "deny_and_arm":
        return caps["deny_decisions"] > 0 and bool(arms)
    if need == "deny_and_model":
        return caps["deny_decisions"] > 0 and bool(models)
    if need == "deny_and_sessions":
        return caps["deny_decisions"] > 0 and caps["sessions_carrying"] > 0
    if need == "file_mutations":
        return caps["file_mutations"] > 0
    if need == "result_json":
        return caps["result_json"] > 0
    if need == "thought_tokens":
        return caps["thought_tokens"] > 0
    return False


def direction_b():
    shipped, withheld = [], []
    for entry in sorted(os.listdir(DATA)):
        p = os.path.join(DATA, entry)
        if not os.path.isdir(p):
            continue
        (shipped if entry.startswith(SHIPPED_PREFIX) else withheld).append(entry)

    rows = []
    for name in shipped:
        caps, models, arms, rules = scan_archive(os.path.join(DATA, name))
        feeds = [f["id"] for f in FAMILIES
                 if satisfies(f["needs"], caps, models, arms)]
        blocked = []
        for f in FAMILIES:
            if f["id"] in feeds:
                continue
            blocked.append({"number": f["id"],
                            "cannot_feed_because": "the archive carries no %s"
                                                   % f["needs_text"]})
        rows.append({
            "archive": name,
            "inputs": caps,
            "models": models,
            "arms": arms,
            "rules_denied": rules,
            "feeds": feeds,
            "cannot_feed": blocked,
            "orphan": not feeds,
        })

    orphans = [r for r in rows if r["orphan"]]
    no_deny = [r for r in rows if r["inputs"]["deny_decisions"] == 0]
    return {
        "shipped_archives": len(rows),
        "definition": (
            "an archive is an orphan when it carries the input for none of the "
            "published number families below. The predicates are necessary "
            "conditions read off the archive's own records, so a negative is "
            "sound: an archive with no deny decision cannot contribute to a "
            "post-denial rate. A positive means the archive carries the input "
            "the command reads, not that the published value was computed "
            "over it."),
        "families": FAMILIES,
        "rows": rows,
        "orphans": [r["archive"] for r in orphans],
        "orphan_detail": orphans,
        "no_post_denial_number": [r["archive"] for r in no_deny],
        "no_post_denial_note": (
            "%d of %d shipped archives contain zero deny decisions and "
            "therefore feed no post-denial number. Most are small cells; "
            "whether that is thin sampling or dead weight is a judgement "
            "nobody has recorded, and recording it is the point of this file."
            % (len(no_deny), len(rows))),
        "withheld_archives": withheld,
        "withheld_note": (
            "%d archives under paper/data are not shipped: the builder ships "
            "only `%s*` (make_artifact.ARCHIVE_GLOB_PREFIX). DATA-RELEASE.md 3 "
            "requires withheld items to be listed by name with the reason, so "
            "they are listed here." % (len(withheld), SHIPPED_PREFIX)),
    }


class CorpusTooThin(Exception):
    """The scan cannot describe the release, so its output must not be kept."""


def corpus_sufficiency(b):
    """Preconditions on direction B before the committed map may be replaced."""
    n_arch = b["shipped_archives"]
    denies = sum(r["inputs"]["deny_decisions"] for r in b["rows"])
    prior = None
    try:
        with io.open(OUT_JSON, encoding="utf-8") as fh:
            prior = (json.load(fh).get("direction_b") or {}).get(
                "shipped_archives")
    except Exception:
        prior = None

    if n_arch == 0:
        raise CorpusTooThin(
            "P1: no archive under paper/data begins with `%s`, so there is no "
            "direction B to write." % SHIPPED_PREFIX)
    if denies == 0:
        raise CorpusTooThin(
            "P2: %d archive(s) found and not one deny decision among them. "
            "Every published number in this map is downstream of a guard "
            "denial, and the archives that carry the event logs "
            "(`paper/data/denials*/`) are gitignored, so a clone has the "
            "directory names and none of the evidence. This scan is measuring "
            "an absent corpus." % n_arch)
    if prior is not None and n_arch < prior:
        raise CorpusTooThin(
            "P3: the committed map describes %d shipped archives and this scan "
            "found %d. A scan that sees less corpus than the map does must not "
            "replace it." % (prior, n_arch))
    return {"shipped_archives": n_arch, "deny_decisions": denies,
            "committed_map_archives": prior,
            "checked": ["P1 at least one shipped archive",
                        "P2 at least one deny decision in the corpus",
                        "P3 no shrinkage against the committed map"]}


def _builder_lists():
    """INCLUDE_DIRS / INCLUDE_DATA_FILES, read out of make_artifact.py."""
    import ast
    path = os.path.join(REPO, "paper", "scripts", "make_artifact.py")
    out = {"dirs": [], "files": []}
    try:
        tree = ast.parse(io.open(path, encoding="utf-8").read())
    except Exception:
        return out
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not node.targets:
            continue
        tgt = node.targets[0]
        if not isinstance(tgt, ast.Name):
            continue
        if tgt.id not in ("INCLUDE_DIRS", "INCLUDE_DATA_FILES",
                          "INCLUDE_FILES"):
            continue
        try:
            vals = ast.literal_eval(node.value)
        except Exception:
            continue
        for v in vals:
            (out["dirs"] if tgt.id == "INCLUDE_DIRS" else out["files"]).append(v)
    return out


_SHIPPED_OTHERWISE = None


def ships_by_another_route(name):
    """Is this paper/data entry in the release under a rule other than the
    `denials*` archive sweep? Returns the rule, or None."""
    global _SHIPPED_OTHERWISE
    if _SHIPPED_OTHERWISE is None:
        _SHIPPED_OTHERWISE = _builder_lists()
    rel = "paper/data/" + name
    for d in _SHIPPED_OTHERWISE["dirs"]:
        if d == rel:
            return "make_artifact.INCLUDE_DIRS"
    hits = [f for f in _SHIPPED_OTHERWISE["files"]
            if f == rel or f.startswith(rel + "/")]
    if hits:
        return ("make_artifact.INCLUDE_DATA_FILES (%d file%s)"
                % (len(hits), "" if len(hits) == 1 else "s"))
    return None


def withheld_reason(name):
    route = ships_by_another_route(name)
    if route:
        return ("NOT WITHHELD - outside the `%s*` archive sweep but shipped "
                "by `%s`." % (SHIPPED_PREFIX, route))
    if name.startswith("probe-"):
        return ("a probe cell: a few sessions run to check a model/thinking "
                "combination answers at all. Feeds no published number.")
    if name.startswith("armcheck-"):
        return ("an arm-integrity spot check, run to confirm the arm text "
                "reached the model. Feeds no published number.")
    if name.startswith("famcheck"):
        return ("a task-family spot check, run to confirm the deficit-first "
                "picker was spreading families. Feeds no published number.")
    if name.startswith("ovr-check"):
        return ("an override-path spot check, run to confirm the override "
                "string reached the model. Feeds no published number.")
    if name.startswith("thruput"):
        return "a throughput measurement of the harness, not of the guard."
    if name.startswith("events") or name.startswith("."):
        return "instrument state, not a collection archive."
    if name in ("archive", "external"):
        return ("a holding directory for material collected elsewhere; it "
                "carries no session records of its own and feeds no published "
                "number.")
    if name == "incidents":
        return ("startup and daemon-incident artifacts from the operators' own "
                "machines. Retained as evidence about the instrument; withheld "
                "because they are machine state rather than collection data, "
                "and because they carry operator paths the scrub is not the "
                "right place to fix.")
    return ("outside `%s*`, which is the only prefix the builder's archive "
            "sweep ships, and not named in INCLUDE_DIRS or "
            "INCLUDE_DATA_FILES either." % SHIPPED_PREFIX)


# --------------------------------------------------------------------------


def render(doc, path):
    w = sys.stdout if path == "-" else io.open(path, "w", encoding="utf-8",
                                               newline="\n")
    W = w.write
    a, b = doc["direction_a"], doc["direction_b"]
    W("# Archive to published number to command, in both directions\n\n")
    W("Snapshot %s. Generated by `%s`.\n\n"
      % (doc["generated_utc"], doc["generator"]))
    W("`DATA-RELEASE.md` section 4: *\"A second file maps archive -> published "
      "number -> the command that computes it, in both directions. A number "
      "with no command is unsupported. An archive feeding no number is either "
      "dead weight or a result nobody wrote up.\"*\n\n")
    W("Both orphan lists below are complete. Neither is trimmed: an orphan "
      "list curated by the party it embarrasses is not evidence.\n\n")

    W("---\n\n## Direction A - published number -> command\n\n")
    W("%s\n\n" % a["source_note"])
    W("| status | entries |\n|---|---:|\n")
    W("| mapped rows in the audit's full table | %d |\n"
      % a["totals"]["mapped_rows"])
    W("| **CONTRADICTED** - a command emits a different value | **%d** |\n"
      % a["totals"]["contradicted_entries"])
    W("| **UNTRACEABLE** - no command emits it, no artifact supports it | "
      "**%d** |\n" % a["totals"]["untraceable_entries"])
    stale = [r for r in a["orphans"]["contradicted"] + a["orphans"]["untraceable"]
             if r.get("present_in_main_tex_today") is False]
    W("\n%d of the %d orphaned claims no longer appear in `main.tex` as "
      "written; they are marked below.\n\n"
      % (len(stale), a["totals"]["contradicted_entries"]
         + a["totals"]["untraceable_entries"]))

    W("### A1 - UNTRACEABLE: no command emits it (complete list, %d)\n\n"
      % a["totals"]["untraceable_entries"])
    W("| # | value | main.tex line(s) | claim | why nothing emits it | still "
      "in main.tex |\n|---|---|---|---|---|---|\n")
    for r in a["orphans"]["untraceable"]:
        W("| %s | %s | %s | %s | %s | %s |\n"
          % (r["id"], r["value"], r["lines"], _cell(r["claim"]),
             _cell(r["note"]), _yn(r.get("present_in_main_tex_today"))))

    W("\n### A2 - CONTRADICTED: a command emits a different value (complete "
      "list, %d)\n\n" % a["totals"]["contradicted_entries"])
    W("| # | value | main.tex line(s) | claim | what the tree says | why | "
      "still in main.tex |\n|---|---|---|---|---|---|---|\n")
    for r in a["orphans"]["contradicted"]:
        W("| %s | %s | %s | %s | %s | %s | %s |\n"
          % (r["id"], r["value"], r["lines"], _cell(r["claim"]),
             _cell(r["what_the_tree_says"]), _cell(r["why"]),
             _yn(r.get("present_in_main_tex_today"))))

    W("\n---\n\n## Direction B - archive -> published number\n\n")
    W("%s\n\n" % b["definition"])
    W("### The number families and the command for each\n\n")
    W("| number | published value | command | the input it needs |\n"
      "|---|---|---|---|\n")
    for f in b["families"]:
        W("| `%s` | %s | `%s` | %s |\n"
          % (f["id"], f["published"], f["command"], f["needs_text"]))
    notes = [f for f in b["families"] if f.get("command_note")]
    if notes:
        W("\nWhere the obvious command emits a different number, the "
          "difference is stated rather than left for a reviewer to find:\n\n")
        for f in notes:
            W("- **`%s`** - %s\n" % (f["id"], f["command_note"]))

    W("\n### B1 - orphaned archives: shipped, feeding no published number "
      "(complete list, %d of %d)\n\n"
      % (len(b["orphans"]), b["shipped_archives"]))
    if not b["orphans"]:
        W("None. Every shipped archive carries the input for at least one "
          "published number.\n\n")
    else:
        W("| archive | records | deny | tool calls | sessions carrying | "
          "result.json |\n|---|---:|---:|---:|---:|---:|\n")
        for r in b["orphan_detail"]:
            i = r["inputs"]
            W("| `%s` | %d | %d | %d | %d | %d |\n"
              % (r["archive"], i["records"], i["deny_decisions"],
                 i["tool_calls"], i["sessions_carrying"], i["result_json"]))

    W("\n### B2 - archives feeding no POST-DENIAL number (complete list, "
      "%d of %d)\n\n"
      % (len(b["no_post_denial_number"]), b["shipped_archives"]))
    W("%s\n\n" % b["no_post_denial_note"])
    W("| archive | records | sessions carrying | tool calls | feeds |\n"
      "|---|---:|---:|---:|---|\n")
    by_name = {r["archive"]: r for r in b["rows"]}
    for name in b["no_post_denial_number"]:
        r = by_name[name]
        i = r["inputs"]
        W("| `%s` | %d | %d | %d | %s |\n"
          % (name, i["records"], i["sessions_carrying"], i["tool_calls"],
             ", ".join(r["feeds"]) or "**nothing**"))

    W("\n### B2b - per number, every shipped archive that cannot feed it "
      "(complete)\n\n")
    W("A number-by-number view of the same data. Each list is every archive "
      "that lacks that number's input, named in full.\n\n")
    W("| number | archives that can feed it | archives that cannot |\n"
      "|---|---:|---:|\n")
    cannot = {}
    for f in b["families"]:
        cannot[f["id"]] = [r["archive"] for r in b["rows"]
                           if f["id"] not in r["feeds"]]
        W("| `%s` | %d | %d |\n"
          % (f["id"], b["shipped_archives"] - len(cannot[f["id"]]),
             len(cannot[f["id"]])))
    for f in b["families"]:
        lst = cannot[f["id"]]
        W("\n**`%s`** - %d archive(s) cannot feed it, because each carries no "
          "%s:\n\n" % (f["id"], len(lst), f["needs_text"]))
        if not lst:
            W("_none: every shipped archive carries this input._\n")
        else:
            W("```\n")
            for name in lst:
                W("%s\n" % name)
            W("```\n")

    W("\n### B3 - every shipped archive and what it feeds\n\n")
    W("| archive | deny | tool calls | file mutations | sessions carrying | "
      "result.json | feeds |\n|---|---:|---:|---:|---:|---:|---|\n")
    for r in b["rows"]:
        i = r["inputs"]
        W("| `%s` | %d | %d | %d | %d | %d | %s |\n"
          % (r["archive"], i["deny_decisions"], i["tool_calls"],
             i["file_mutations"], i["sessions_carrying"], i["result_json"],
             ", ".join(r["feeds"]) or "**nothing**"))

    W("\n### B4 - withheld archives, by name with the reason (%d)\n\n"
      % len(b["withheld_archives"]))
    W("%s\n\n" % b["withheld_note"])
    W("| archive | reason it is not in the release |\n|---|---|\n")
    for name in b["withheld_archives"]:
        W("| `%s` | %s |\n" % (name, withheld_reason(name)))
    if w is not sys.stdout:
        w.close()


def _cell(s):
    return (s or "").replace("|", "\\|").replace("\n", " ")


def _yn(v):
    if v is None:
        return "prose claim - not literally checkable"
    return "yes" if v else "**no**"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stdout", action="store_true",
                    help="print the rendered map and write no files. Always "
                         "permitted: it cannot destroy the committed map.")
    ap.add_argument("--check", action="store_true",
                    help="scan and report whether the corpus here can produce "
                         "a map, then exit without writing. Exit 3 if not.")
    args = ap.parse_args()

    doc = {
        "schema": "archive-number-command-map/1",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generator": "paper/scripts/release/number_map.py",
        "specification": "paper/DATA-RELEASE.md section 4, second paragraph",
        "direction_a": direction_a(),
        "direction_b": direction_b(),
    }
    names = doc["direction_b"]["withheld_archives"]
    doc["direction_b"]["withheld_reasons"] = {n: withheld_reason(n)
                                              for n in names}
    # SPLIT, because the note used to say all of them were withheld and some
    # of them ship. An inaccurate withheld list is worse than none: it is the
    # one place a reviewer checks the release against its own promises.
    elsewhere = sorted(n for n in names if ships_by_another_route(n))
    doc["direction_b"]["shipped_by_another_route"] = elsewhere
    doc["direction_b"]["withheld_note"] = (
        "%d entries under `paper/data` are outside the `%s*` archive sweep. "
        "%d of them ship anyway, through `INCLUDE_DIRS` or "
        "`INCLUDE_DATA_FILES`, and are marked NOT WITHHELD below. The "
        "remaining %d are genuinely withheld and DATA-RELEASE.md 3 requires "
        "each to be named with its reason, which is what this table is."
        % (len(names), SHIPPED_PREFIX, len(elsewhere),
           len(names) - len(elsewhere)))

    a, b = doc["direction_a"], doc["direction_b"]
    print("  direction A: %d mapped rows, %d contradicted, %d untraceable"
          % (a["totals"]["mapped_rows"], a["totals"]["contradicted_entries"],
             a["totals"]["untraceable_entries"]))
    print("  direction B: %d shipped archives, %d feeding no number, "
          "%d feeding no post-denial number"
          % (b["shipped_archives"], len(b["orphans"]),
             len(b["no_post_denial_number"])))
    try:
        doc["corpus_sufficiency"] = corpus_sufficiency(b)
        thin = None
    except CorpusTooThin as exc:
        thin = exc
        doc["corpus_sufficiency"] = {"sufficient": False, "reason": str(exc)}
    if args.stdout:
        if thin:
            sys.stderr.write(
                "number_map: %s\nnumber_map: printing anyway (--stdout writes "
                "nothing), but this map does not describe the release.\n"
                % thin)
        render(doc, "-")
        return 3 if thin else 0
    if thin:
        exc = thin
        sys.stderr.write("number_map: %s\n" % exc)
        sys.stderr.write(
            "number_map: REFUSING TO WRITE. paper/NUMBER-MAP.md and\n"
            "  paper/number-map.json are unchanged. Overwriting them from a\n"
            "  tree without the corpus replaces the map with a stub and used\n"
            "  to exit 0 while doing it.\n"
            "  To see what this tree does support, without writing:\n"
            "      python paper/scripts/release/number_map.py --stdout\n"
            "  To regenerate for real, run on the collection machine, where\n"
            "  paper/data/denials*/ is present.\n")
        return 3
    if args.check:
        print("  corpus sufficient: %d archives, %d deny decisions"
              % (doc["corpus_sufficiency"]["shipped_archives"],
                 doc["corpus_sufficiency"]["deny_decisions"]))
        return 0
    render(doc, OUT_MD)
    io.open(OUT_JSON, "w", encoding="utf-8", newline="\n").write(
        json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print("  wrote %s" % os.path.relpath(OUT_MD, REPO))
    print("  wrote %s" % os.path.relpath(OUT_JSON, REPO))
    return 0


if __name__ == "__main__":
    sys.exit(main())
