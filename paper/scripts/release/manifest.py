#!/usr/bin/env python3
"""The DATA-RELEASE.md section 4 integrity manifest: one entry per released file."""

import argparse
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

MANIFEST_NAME = "MANIFEST.jsonl"
SHA_MANIFEST_NAME = "MANIFEST.sha256"

OFF_INSTRUMENT_NAME = "paper/run-b-excluded-sessions.txt"
_DECLARED_COUNT_RE = re.compile(r"^#\s*count\s+(\d+)\s*$")

# The campaign's declared stop, from run-b-declaration.md: 787 raw denial
# events per arm, or $600, or this instant - whichever binds first. An archive
# a campaign is still collecting into is partial by declaration, not by guess.
RUN_B_DECLARED_STOP = "2026-08-27T06:00:00Z"
# An archive that received a record inside this window before the snapshot is
# being written to now.
LIVE_WINDOW_HOURS = 24

SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache", ".mypy_cache"}

HARNESS = {
    "api": {"script": "paper/scripts/api/run_api.py",
            "evidence": "run_api.py:1076 opens <archive>/usage.jsonl for append"},
    "antigravity": {"script": "paper/scripts/gemini/run-agy.sh",
                    "evidence": "run-agy.sh:572 appends to "
                                "<archive>/sessions.jsonl"},
    "cli": {"script": "paper/scripts/denials/run-denials.sh",
            "evidence": "run-denials.sh:430 writes <archive>/sessions.w<N>.jsonl "
                        "through paper/scripts/denials/tally.py"},
}
INSTRUMENT_WRITES = ("guard event logs are written by the collecting binary "
                     "(target/release/sentinel-hook), not by the harness")

REASONS = {
    "R-not-record":
        "not a record file. Section 4's record count and its three-way "
        "reconciliation apply to the data files. A line count over source code "
        "or prose would be the line-versus-record conflation this project has "
        "hit four times, so it is not offered here.",
    "R-no-ts-field":
        "this record shape carries no timestamp field. The file mtime is "
        "deliberately NOT substituted: an mtime is when the bytes were last "
        "written, and section 4 asks for the record timestamp. The archive "
        "rollup in this header carries the archive's first and last record "
        "timestamp, taken from its guard event logs.",
    "R-ts-from-records":
        "read from the records' own `ts` field, at the resolution the "
        "instrument wrote it - nanoseconds in the guard event logs.",
    "R-binary-off-instrument":
        "this session is on the off-instrument list, so the binary that "
        "decided it was NOT the pinned instrument and the pin must not be "
        "asserted over it. The two replacement hashes and the two windows are "
        "in `paper/run-b-excluded-sessions.txt`; which of them decided a "
        "given session is not recorded per session, so nothing is claimed "
        "here beyond that it was not the pinned one.",
    "R-off-instrument":
        "this session was collected while the guard binary on disk was not "
        "the pinned instrument, so it was decided by a different rule set. It "
        "is retained and shipped - a run collected against a changed "
        "instrument is evidence about the instrument - and it is excluded "
        "from every pooled figure by the corpus walk. The list, its two "
        "windows and their causes are `paper/run-b-excluded-sessions.txt`.",
    "R-vendor-verbatim":
        "the vendor's fields ship verbatim in the file this entry describes. "
        "The scrub rewrites machine paths and operator identity only, and "
        "touches no model identifier, token account, service tier, finish "
        "reason or request id.",
    "R-model-from-archive":
        "this file states no model of its own; the identifiers given are the "
        "ones the archive's own session records carry.",
    "R-binary-predates":
        "every record in this file predates the instrument attestation. The "
        "binary in force was not hashed at the time, and asserting the pinned "
        "hash over it would be a fabricated provenance claim.",
    "R-binary-spans":
        "this file's records span the attestation instant: those at or after "
        "it were collected under the attested binary, those before it by a "
        "binary whose hash nobody recorded.",
    "R-binary-inside":
        "every record in this file is at or after the instant the binary at "
        "this hash was first recorded at the hook path.",
    "R-binary-no-ts":
        "this file carries no record timestamp, so it cannot be placed inside "
        "or outside the instrument's attestation window. The archive rollup "
        "carries the archive's own window.",
    "R-binary-not-instrument":
        "not produced by the collecting binary.",
    "R-script-none":
        "not produced by a collection run.",
    "R-script-ambiguous":
        "the archive's layout does not identify a single harness.",
    "R-event-log-writer":
        "the script named drove the session; the event records themselves were "
        "written by the collecting binary, not by the harness.",
    "R-not-an-archive":
        "not part of a collection archive: this is an analysis script, a "
        "document, a redistributed third-party corpus or a rater label file.",
    "R-disagreement":
        "M1 counts non-empty lines, M2 counts lines that parse as a JSON "
        "object, M3 counts data-carrying records under gradient.sh's rule. "
        "Where they differ the entry gives all three and the cause. Nothing is "
        "reconciled: the disagreement is the finding.",
    "R-status-see-rollup":
        "an entry gives `archive_status` only. The REASON for that status is "
        "given once, in this header's `archives` rollup under the archive's "
        "own name, rather than repeated on each of the archive's files.",
}

RECORD_FILES = re.compile(r"^(usage\.jsonl|sessions\.jsonl|sessions\.w\d+\.jsonl)$")
SESSION_JSON = ("result.json", "label.json")
META_JSON = ("manifest.json", "campaign.json")
SET_ASIDE_DIRS = ("events.quarantined", "events.incomplete", "events.staging")
QUARANTINE_DIRS = ("events.quarantined",)
UNHOOKED = re.compile(r"(^|/)[^/]*\.unhooked(/|$)")
PRE_PRUNE = re.compile(r"\.pre-prune$")


# --------------------------------------------------------------------------
# counting


def carries_data(rec):
    """`gradient.sh`'s rule over any of the three record shapes."""
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


def is_event_record(rec):
    """A structurally complete guard/harness event. Torn writes fail this."""
    return bool(rec.get("ts")) and bool(rec.get("kind"))


def classify(rel, name):
    """(record_kind, harness) for one released path."""
    parts = rel.split("/")
    ext = os.path.splitext(name)[1].lower()
    in_archive = len(parts) > 2 and parts[0] == "paper" and parts[1] == "data" \
        and parts[2].startswith("denials")
    if not in_archive:
        if ext == ".jsonl":
            return "corpus-jsonl", None
        if ext == ".json":
            return "corpus-json", None
        return "not-a-record-file", None
    if RECORD_FILES.match(name):
        if name == "usage.jsonl":
            return "session-record-file", "api"
        if name == "sessions.jsonl":
            return "session-record-file", "antigravity"
        return "session-record-file", "cli"
    if name == "events.jsonl" or (len(parts) > 3 and parts[3] == "events"
                                  and ext == ".jsonl"):
        return "event-log", None
    if name in SESSION_JSON:
        return "session-json", "cli"
    if name in META_JSON:
        return "archive-metadata", None
    if ext == ".jsonl":
        return "event-log", None
    return "not-a-record-file", None


def count_file(path, kind):
    """M1/M2/M3, plus the model ids, vendor keys and record timestamps."""
    out = {"m1_raw_lines": 0, "m2_parsed": 0, "m3_carrying": 0,
           "first_ts": None, "last_ts": None, "models": set(),
           "keys": set(), "torn": 0}
    if kind == "not-a-record-file":
        return out
    single = kind in ("session-json", "archive-metadata", "corpus-json")
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return out
    if single:
        out["m1_raw_lines"] = 1
        try:
            rec = json.loads(text)
        except Exception:
            out["torn"] = 1
            return out
        if not isinstance(rec, dict):
            return out
        out["m2_parsed"] = 1
        if kind == "session-json":
            out["m3_carrying"] = 1 if carries_data(rec) else 0
        else:
            out["m3_carrying"] = 1 if rec else 0
        _harvest(rec, out)
        return out
    for line in text.split("\n"):
        if not line.strip():
            continue
        out["m1_raw_lines"] += 1
        try:
            rec = json.loads(line)
        except Exception:
            out["torn"] += 1
            continue
        if not isinstance(rec, dict):
            continue
        out["m2_parsed"] += 1
        if kind == "event-log":
            if is_event_record(rec):
                out["m3_carrying"] += 1
        elif kind == "session-record-file":
            if carries_data(rec):
                out["m3_carrying"] += 1
        else:
            if rec:
                out["m3_carrying"] += 1
        _harvest(rec, out)
    return out


def _harvest(rec, out):
    """Model identifier, vendor metadata keys and record timestamp, as found."""
    for k in rec.keys():
        out["keys"].add(k)
    m = rec.get("model")
    if isinstance(m, str) and m:
        out["models"].add(m)
    mu = rec.get("modelUsage")
    if isinstance(mu, dict):
        for k in mu:
            if isinstance(k, str) and k:
                out["models"].add(k)
    ts = rec.get("ts") or rec.get("timestamp")
    if isinstance(ts, str) and ts:
        if out["first_ts"] is None or ts < out["first_ts"]:
            out["first_ts"] = ts
        if out["last_ts"] is None or ts > out["last_ts"]:
            out["last_ts"] = ts


def sha256_and_size(path):
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


# --------------------------------------------------------------------------
# provenance read out of the repository at build time


def git_commit(repo, relpath):
    try:
        r = subprocess.run(["git", "-C", repo, "log", "-1", "--format=%h",
                            "--", relpath],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return None


def load_json(path):
    try:
        with io.open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def instrument_record(repo):
    """The collecting binary: hash, commit, build timestamp, and its limits."""
    pin = load_json(os.path.join(repo, "paper", "run-b-guard.json")) or {}
    build = load_json(os.path.join(repo, "paper",
                                   "run-b-guard-build.json")) or {}
    prov_path = os.path.join(repo, "paper",
                             "run-b-guard-history.jsonl")
    attested_from = pin.get("pinned_at")
    entries = 0
    try:
        with io.open(prov_path, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                entries += 1
                d = json.loads(line)
                ts = d.get("ts")
                if ts and (attested_from is None or ts < attested_from):
                    attested_from = ts
    except Exception:
        pass
    rec = {
        "sha256": pin.get("sha256"),
        "commit": pin.get("commit"),
        "path_in_source_tree": pin.get("hook"),
        "attested_from": attested_from,
        "attestation_source": ("paper/run-b-guard.json plus the "
                               "append-only log paper/"
                               "run-b-guard-history.jsonl (%d entr%s)"
                               % (entries, "y" if entries == 1 else "ies")),
        "rustc_version": build.get("rustc_version"),
    }
    if build.get("recovered"):
        rec["build_timestamp"] = build.get("build_timestamp")
        rec["build_timestamp_status"] = build.get("build_timestamp_status")
        rec["build_timestamp_method"] = build.get("build_timestamp_method")
        rec["build_timestamp_caveats"] = build.get("build_timestamp_caveats")
        rec["build_timestamp_lower_bound"] = \
            build.get("build_timestamp_lower_bound")
        rec["build_timestamp_upper_bound"] = \
            build.get("build_timestamp_upper_bound")
    else:
        rec["build_timestamp"] = None
        rec["build_timestamp_status"] = build.get(
            "build_timestamp_status", "unrecoverable")
        rec["build_timestamp_reason"] = build.get(
            "build_timestamp_reason",
            "paper/run-b-guard-build.json is absent, so no recovery was "
            "attempted for this build. The field is unknown, not zero.")
    rec["scope"] = (
        "This binary is attested for records at or after attested_from only. "
        "The corpus predating that instant was collected by a binary whose "
        "hash nobody recorded; those entries carry attributed=false with the "
        "reason rather than inheriting this hash.")
    return rec


def script_records(repo):
    out = {}
    for key, meta in HARNESS.items():
        rel = meta["script"]
        out[key] = {"path": rel, "commit": git_commit(repo, rel),
                    "evidence": meta["evidence"]}
    out["_instrument_writes_event_logs"] = INSTRUMENT_WRITES
    return out


# --------------------------------------------------------------------------
# build


def walk_files(root):
    for dirpath, dirnames, names in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(names):
            p = os.path.join(dirpath, name)
            if not os.path.isfile(p):
                continue
            yield p, os.path.relpath(p, root).replace("\\", "/")


def off_instrument_list(artifact, repo):
    """(keys, declared, source, sha256) for the off-instrument exclusion list."""
    for source, base in (("artifact", artifact), ("repository", repo)):
        path = os.path.join(base, OFF_INSTRUMENT_NAME)
        if not os.path.exists(path):
            continue
        keys, declared = set(), None
        with io.open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip().replace("\\", "/").strip("/")
                if line.startswith("#"):
                    m = _DECLARED_COUNT_RE.match(line)
                    if m:
                        declared = int(m.group(1))
                    continue
                if line:
                    keys.add(line)
        if declared is None:
            raise SystemExit(
                "  %s declares no `# count`: a truncated copy would be\n"
                "  indistinguishable from a complete one. Refusing to mark."
                % path)
        if declared != len(keys):
            raise SystemExit(
                "  %s declares `# count %d` and carries %d entries. Refusing\n"
                "  to mark a subset: the difference is sessions that would be\n"
                "  read as on-instrument." % (path, declared, len(keys)))
        digest, _n = sha256_and_size(path)
        return frozenset(keys), declared, source, digest
    return frozenset(), 0, "absent", None


def archive_of(rel):
    parts = rel.split("/")
    if len(parts) > 2 and parts[0] == "paper" and parts[1] == "data" \
            and parts[2].startswith("denials"):
        return parts[2]
    return None


def file_disposition(rel):
    """Retained but excluded from analysis? Returns (state, reason) or None."""
    if UNHOOKED.search(rel):
        return ("quarantined",
                "sits in an `.unhooked/` subtree: the session ran with no "
                "guard hook attached and is retained as evidence, not analysed")
    for d in QUARANTINE_DIRS:
        if "/" + d + "/" in rel:
            return ("quarantined",
                    "sits under `%s/`: set aside at collection time" % d)
    for d in SET_ASIDE_DIRS:
        if "/" + d + "/" in rel:
            return ("set aside",
                    "sits under `%s/`: recorded but never promoted into the "
                    "analysis population" % d)
    if PRE_PRUNE.search(rel):
        return ("set aside",
                "a `.pre-prune` copy retained beside the pruned file")
    return None


def disagreement_text(m1, m2, m3, kind):
    if m1 == m2 == m3:
        return None
    bits = []
    if m1 != m2:
        bits.append("%d line(s) do not parse (torn or truncated write)"
                    % (m1 - m2))
    if m2 != m3:
        if kind == "event-log":
            bits.append("%d parsed record(s) lack `ts` or `kind`" % (m2 - m3))
        else:
            bits.append("%d parsed record(s) are API errors or zero-token "
                        "stubs" % (m2 - m3))
    return "M1 %d / M2 %d / M3 %d: %s" % (m1, m2, m3, "; ".join(bits))


def build_manifest(artifact, repo, snapshot):
    files = []
    shapes = {}
    shape_ids = {}
    archives = {}
    off_keys, off_declared, off_source, off_digest = off_instrument_list(
        artifact, repo)
    off_marked = 0

    for path, rel in walk_files(artifact):
        if rel in (MANIFEST_NAME, SHA_MANIFEST_NAME):
            continue
        name = os.path.basename(rel)
        kind, harness = classify(rel, name)
        digest, nbytes = sha256_and_size(path)
        c = count_file(path, kind)

        keys = tuple(sorted(c["keys"]))
        if keys and keys not in shape_ids:
            shape_ids[keys] = "s%d" % (len(shape_ids) + 1)
            shapes[shape_ids[keys]] = list(keys)
        entry = {
            "path": rel,
            "bytes": nbytes,
            "sha256": digest,
        }
        if kind == "not-a-record-file":
            entry["records"] = {
                "applies": False,
                "extension": os.path.splitext(name)[1] or "(none)",
                "reason_code": "R-not-record"}
            entry["model"] = {
                "applies": False,
                "reason_code": "R-not-record",
                "reason": "not a record-bearing file, so no vendor returned "
                          "metadata about it"}
            entry["first_record_ts"] = None
            entry["last_record_ts"] = None
            entry["record_ts_reason_code"] = "R-not-record"
        else:
            r = {"applies": True, "kind": kind,
                 "m1_raw_lines": c["m1_raw_lines"],
                 "m2_parsed": c["m2_parsed"],
                 "m3_carrying": c["m3_carrying"],
                 "agree": c["m1_raw_lines"] == c["m2_parsed"] == c["m3_carrying"]}
            d = disagreement_text(c["m1_raw_lines"], c["m2_parsed"],
                                  c["m3_carrying"], kind)
            if d:
                r["disagreement"] = d
            if c["torn"]:
                r["unparseable_lines"] = c["torn"]
            entry["records"] = r
            entry["first_record_ts"] = c["first_ts"]
            entry["last_record_ts"] = c["last_ts"]
            entry["record_ts_reason_code"] = (
                "R-ts-from-records" if c["first_ts"] else "R-no-ts-field")
            model = {}
            if c["models"]:
                model["identifiers"] = sorted(c["models"])
            if keys:
                model["api_metadata_shape"] = shape_ids[keys]
            model["api_metadata_unedited"] = True
            entry["model"] = model

        arc = archive_of(rel)
        if arc:
            entry["archive"] = arc
            a = archives.setdefault(arc, {
                "m1": 0, "m2": 0, "m3": 0, "bytes": 0, "files": 0,
                "session_m1": 0, "session_m2": 0, "session_m3": 0,
                "first": None, "last": None, "models": set(),
                "quarantined_files": 0, "set_aside_files": 0,
                "off_instrument_files": 0,
                "torn": 0, "harnesses": set()})
            a["files"] += 1
            a["bytes"] += nbytes
            a["m1"] += c["m1_raw_lines"]
            a["m2"] += c["m2_parsed"]
            a["m3"] += c["m3_carrying"]
            a["torn"] += c["torn"]
            if kind in ("session-record-file", "session-json"):
                a["session_m1"] += c["m1_raw_lines"]
                a["session_m2"] += c["m2_parsed"]
                a["session_m3"] += c["m3_carrying"]
            if harness:
                a["harnesses"].add(harness)
            a["models"] |= c["models"]
            if c["first_ts"] and (a["first"] is None or c["first_ts"] < a["first"]):
                a["first"] = c["first_ts"]
            if c["last_ts"] and (a["last"] is None or c["last_ts"] > a["last"]):
                a["last"] = c["last_ts"]
            disp = file_disposition(rel)
            if disp:
                entry["record_disposition"] = disp[0]
                entry["record_disposition_reason"] = disp[1]
                if disp[0] == "quarantined":
                    a["quarantined_files"] += 1
                else:
                    a["set_aside_files"] += 1
            if rel[len("paper/data/"):] in off_keys:
                entry["off_instrument"] = True
                entry["off_instrument_reason_code"] = "R-off-instrument"
                a["off_instrument_files"] += 1
                off_marked += 1
        entry["_harness"] = harness
        files.append(entry)

    # Archive rollups and the five-state status.
    live_cut = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(snapshot - LIVE_WINDOW_HOURS * 3600))
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(snapshot))
    rollup = {}
    for arc, a in sorted(archives.items()):
        status, reason = archive_status(a, live_cut, now_iso)
        rollup[arc] = {
            "files": a["files"], "bytes": a["bytes"],
            "session_records": {"m1_raw_lines": a["session_m1"],
                                "m2_parsed": a["session_m2"],
                                "m3_carrying": a["session_m3"],
                                "agree": a["session_m1"] == a["session_m2"]
                                == a["session_m3"]},
            "all_records": {"m1_raw_lines": a["m1"], "m2_parsed": a["m2"],
                            "m3_carrying": a["m3"]},
            "unparseable_lines": a["torn"],
            "first_record_ts": a["first"], "last_record_ts": a["last"],
            "models": sorted(a["models"]),
            "harnesses": sorted(a["harnesses"]),
            "quarantined_files": a["quarantined_files"],
            "set_aside_files": a["set_aside_files"],
            "off_instrument_files": a["off_instrument_files"],
            "status": status, "status_reason": reason,
        }
        d = disagreement_text(a["session_m1"], a["session_m2"], a["session_m3"],
                              "session-record-file")
        if d:
            rollup[arc]["session_records"]["disagreement"] = d

    inst = instrument_record(repo)
    scripts = script_records(repo)

    # Second pass: attach per-file provenance that needed the rollups.
    for e in files:
        harness = e.pop("_harness", None)
        arc = e.get("archive")
        if arc:
            r = rollup[arc]
            e["archive_status"] = r["status"]
            if not e.get("model"):
                e["model"] = {}
            if "identifiers" not in e.get("model", {}) and r["models"]:
                e["model"]["archive_identifiers"] = r["models"]
                e["model"]["archive_identifiers_reason_code"] = \
                    "R-model-from-archive"
            h = harness or (r["harnesses"][0] if len(r["harnesses"]) == 1
                            else None)
            if h and h in scripts:
                e["collecting_script"] = {"path": scripts[h]["path"],
                                          "commit": scripts[h]["commit"]}
                if e["records"].get("kind") == "event-log":
                    e["collecting_script"]["reason_code"] = \
                        "R-event-log-writer"
                    e["collecting_script"]["written_by"] = \
                        inst.get("path_in_source_tree")
            elif e["records"].get("kind") == "event-log":
                e["collecting_script"] = {
                    "path": inst.get("path_in_source_tree"),
                    "commit": inst.get("commit"),
                    "reason_code": "R-event-log-writer"}
            else:
                e["collecting_script"] = {
                    "path": None,
                    "reason_code": "R-script-ambiguous",
                    "harnesses_present": r["harnesses"]}
            e["collecting_binary"] = binary_attribution(inst, e, r)
        else:
            e["archive_status"] = "not applicable"
            e["archive_status_reason_code"] = "R-not-an-archive"
            e["collecting_script"] = {"path": None,
                                      "reason_code": "R-script-none"}
            e["collecting_binary"] = {"attributed": False,
                                      "reason_code": "R-binary-not-instrument"}

    n_dis = sum(1 for e in files
                if e["records"].get("applies") and not e["records"]["agree"])
    header = {
        "schema": "data-release-section4-manifest/1",
        "generated_utc": now_iso,
        "generator": "paper/scripts/release/manifest.py",
        "specification": "paper/DATA-RELEASE.md section 4",
        "entries": len(files),
        "files_in_release_when_complete": len(files) + 2,
        "files_in_release_note": (
            "entries + the two integrity files named in `excluded`. "
            "`manifest.py --verify` counts the tree itself rather than "
            "trusting this line."),
        "excluded": [
            {"path": MANIFEST_NAME,
             "reason": "a manifest cannot contain its own digest. This file is "
                       "written before MANIFEST.sha256, so MANIFEST.sha256 "
                       "carries an entry for it and `sha256sum -c` pins it."},
            {"path": SHA_MANIFEST_NAME,
             "reason": "written after this file, and it is the file that pins "
                       "this one. Its own digest over its body is printed in "
                       "its header."},
        ],
        "section4_fields": {
            "relative path": "`path`",
            "byte size": "`bytes`",
            "SHA-256": "`sha256`",
            "record count, three ways, disagreements reported":
                "`records.m1_raw_lines` / `.m2_parsed` / `.m3_carrying`, with "
                "`records.disagreement` naming all three and the cause. %d of "
                "%d entries disagree." % (n_dis, len(files)),
            "collecting binary (commit, build timestamp, binary hash)":
                "`collecting_binary`, attested only from %s; see `instrument`"
                % inst.get("attested_from"),
            "collecting script and its commit": "`collecting_script`",
            "model identifier and API metadata as returned, unedited":
                "`model.identifiers` and `model.api_metadata_shape`, keyed "
                "into `record_shapes`; the vendor records themselves ship "
                "verbatim in the file the entry describes",
            "first and last record timestamp at full resolution":
                "`first_record_ts` / `last_record_ts`, read from the records' "
                "`ts` field, not from file mtimes",
            "complete / partial / failed / quarantined / set aside":
                "`archive_status` per archive, `record_disposition` for a file "
                "held in a quarantined or set-aside subtree",
        },
        "reason_codes": REASONS,
        "reason_codes_always_in_force": [
            "R-vendor-verbatim - true of every record file in this release",
            "R-status-see-rollup - true of every entry carrying `archive`",
            "R-disagreement - the policy behind every `records.disagreement`",
        ],
        "reason_codes_note": (
            "each entry names a code instead of repeating the sentence. The "
            "sentences are here in full; the join is one lookup. The first "
            "build repeated them per entry and the manifest came to 90 MB, "
            "four fifths of it the same six sentences."),
        "instrument_attested_from": inst.get("attested_from"),
        "counting_methods": {
            "M1": "non-empty lines. Counting lines is not counting records.",
            "M2": "lines that parse as a JSON object; M1>M2 is a torn write.",
            "M3": "gradient.sh's count() rule as transcribed in "
                  "inventory.py:carries_data - skip an API error, skip a "
                  "zero-token record. For guard event logs, records carrying "
                  "both `ts` and `kind`.",
            "policy": "disagreements are reported, never reconciled.",
        },
        "archive_status_definitions": {
            "_decided_on": "the SESSION count, not the total record count. An "
                           "archive whose sessions all died still holds "
                           "thousands of guard events, so a rule that counts "
                           "every record calls a weekly-limit stub complete - "
                           "which is what the first version of this manifest "
                           "did to denials-opus-max, 48 of 21,813.",
            "complete": "collection has stopped, nothing is quarantined or set "
                        "aside, every line parses, and every session entry "
                        "carries data",
            "partial": "any of: the campaign's declared stop (%s) has not been "
                       "reached and the archive received a record within %d h "
                       "of the snapshot; some session entries carry no data, "
                       "so the run did not land everything it attempted; there "
                       "are torn writes; or quarantined or set-aside records "
                       "sit alongside analysable ones. The reason string says "
                       "which, with the magnitude."
                       % (RUN_B_DECLARED_STOP, LIVE_WINDOW_HOURS),
            "failed": "session entries were written and none of them carries "
                      "data - a weekly-limit or rate-limit stub. Retained: a "
                      "run that failed is evidence about the instrument",
            "quarantined": "every analysable record sits under "
                           "`events.quarantined/` or an `.unhooked/` subtree",
            "set aside": "every record sits under `events.incomplete/`, "
                         "`events.staging/` or a `.pre-prune` copy - retained, "
                         "never promoted into the analysis population",
        },
        "off_instrument": {
            "declared": off_declared,
            "marked": off_marked,
            "list": OFF_INSTRUMENT_NAME,
            "list_read_from": off_source,
            "list_sha256": off_digest,
            "key": "`off_instrument: true` on the entry for every session log "
                   "the list names",
            "what_it_means":
                "the session was collected while the guard binary on disk was "
                "not the pinned instrument, so a different rule set decided "
                "it. Retained, never deleted - a run collected against a "
                "changed instrument is evidence about the instrument - and "
                "excluded from every pooled figure inside the corpus walk "
                "(`paper/scripts/analysis/archive.py`), not at the call "
                "sites.",
            "if_declared_and_marked_differ":
                "they cannot: the list is refused if its header disagrees "
                "with its entries, and a session log named in the list and "
                "absent from the release would leave `marked` short. Compare "
                "the two numbers; a gap is a defect in this release, not a "
                "rounding.",
        },
        "instrument": inst,
        "collecting_scripts": scripts,
        "record_shapes": shapes,
        "record_shapes_note": (
            "the union of top-level keys observed in a file's records, as the "
            "vendor and the harness wrote them. Keyed so 50k entries do not "
            "each carry a copy."),
        "archives": rollup,
        "corpus_note": (
            "A collection run was writing into the API archives while this "
            "manifest was built. Every count for an archive marked partial is "
            "a lower bound at the snapshot instant and the digests pin the "
            "bytes as released, which is the property that matters."),
    }
    return header, files


def archive_status(a, live_cut, now_iso):
    """The five states, in precedence order, with the reason."""
    total = a["m1"]
    carrying = a["m3"]
    sm1, sm3 = a["session_m1"], a["session_m3"]
    if sm1 > 0 and sm3 == 0:
        return ("failed",
                "%d session entr%s written and none carries data: every one is "
                "an API error or a zero-token stub. Retained as evidence about "
                "the instrument." % (sm1, "y" if sm1 == 1 else "ies"))
    if a["files"] and a["quarantined_files"] == a["files"]:
        return ("quarantined",
                "all %d released file(s) sit under `events.quarantined/` or an "
                "`.unhooked/` subtree" % a["files"])
    if a["files"] and a["set_aside_files"] == a["files"]:
        return ("set aside",
                "all %d released file(s) are incomplete, staged or "
                "`.pre-prune` copies, retained but never promoted into the "
                "analysis population" % a["files"])
    reasons = []
    if a["last"] and a["last"] >= live_cut and now_iso < RUN_B_DECLARED_STOP:
        reasons.append("still collecting: received a record at %s, inside the "
                       "%d h before the snapshot, and the campaign's declared "
                       "stop (%s) has not been reached"
                       % (a["last"], LIVE_WINDOW_HOURS, RUN_B_DECLARED_STOP))
    if sm1 and sm3 < sm1:
        reasons.append("%d of %d session entr%s carr%s data; the rest are API "
                       "errors or zero-token stubs, so the run did not land "
                       "everything it attempted"
                       % (sm3, sm1, "y" if sm1 == 1 else "ies",
                          "ies" if sm3 == 1 else "y"))
    if a["quarantined_files"]:
        reasons.append("%d quarantined file(s) alongside analysable ones"
                       % a["quarantined_files"])
    if a["set_aside_files"]:
        reasons.append("%d set-aside file(s) alongside analysable ones"
                       % a["set_aside_files"])
    if a["torn"]:
        reasons.append("%d unparseable line(s)" % a["torn"])
    if reasons:
        return "partial", "; ".join(reasons)
    return ("complete",
            "collection has stopped (no record inside the %d h before the "
            "snapshot), nothing is quarantined or set aside, every line "
            "parses, and all %d session entr%s carr%s data"
            % (LIVE_WINDOW_HOURS, sm1, "y" if sm1 == 1 else "ies",
               "ies" if sm1 == 1 else "y"))


def binary_attribution(inst, entry, rollup):
    """Attribute the pinned binary only where the records are inside its
    attestation window. Anything else is a null with the reason."""
    if entry.get("off_instrument"):
        return {"attributed": False,
                "reason_code": "R-binary-off-instrument",
                "not_this_binary": inst.get("sha256")}
    base = {"sha256": inst.get("sha256"), "commit": inst.get("commit"),
            "build_timestamp": inst.get("build_timestamp")}
    if inst.get("build_timestamp") is None:
        base["build_timestamp_status"] = inst.get("build_timestamp_status")
        base["build_timestamp_reason"] = inst.get("build_timestamp_reason")
    att = inst.get("attested_from")
    first = entry.get("first_record_ts") or rollup.get("first_record_ts")
    last = entry.get("last_record_ts") or rollup.get("last_record_ts")
    if not att:
        return {"attributed": False, "reason_code": "R-binary-predates"}
    if not last:
        return {"attributed": False, "reason_code": "R-binary-no-ts"}
    if first and first >= att:
        out = dict(base)
        out["attributed"] = True
        out["reason_code"] = "R-binary-inside"
        return out
    if last >= att:
        out = dict(base)
        out["attributed"] = "partial"
        out["reason_code"] = "R-binary-spans"
        return out
    return {"attributed": False, "reason_code": "R-binary-predates"}


def write_manifest(artifact, repo):
    snapshot = time.time()
    header, files = build_manifest(artifact, repo, snapshot)
    path = os.path.join(artifact, MANIFEST_NAME)
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(header, sort_keys=True) + "\n")
        for e in files:
            fh.write(json.dumps(e, sort_keys=True) + "\n")
    nbytes = os.path.getsize(path)
    n_dis = sum(1 for e in files
                if e["records"].get("applies") and not e["records"]["agree"])
    print("  section 4 manifest: %d entries, %.1f MB, %d with a counting "
          "disagreement" % (len(files), nbytes / 1048576.0, n_dis))
    inst = header["instrument"]
    print("    instrument %s commit %s build %s"
          % ((inst.get("sha256") or "-")[:16], inst.get("commit"),
             inst.get("build_timestamp") or inst.get("build_timestamp_status")))
    off = header["off_instrument"]
    print("    off-instrument: %d of %d declared session logs marked "
          "(list read from the %s)"
          % (off["marked"], off["declared"], off["list_read_from"]))
    if off["marked"] != off["declared"]:
        print("    THE TWO DISAGREE: %d session log(s) the list names are not "
              "in this release, so their exclusion cannot be checked here."
              % (off["declared"] - off["marked"]))
    return len(files)


# --------------------------------------------------------------------------
# verify - runs inside the release, needs no repository


def verify(artifact, recount=True):
    path = os.path.join(artifact, MANIFEST_NAME)
    if not os.path.exists(path):
        print("  %s is missing: this release carries no section 4 manifest"
              % MANIFEST_NAME)
        return 1
    bad = []
    seen = set()
    header = None
    n = 0
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            if header is None:
                header = rec
                continue
            n += 1
            rel = rec["path"]
            seen.add(rel)
            p = os.path.join(artifact, rel)
            if not os.path.exists(p):
                bad.append((rel, "listed in the manifest and absent from the "
                                 "tree"))
                continue
            digest, nbytes = sha256_and_size(p)
            if nbytes != rec["bytes"]:
                bad.append((rel, "size %d, manifest says %d"
                            % (nbytes, rec["bytes"])))
            if digest != rec["sha256"]:
                bad.append((rel, "sha256 mismatch"))
            if recount and rec["records"].get("applies"):
                kind = rec["records"]["kind"]
                c = count_file(p, kind)
                for key, got in (("m1_raw_lines", c["m1_raw_lines"]),
                                 ("m2_parsed", c["m2_parsed"]),
                                 ("m3_carrying", c["m3_carrying"])):
                    if rec["records"][key] != got:
                        bad.append((rel, "%s recomputes to %d, manifest says %d"
                                    % (key, got, rec["records"][key])))
    on_disk = []
    for _p, rel in walk_files(artifact):
        if rel in (MANIFEST_NAME, SHA_MANIFEST_NAME):
            continue
        on_disk.append(rel)
    missing = sorted(set(on_disk) - seen)

    print("  section 4 manifest: %d entries" % n)
    print("  files in the release: %d (%d covered, %d excluded by name: %s)"
          % (len(on_disk) + 2, len(on_disk), 2,
             ", ".join([MANIFEST_NAME, SHA_MANIFEST_NAME])))
    if missing:
        print("  %d FILE(S) IN THE TREE WITH NO MANIFEST ENTRY:" % len(missing))
        for rel in missing[:20]:
            print("      %s" % rel)
        return 1
    if bad:
        print("  %d MISMATCH(ES):" % len(bad))
        for rel, why in bad[:20]:
            print("      %-60s %s" % (rel[:60], why))
        return 1
    print("  one entry per released file, and every size, digest and "
          "three-way count recomputes.")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--artifact", default=None,
                    help="the built release (default: the tree this script "
                         "was run from)")
    ap.add_argument("--repo", default=REPO,
                    help="the source repository, for git provenance")
    ap.add_argument("--verify", action="store_true",
                    help="re-check an existing manifest against the tree; "
                         "needs no repository")
    ap.add_argument("--no-recount", action="store_true",
                    help="with --verify, check sizes and digests only")
    args = ap.parse_args()

    artifact = args.artifact or REPO
    if args.verify:
        return verify(artifact, recount=not args.no_recount)
    write_manifest(artifact, args.repo)
    return 0


if __name__ == "__main__":
    sys.exit(main())
