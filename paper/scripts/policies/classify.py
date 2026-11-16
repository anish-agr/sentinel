#!/usr/bin/env python
"""Classifies the rules developers write for their agents, by enforceability."""

import argparse
import collections
import io
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.abspath(os.environ.get("POLICY_DIR") or os.path.join(
    HERE, "..", "..", "..", ".campaign", "policies"))

# --------------------------------------------------------------- extraction --

BULLET = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+(.*)$")
CODE_FENCE = re.compile(r"^\s*```")
HEADING = re.compile(r"^\s*#{1,6}\s+")
LINK_ONLY = re.compile(r"^\s*\[?[^]]*\]?\([^)]*\)\s*$")


def statements(text):
    """Candidate rules: bullet items and numbered items, fences excluded."""
    out = []
    in_fence = False
    for line in text.split("\n"):
        if CODE_FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence or HEADING.match(line):
            continue
        m = BULLET.match(line)
        if not m:
            continue
        body = m.group(1).strip()
        body = re.sub(r"`([^`]*)`", r"\1", body)          # keep code text, drop ticks
        body = re.sub(r"\[([^]]*)\]\([^)]*\)", r"\1", body)  # link text, not target
        body = re.sub(r"\*\*|__|\*", "", body).strip()
        if len(body) < 12 or LINK_ONLY.match(body):
            continue
        out.append(body)
    return out


# --------------------------------------------------------------- normativity --

DEONTIC = re.compile(
    r"\b(must|never|always|do not|don't|dont|should|shall|avoid|ensure|"
    r"required|require|prohibited|forbidden|no longer|not allowed|"
    r"make sure|be sure|only use|only run|prefer|use |run |add |remove |"
    r"keep |write |follow|check |verify|update )", re.I)

DESCRIPTIVE_LEAD = re.compile(
    r"^(this|the|it|there|these|those|our|a |an )\b.*\b(is|are|was|were|"
    r"contains|provides|uses|includes|has|have|holds|lives|located)\b", re.I)


def is_normative(s):
    if DESCRIPTIVE_LEAD.match(s):
        return False
    return bool(DEONTIC.search(s))


# ------------------------------------------------------------ classification --

# The same twelve enforceable-violation signatures the violation classifier
# uses. A rule matching one of these names an action a fixed predicate over the
# command could refuse.
SIGNATURES = {
    "file_destruction": r"\brm -rf|\brm -fr|\brm\b.*-r|delete .*(director|file)|"
                        r"\bshred\b|\brmdir\b|remove .*recursiv",
    "privilege_escalation": r"\bsudo\b|\bdoas\b|\bsu -\b|as root\b|root access",
    "git_destructive": r"force.?push|push --force|-f to (main|master)|"
                       r"reset --hard|git clean|filter-branch|rebase .*(main|master)|"
                       r"amend|force.?with.?lease|delete .*branch|history rewrit",
    "database_destructive": r"drop table|drop database|truncate\b|delete from|"
                            r"\bmigrat.*(down|rollback)|wipe .*(database|db)\b",
    "system_path_write": r"/etc/|/usr/(local/)?s?bin|/System/|C:\\\\Windows|"
                         r"system director|global config",
    "persistence": r"crontab|systemd|systemctl|launchd|\.bashrc|\.zshrc|\.profile|"
                   r"authorized_keys|autostart|startup script",
    "network_exfiltration": r"\bscp\b|\brsync\b.*:|upload|send .*(remote|external)|"
                            r"\bcurl\b.*(-d|--data|POST)|exfiltrat",
    "secret_access": r"\.env\b|secret|credential|api.?key|token\b|password|"
                     r"\bprintenv\b|private key|\.pem\b|id_rsa",
    "pipe_to_interpreter": r"curl.*\|.*(sh|bash)|wget.*\|.*(sh|bash)|pipe .*shell",
    "cloud_destruction": r"terraform destroy|kubectl delete|helm (uninstall|delete)|"
                         r"aws .*(rb|delete)|tear down .*(stack|environment)",
    "unbounded_compute": r"while true|infinite loop|\bfork bomb\b|busy.?wait|"
                         r"unbounded (loop|process)",
    "global_package_install": r"npm i(nstall)? -g|pip install --user|global(ly)? install|"
                              r"-g\b.*install",
}
SIGNATURES = {k: re.compile(v, re.I) for k, v in SIGNATURES.items()}

# Rules about what the agent may *claim*, not what it may do. Nothing
# irreversible happens when one of these is broken, so no pre-action gate can
# reach them however the ruleset is written.
CLAIM = re.compile(
    r"\b(do not|don't|never|always)\b.{0,60}\b(claim|say|report|state|assert|"
    r"pretend|declare|mark .*(done|complete)|tell (me|the user))|"
    r"\b(honest|accurate|truthful|verify before|confirm before)\b|"
    r"without (running|verifying|testing|checking)", re.I)

# Rules whose subject is a command shape but whose correctness depends on facts
# the monitor cannot see. Style, architecture, taste, and process.
SEMANTIC = re.compile(
    r"\b(readable|clean|idiomatic|simple|concise|consistent|maintainable|"
    r"convention|style|format|lint|naming|comment|document|refactor|"
    r"test coverage|unnecessar|appropriate|reasonable|best practice|"
    r"pattern|architecture|design|structure|small|short|clear)\b", re.I)


def classify(s):
    """-> (class, signature or None). Order matters and is deliberate."""
    if CLAIM.search(s):
        return "C3", None
    for name, pattern in SIGNATURES.items():
        if pattern.search(s):
            return "C1", name
    if SEMANTIC.search(s):
        return "C2", None
    return "U", None


# ----------------------------------------------------------------- reporting --

def load_manifest():
    path = os.path.join(CORPUS, "content.jsonl")
    rows = []
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main(args):
    manifest = load_manifest()
    raw = os.path.join(CORPUS, "raw")
    per_class = collections.Counter()
    per_sig = collections.Counter()
    total_statements = normative = 0
    files = 0
    dump = io.open(args.dump, "w", encoding="utf-8") if args.dump else None

    for row in manifest:
        path = os.path.join(raw, row["file"])
        if not os.path.isfile(path):
            continue
        files += 1
        try:
            text = io.open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for s in statements(text):
            total_statements += 1
            if not is_normative(s):
                continue
            normative += 1
            cls, sig = classify(s)
            per_class[cls] += 1
            if sig:
                per_sig[sig] += 1
            if dump:
                dump.write(json.dumps({
                    "repo": row["repo"], "filename": row["filename"],
                    "statement": s, "machine_class": cls, "signature": sig,
                }) + "\n")
    if dump:
        dump.close()

    print("")
    print("Agent instruction corpus")
    print("  files              %d" % files)
    print("  repositories       %d" % len(set(r["repo"] for r in manifest)))
    print("  bullet statements  %d" % total_statements)
    print("  normative rules    %d  (%.1f%% of statements)"
          % (normative, 100.0 * normative / max(1, total_statements)))
    print("")
    print("What developers write rules about, by enforceability")
    order = ["C1", "C2", "C3", "U"]
    for c in order:
        n = per_class[c]
        label = {"C1": "deterministic (a predicate exists)",
                 "C2": "semantic (needs intent/context)",
                 "C3": "a claim, not an action",
                 "U": "unmatched by any pattern"}[c]
        print("  %-4s %-36s %6d  %5.1f%%"
              % (c, label, n, 100.0 * n / max(1, normative)))
    print("")
    print("C1 rules by signature")
    for name, n in per_sig.most_common():
        print("  %-26s %5d  %5.1f%% of C1" % (name, n, 100.0 * n / max(1, per_class["C1"])))
    print("")
    print("Compare against violations actually committed (StepShield, n=747):")
    print("  C1 18.6%%   C2 52.6%%   C3 13.5%%   C0 15.3%%")
    print("")
    print("This classifier is a deterministic keyword heuristic. Like the")
    print("violation classifier it needs a hand-labelled agreement statistic")
    print("before any of the above is reportable.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--dump", help="write every classified statement to JSONL")
    main(p.parse_args())
