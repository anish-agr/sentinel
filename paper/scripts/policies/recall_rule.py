#!/usr/bin/env python
"""The signature the matcher was missing, fitted once and scored once."""

import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)

import classify as base                                        # noqa: E402

# A refusal. A pre-execution gate can decline an action; it cannot compel one,
# so the polarity is not incidental.
PROHIBITION = re.compile(
    r"\b(never|do not|don't|dont|do  not|must not|may not|cannot|can't|"
    r"prohibited|forbidden|disallowed|not allowed|avoid|no longer)\b"
    r"|^\s*no\s+\w", re.I)

# A requirement whose subject is the FORM of a command rather than an action to
# be taken: "always pass --x", "use nx run", "commit messages must be in
# English". A gate can refuse the command that lacks the form.
FORM_REQUIREMENT = re.compile(
    r"\b(always|must|only|prefer)\b[^.]{0,80}?"
    r"\b(use|run|pass|prefix|branch|commit|write|execute|target)\b", re.I)

# Something the guard can see in the command line itself.
CONCRETE = re.compile(
    r"--[a-z][\w-]{1,}"                                   # a flag
    r"|\.\w{1,5}\b(?![\w.])"                              # an extension
    r"|\b[\w-]+/[\w./-]+"                                 # a path
    r"|`[^`]+`"                                           # a literal
    r"|\b(git|npm|pnpm|yarn|cargo|pip|uv|poetry|conda|python3?|node|nx|tsc|"
    r"docker|kubectl|cdk|terraform|make|sail|cron|crontab|venv|rm|chmod|"
    r"curl|wget|ssh|scp)\b", re.I)


def enforceable(statement):
    """True when a guard could refuse this from one command."""
    if base.classify(statement)[0] == "C1":
        return True
    if not CONCRETE.search(statement):
        return False
    return bool(PROHIBITION.search(statement)
                or FORM_REQUIREMENT.search(statement))


def score(labels, keyfile, name):
    key = json.load(io.open(os.path.join(
        REPO, "paper", "data", "labelkit", "_keys", keyfile), encoding="utf-8"))
    rows = [json.loads(l) for l in io.open(
        os.path.join(REPO, "paper", "data", labels), encoding="utf-8")
        if l.strip()]
    tp = fp = fn = tn = 0
    missed = []
    for r in rows:
        rec = key[str(r["item"])]
        s = rec["statement"] if isinstance(rec, dict) else rec
        got, want = enforceable(s), r["consensus"] == "A"
        tp += got and want
        fp += got and not want
        fn += (not got) and want
        tn += (not got) and (not want)
        if want and not got:
            missed.append(s)
    n = tp + fp + fn + tn
    prec = tp / float(tp + fp) if tp + fp else float("nan")
    rec_ = tp / float(tp + fn) if tp + fn else float("nan")
    print("")
    print("  %s  (n=%d)" % (name, n))
    print("    recall     %2d/%-2d   %.0f%%" % (tp, tp + fn, 100 * rec_))
    print("    precision  %2d/%-2d   %.0f%%" % (tp, tp + fp, 100 * prec))
    print("    accuracy          %.1f%%" % (100.0 * (tp + tn) / n))
    return missed


def main():
    print("")
    print("  NOT SHIPPED. See the module docstring: 61% recall at 15%")
    print("  precision is not a usable classifier, and adopting it would")
    print("  inflate the policy rate about fourfold - in the direction that")
    print("  weakens our own claim. The panel's rate stands as the estimate")
    print("  and the matcher keeps its perfect precision.")
    print("")
    print("  ENFORCEABLE-STATEMENT RULE")
    print("  fitted on the development panel, scored on the held-out panel")
    score("policy-statements.labels-holdout.jsonl", "key-holdout-policy.json",
          "held out, 4 fresh raters")
    return 0


if __name__ == "__main__":
    sys.exit(main())
