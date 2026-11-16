#!/usr/bin/env python
"""C16 - is the action-space effect real, or an artifact of three datasets?"""

import argparse
import collections
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import wilson, newcombe  # noqa: E402

DATA = os.path.join("paper", "data")

SHELL_EXEC = {
    "bash", "sh", "zsh", "shell", "exec", "execute", "run", "run_command",
    "execute_command", "run_terminal_cmd", "terminal", "command", "system",
    "subprocess", "apply_patch", "patch",
}
FS_VERBS = {
    "read", "write", "edit", "create_file", "delete", "remove", "rm", "mv",
    "cp", "copy", "move", "ls", "list_files", "cat", "mkdir", "glob", "grep",
    "find", "open_file", "append", "truncate",
}
CLI_SHAPE = re.compile(r"^[A-Za-z][\w.-]*(\s+[\w.:/-]+)+$")
ARG_COMMAND_KEY = re.compile(r'"(command|cmd|script|shell_command|bash)"\s*:', re.I)


def space_of(action, arguments):
    """'shell' or 'api', with the reason, so every call can be audited."""
    name = (action or "").strip()
    low = name.lower()
    if not name or name == "?":
        return "none", "no action recorded (a final message)"
    head = low.split()[0] if low.split() else low
    if head in SHELL_EXEC:
        return "shell", "shell executor"
    if low in FS_VERBS or head in FS_VERBS:
        return "shell", "filesystem verb"
    if ARG_COMMAND_KEY.search(arguments or ""):
        return "shell", "carries a command string in its arguments"
    if CLI_SHAPE.match(name):
        return "shell", "CLI invocation with a subcommand"
    return "api", "single-identifier tool call over a payload"


def load(path):
    rows = []
    with io.open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def block(title, rows):
    """C1 share within one slice of the data."""
    by = collections.defaultdict(lambda: [0, 0])
    for r in rows:
        sp = r["_space"]
        by[sp][0] += 1
        if r.get("machine_class") == "C1":
            by[sp][1] += 1
    print(title)
    print("  %-8s %7s %7s %8s   %s" % ("space", "steps", "C1", "share", "95% CI"))
    for sp in ("shell", "api", "none"):
        n, c = by[sp]
        if not n:
            continue
        lo, hi = wilson(c, n)
        print("  %-8s %7d %7d %7.1f%%   [%.1f, %.1f]"
              % (sp, n, c, 100.0 * c / n, 100 * lo, 100 * hi))
    ns, cs = by["shell"]
    na, ca = by["api"]
    if ns and na:
        d = 100.0 * (cs / float(ns) - ca / float(na))
        lo, hi = newcombe(cs, ns, ca, na)
        verdict = "excludes 0" if lo > 0 or hi < 0 else "INCLUDES 0 - not significant"
        print("  shell - api  %+.1f points   95%% CI [%+.1f, %+.1f]  %s"
              % (d, 100 * lo, 100 * hi, verdict))
    print("")
    return by


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--show", choices=("shell", "api", "none"),
                    help="print the distinct actions classified into this space")
    args = ap.parse_args()

    rows = load(os.path.join(DATA, "atbench-violations.jsonl"))
    for r in rows:
        sp, why = space_of(r.get("action"), r.get("arguments"))
        r["_space"] = sp
        r["_why"] = why

    print("")
    print("C16 - action space within ATBench, holding the corpus fixed")
    print("%d steps of unsafe trajectories" % len(rows))
    print("")

    block("Pooled across the three ATBench variants", rows)

    for corpus in ("ATBench", "ATBench-Claw", "ATBench-Codex"):
        sub = [r for r in rows if r.get("category") == corpus]
        if sub:
            block("%s alone (%d steps)" % (corpus, len(sub)), sub)

    print("Note: 'none' is a step with no action recorded - a final assistant")
    print("message. It is reported, never folded into either space, because a")
    print("message is not a small action but a different kind of thing.")

    if args.show:
        seen = collections.Counter()
        why = {}
        for r in rows:
            if r["_space"] == args.show:
                seen[r.get("action") or "?"] += 1
                why[r.get("action") or "?"] = r["_why"]
        print("")
        print("distinct actions classified as %s: %d" % (args.show, len(seen)))
        for a, n in seen.most_common(60):
            print("  %-44s %4d   %s" % (a[:44], n, why[a]))


if __name__ == "__main__":
    main()
