#!/usr/bin/env python
"""Why the action-space gap exists: harm shape, not rule bias."""

import argparse
import collections
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import own_action_space as oas  # noqa: E402

COMMAND, PATH = "command", "path"

SHAPE = {
    # -- command-shaped: the harm is the program, not the object -------------
    "git.clean_force":       (COMMAND, "git", "git clean -fd; no object makes this safe or unsafe"),
    "git.history_rewrite":   (COMMAND, "git", "rebase/amend/filter-branch on a protected branch"),
    "git.reset_hard":        (COMMAND, "git", "git reset --hard against a dirty worktree"),
    "git.discard_changes":   (COMMAND, "git", "git checkout . / git restore ."),
    "git.branch_delete":     (COMMAND, "git", "git branch -D of a protected branch"),
    "git.force_push":        (COMMAND, "git", "git push --force onto a protected branch"),
    "git.delete_branch":     (COMMAND, "git", "git push --delete of a protected remote branch"),
    "net.exfiltrate":        (COMMAND, "net/proc/db/cloud", "scp, rsync host:, nc -e, curl --data"),
    "net.pipe_to_shell":     (COMMAND, "net/proc/db/cloud", "curl | sh"),
    "proc.unbounded":        (COMMAND, "net/proc/db/cloud", "fork bomb, miner, while true"),
    "sql.destructive":       (COMMAND, "net/proc/db/cloud", "DROP TABLE against a non-test DSN"),
    "cloud.destroy":         (COMMAND, "net/proc/db/cloud", "terraform destroy, kubectl delete"),
    "publish.irreversible":  (COMMAND, "net/proc/db/cloud", "npm/cargo publish, twine upload"),

    # -- path-shaped: an effect applied to a resolved target ------------------
    "fs.credential_write":   (PATH, "path", "write whose target is credential-shaped"),
    "fs.remove_protected":   (PATH, "path", "delete whose target is protected or outside the repo"),
    "fs.system_write":       (PATH, "path", "write whose target is OS-owned"),

    # -- mixed, conceded to path-shaped so the bound stays conservative -------
    "persist.autostart":     (PATH, "path", "MIXED: crontab/schtasks is command-shaped; conceded"),
    "secret.exposure":       (PATH, "path", "MIXED: bare printenv is command-shaped; conceded"),
    "fs.destructive_command": (PATH, "path", "MIXED: a command table; conceded"),
    "perm.chmod_world_writable": (PATH, "path", "MIXED: chmod 777 is command-shaped; conceded"),
    "fs.disk_destroy":       (PATH, "path", "MIXED: mkfs/dd of=/dev/*; conceded"),
}

CONCEDED = tuple(r for r, (_s, _g, why) in SHAPE.items() if why.startswith("MIXED"))


def measure(archive=None):
    """Return the harm-shape decomposition of every denial, by action space."""
    archive = archive or os.path.join("paper", "data", "denials")
    calls, n_sessions = oas.calls_in(archive)
    mutating = [c for c in calls if not c["read_only"]]
    denials = [c for c in mutating if c["refused"]]

    unknown = sorted({c["rule"] for c in denials if c["rule"] not in SHAPE})
    out = {"sessions": n_sessions, "mutating": len(mutating),
           "denials": len(denials), "unknown_rules": unknown, "space": {}}

    for space in ("shell", "tool"):
        sub = [c for c in denials if c["space"] == space]
        groups = collections.Counter()
        rules = collections.Counter()
        for c in sub:
            shape, group, _ = SHAPE.get(c["rule"], (PATH, "path", "unknown"))
            groups[group] += 1
            rules[c["rule"]] += 1
        n = len(sub)
        cmd = groups["git"] + groups["net/proc/db/cloud"]
        conceded = sum(rules[r] for r in CONCEDED)
        out["space"][space] = {
            "n": n,
            "git": groups["git"],
            "other_command": groups["net/proc/db/cloud"],
            "command": cmd,
            "path": groups["path"],
            "conceded_to_path": conceded,
            "pct_git": 100.0 * groups["git"] / n if n else 0.0,
            "pct_other_command": 100.0 * groups["net/proc/db/cloud"] / n if n else 0.0,
            "pct_command": 100.0 * cmd / n if n else 0.0,
            "pct_path": 100.0 * groups["path"] / n if n else 0.0,
            "rules": rules,
        }
    return out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--archive", default=os.path.join("paper", "data", "denials"))
    ap.add_argument("--rules", action="store_true",
                    help="print the per-rule assignment behind each column")
    args = ap.parse_args()

    if not os.path.isdir(args.archive):
        print("  archive missing: %s" % args.archive)
        return 1

    m = measure(args.archive)
    if m["unknown_rules"]:
        print("  UNASSIGNED RULES (counted as path-shaped, which understates the")
        print("  command-shaped share): %s" % ", ".join(m["unknown_rules"]))
        print("")

    print("")
    print("  HARM SHAPE OF EVERY DENIAL - why the action-space gap exists")
    print("  %d sessions, %d mutating calls, %d denials"
          % (m["sessions"], m["mutating"], m["denials"]))
    print("")
    print("  A command-shaped harm is defined by which program runs and has no")
    print("  expression as (effect, target). A path-shaped harm is an effect on")
    print("  a resolved target and is expressible in any space that has one.")
    print("")
    print("  %-8s %7s %10s %10s %14s %12s"
          % ("space", "denials", "git", "other cmd", "command-shaped", "path-shaped"))
    for space in ("shell", "tool"):
        r = m["space"][space]
        print("  %-8s %7d %6d %3.0f%% %6d %3.0f%% %8d %4.1f%% %6d %5.1f%%"
              % (space, r["n"],
                 r["git"], r["pct_git"],
                 r["other_command"], r["pct_other_command"],
                 r["command"], r["pct_command"],
                 r["path"], r["pct_path"]))
    print("")

    sh, to = m["space"]["shell"], m["space"]["tool"]
    print("  At least %.1f%% of shell denials are command-shaped, against"
          % sh["pct_command"])
    print("  %.1f%% of structured denials. %d shell denials from mixed rules are"
          % (to["pct_command"], sh["conceded_to_path"]))
    print("  conceded to the path column, so the shell figure is a lower bound.")
    print("")
    print("  A typed file tool cannot express a command-shaped harm at all: no")
    print("  Write or Edit rewrites history, pipes a download into a shell,")
    print("  publishes a package or destroys cloud infrastructure. The")
    print("  enforceable fraction differs because the expressible fraction")
    print("  differs, which is a property of the action space and not of the")
    print("  rules written for it.")

    if args.rules:
        print("")
        print("  PER-RULE ASSIGNMENT")
        for space in ("shell", "tool"):
            r = m["space"][space]
            if not r["n"]:
                continue
            print("")
            print("    %s (%d denials)" % (space, r["n"]))
            for rule, k in r["rules"].most_common():
                shape, _group, why = SHAPE.get(rule, (PATH, "path", "unassigned"))
                print("      %-28s %4d  %-7s %s" % (rule, k, shape, why))
    print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
