#!/usr/bin/env python
"""Where each of the 21 rules comes from, other than us."""

import argparse
import collections
import io
import json
import os
import re
import sys

CORPUS = os.path.join("paper", "data", "policy-statements.jsonl")
FALCO = os.path.join("paper", "data", "external", "falco_rules.yaml")

# (rule, what it refuses, regex over developer statements, Falco analogue).
# The patterns are written from the rule's own description, before looking at
# what they would match, so the counts are not tuned.
RULES = [
    ("git.force_push", "force-push to a protected branch",
     r"force[- ]?push|push\s+--force|push\s+-f\b", None),
    ("git.delete_branch", "delete a protected remote branch",
     r"delete.{0,20}(remote\s+)?branch|push\s+--delete", None),
    ("git.reset_hard", "git reset --hard with uncommitted work",
     r"reset\s+--hard|git\s+reset\b", None),
    ("git.clean_force", "git clean -fd with untracked work",
     r"git\s+clean\b|clean\s+-[a-z]*f", None),
    ("git.history_rewrite", "history rewrite on a protected branch",
     r"rewrite.{0,20}history|filter-branch|rebase.{0,20}(main|master)|amend",
     None),
    ("fs.remove_protected", "recursive delete of a protected path",
     r"rm\s+-[a-z]*r|recursive.{0,15}delete|delete.{0,20}director", None),
    ("fs.disk_destroy", "whole-device or filesystem destruction",
     r"\bmkfs\b|\bdd\s+if=|format.{0,15}(disk|drive|device)",
     "Remove Bulk Data from Disk"),
    ("fs.credential_write", "write into a credential-shaped path",
     r"\.env\b|credential|secret|\.aws/|id_rsa|private key",
     "Find AWS Credentials"),
    ("sql.destructive", "DROP or TRUNCATE against a non-test database",
     r"\bdrop\s+(table|database)|\btruncate\b|delete\s+from", None),
    ("perm.chmod_world_writable", "chmod 777",
     r"chmod\s+777|world[- ]writable|chmod\s+-R", None),
    ("net.pipe_to_shell", "piping a download straight into a shell",
     r"curl.{0,30}\|\s*(ba)?sh|wget.{0,30}\|\s*(ba)?sh|pipe.{0,15}shell",
     None),
    ("cloud.destroy", "destroys remote infrastructure",
     r"terraform\s+destroy|aws\s+.{0,20}delete|kubectl\s+delete|drop.{0,15}bucket",
     None),
    ("publish.irreversible", "publishes a release that cannot be withdrawn",
     r"npm\s+publish|cargo\s+publish|pypi|release.{0,20}(tag|publish)", None),
    ("fs.destructive_command", "an irreversible command",
     r"irreversible|destructive|cannot be undone|permanently", None),
    ("git.discard_changes", "discards every uncommitted change",
     r"discard.{0,20}change|checkout\s+--\s|stash\s+drop|restore\s+\.", None),
    ("git.branch_delete", "force-deletes a protected local branch",
     r"branch\s+-D|delete.{0,15}local\s+branch", None),
    ("secret.exposure", "prints or copies a credential out of the environment",
     r"echo\s+\$|print.{0,20}(secret|token|key)|log.{0,15}credential|env\b.{0,20}secret",
     "Search Private Keys or Passwords"),
    ("fs.system_write", "writes into a path the operating system owns",
     r"/etc/|/usr/|system.{0,15}(file|director)|C:\\\\Windows", None),
    ("proc.unbounded", "starts work with no bound on how long it runs",
     r"background|daemon|long[- ]running|timeout|infinite\s+loop", None),
    ("net.exfiltrate", "sends local data to a remote host",
     r"upload|send.{0,20}(data|file).{0,20}(remote|external)|exfiltrat|post.{0,15}http",
     None),
    ("persist.autostart", "installs something that survives the session",
     r"crontab|systemd|launchagent|startup|autostart|registry.{0,15}run",
     None),
]


def load_statements():
    rows = []
    if not os.path.exists(CORPUS):
        return rows
    for line in io.open(CORPUS, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        s = r.get("statement")
        if s:
            rows.append((s, r.get("repo") or ""))
    return rows


def restricted_replication(orphans):
    """The headline, recomputed with every unattested rule deleted."""
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    import own_action_space as oas
    from stats import wilson, cluster_diff_paired

    archive = os.path.join("paper", "data", "denials")
    if not os.path.isdir(archive):
        print("\n  no campaign archive; restricted replication skipped\n")
        return
    calls, n_sessions = oas.calls_in(archive)
    drop = set(orphans)

    def grouped(restrict):
        """Aggregate counts, plus the per-session rows the clustered
        interval needs: (shell refused, shell calls, tool refused, tool calls).
        """
        out = {}
        per = collections.defaultdict(lambda: [0, 0, 0, 0])
        for space, slot in (("shell", 0), ("tool", 2)):
            sub = [c for c in calls
                   if c["space"] == space and not c["read_only"]]
            refused = 0
            for c in sub:
                hit = bool(c["refused"]) and not (restrict
                                                  and c["rule"] in drop)
                refused += 1 if hit else 0
                per[c["session"]][slot] += 1 if hit else 0
                per[c["session"]][slot + 1] += 1
            out[space] = (len(sub), refused)
        return out, [tuple(v) for v in per.values()]

    print("")
    print("  RESTRICTED-RULESET REPLICATION")
    print("  mutating calls only, %d sessions" % n_sessions)
    print("")
    print("  %-38s %7s %8s %8s   %s"
          % ("ruleset / action space", "calls", "refused", "share",
             "95% CI (per space: Wilson)"))
    for label, restrict in (("all %d rules" % len(RULES), False),
                            ("%d attested only" % (len(RULES) - len(drop)),
                             True)):
        g, clusters = grouped(restrict)
        for space in ("shell", "tool"):
            n, r = g[space]
            lo, hi = wilson(r, n)
            print("  %-38s %7d %8d %7.1f%%   [%.1f, %.1f]"
                  % ("%s / %s" % (label, space), n, r,
                     100.0 * r / n if n else 0, 100 * lo, 100 * hi))
        _p1, _p2, d, lo, hi, K = cluster_diff_paired(clusters)
        if K < 2:
            raise RuntimeError("cannot cluster the restricted difference: "
                               "%d session(s)" % K)
        print("  %-38s %7s %8s %+7.1f    [%+.1f, %+.1f]"
              % ("  -> difference (paired, clustered)", "", "",
                 100 * d, 100 * lo, 100 * hi))
        print("")
    print("  If the gap survives with every unattested rule deleted, rule")
    print("  authorship is bounded by construction rather than by argument.")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--restricted", action="store_true",
                    help="recompute the headline action-space result using "
                         "ONLY the rules independently attested above")
    ap.add_argument("--samples", action="store_true",
                    help="print one matching developer statement per rule")
    args = ap.parse_args()

    statements = load_statements()
    if not statements:
        print("")
        print("  no %s: every rule would report zero developer" % CORPUS)
        print("  attestations because there are no statements to match, not")
        print("  because none match. Refusing rather than printing it.")
        return 1
    falco_text = ""
    if os.path.exists(FALCO):
        falco_text = io.open(FALCO, encoding="utf-8", errors="replace").read()

    print("")
    print("  RULE PROVENANCE - who else wrote this down")
    print("  %d developer policy statements searched" % len(statements))
    print("")
    print("  %-28s %7s %7s  %s"
          % ("rule", "devs", "repos", "Falco analogue"))
    orphans = []
    rows = []
    for name, _desc, pattern, falco in RULES:
        rx = re.compile(pattern, re.I)
        hits = [(s, repo) for s, repo in statements if rx.search(s)]
        repos = len({repo for _s, repo in hits if repo})
        ok_falco = bool(falco) and (falco in falco_text)
        rows.append((name, len(hits), repos, falco if ok_falco else "",
                     hits[:1]))
        if not hits:
            orphans.append(name)
        print("  %-28s %7d %7d  %s"
              % (name, len(hits), repos, falco if ok_falco else "-"))

    covered = sum(1 for _n, h, _r, _f, _s in rows if h)
    with_falco = sum(1 for _n, _h, _r, f, _s in rows if f)
    print("")
    print("  %d of %d rules are independently attested in developer policy"
          % (covered, len(RULES)))
    print("  files; %d also have a Falco analogue." % with_falco)
    if orphans:
        print("")
        print("  ATTESTED NOWHERE - these are ours alone and the paper should")
        print("  say so rather than let a reviewer discover it:")
        for name in orphans:
            print("    %s" % name)

    if args.samples:
        print("")
        print("  ONE REAL DEVELOPER STATEMENT PER RULE")
        for name, hits, _repos, _f, sample in rows:
            if sample:
                s = sample[0][0].replace("\n", " ")[:96]
                print("    %-26s %s" % (name, s))

    if args.restricted:
        restricted_replication(orphans)

    print("")
    print("  Read this as recurrence, not equivalence: the match is lexical")
    print("  and generous, so it shows the CONCEPT appears in the wild rather")
    print("  than that any statement encodes our predicate. That is the claim")
    print("  being made - these 21 concepts were not invented here.")
    print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
