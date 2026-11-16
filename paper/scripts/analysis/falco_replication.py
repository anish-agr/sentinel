#!/usr/bin/env python
"""The action-space measurement, replicated under somebody else's ruleset."""

import argparse
import io
import os
import re
import shlex
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stats import wilson  # noqa: E402
import own_action_space  # noqa: E402

RULES_YAML = os.path.join("paper", "data", "external", "falco_rules.yaml")

# Fields our virtual event can populate from a recorded command, and nothing
# else. A rule whose expanded condition references any field outside this set
# is excluded as requiring state a text log does not carry.
SUPPORTED_FIELDS = {"evt.type", "evt.dir", "proc.name", "proc.args",
                    "proc.cmdline", "proc.exepath"}


def load_ruleset(path):
    docs = yaml.safe_load(io.open(path, encoding="utf-8"))
    rules, macros, lists = [], {}, {}
    for d in docs:
        if not isinstance(d, dict):
            continue
        if "rule" in d:
            rules.append(d)
        elif "macro" in d:
            macros[d["macro"]] = d["condition"]
        elif "list" in d:
            lists[d["list"]] = d["items"]
    return rules, macros, lists


def expand(cond, macros, lists, depth=0):
    """Inline every macro and list reference into one condition string."""
    macros = dict(macros)
    macros["never_true"] = "evt.type = __never__"
    macros["always_true"] = "evt.type != __never__"
    if depth > 20:
        raise ValueError("macro recursion")
    # Lists first: bare names inside parentheses.
    def sub_lists(text):
        for name, items in lists.items():
            flat = []
            for it in items:
                if isinstance(it, str) and it in lists:
                    flat.extend(lists[it])
                else:
                    flat.append(it)
            joined = ", ".join(str(x) for x in flat)
            text = re.sub(r"\b%s\b" % re.escape(name), joined, text)
        return text
    changed = True
    while changed:
        changed = False
        for name, body in macros.items():
            # (?<![.\w]) ... (?![.\w(]): a macro reference stands alone.
            # `container` must not match inside `container.id` (a field),
            # nor may an expansion re-trigger on text it introduced.
            pat = r"(?<![.\w])%s(?![.\w])" % re.escape(name)
            if re.search(pat, cond):
                cond = re.sub(pat, "( " + body + " )", cond)
                changed = True
        depth += 1
        if depth > 60:
            raise ValueError("macro recursion")
    return sub_lists(cond)



TOKEN = re.compile(r"""
      (?P<lpar>\() | (?P<rpar>\))
    | (?P<comma>,)
    | (?P<str>"[^"]*"|'[^']*')
    | (?P<op>!=|>=|<=|=|<|>)
    | (?P<word>[^\s(),=<>!]+|!)
""", re.X)


def tokenize(cond):
    out = []
    for m in TOKEN.finditer(cond):
        kind = m.lastgroup
        val = m.group(0)
        if kind == "str":
            val = val[1:-1]
            kind = "word"
        elif kind == "op":
            kind = "word"
        out.append((kind, val))
    return out


class Unsupported(Exception):
    pass


class Parser:
    """Recursive descent over: expr := term (or term)*; term := factor
    (and factor)*; factor := 'not' factor | '(' expr ')' | comparison."""

    OPS = {"=", "!=", "in", "contains", "icontains", "startswith",
           "endswith", "glob", ">=", "<=", ">", "<"}

    def __init__(self, tokens):
        self.toks = tokens
        self.i = 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def next(self):
        t = self.peek()
        self.i += 1
        return t

    def parse(self):
        node = self.expr()
        if self.peek()[0] is not None:
            raise Unsupported("trailing tokens")
        return node

    def expr(self):
        left = self.term()
        while self.peek() == ("word", "or"):
            self.next()
            left = ("or", left, self.term())
        return left

    def term(self):
        left = self.factor()
        while self.peek() == ("word", "and"):
            self.next()
            left = ("and", left, self.factor())
        return left

    def factor(self):
        kind, val = self.peek()
        if (kind, val) == ("word", "not"):
            self.next()
            return ("not", self.factor())
        if kind == "lpar":
            self.next()
            node = self.expr()
            if self.next()[0] != "rpar":
                raise Unsupported("unbalanced paren")
            return node
        return self.comparison()

    def comparison(self):
        kind, field = self.next()
        if kind != "word":
            raise Unsupported("expected field")
        # Unary postfix: `proc.env exists`.
        if self.peek() == ("word", "exists"):
            self.next()
            return ("exists", field, None)
        kind, op = self.next()
        if kind != "word" or op not in self.OPS:
            raise Unsupported("op %r" % op)
        if op == "in":
            if self.next()[0] != "lpar":
                raise Unsupported("in without list")
            items = []
            while True:
                k, v = self.next()
                if k == "rpar":
                    break
                if k == "comma":
                    continue
                items.append(v)
            return ("in", field, items)
        k, v = self.next()
        if k != "word":
            raise Unsupported("expected value")
        return (op, field, v)


def fields_of(node, acc):
    op = node[0]
    if op in ("and", "or"):
        fields_of(node[1], acc)
        fields_of(node[2], acc)
    elif op == "not":
        fields_of(node[1], acc)
    else:
        acc.add(node[1])
    return acc


def evaluate(node, event):
    op = node[0]
    if op == "and":
        return evaluate(node[1], event) and evaluate(node[2], event)
    if op == "or":
        return evaluate(node[1], event) or evaluate(node[2], event)
    if op == "not":
        return not evaluate(node[1], event)
    field = node[1]
    val = event.get(field, "")
    if op == "=":
        return val == node[2]
    if op == "!=":
        return val != node[2]
    if op == "in":
        return val in node[2]
    if op == "contains":
        return node[2] in val
    if op == "icontains":
        return node[2].lower() in val.lower()
    if op == "startswith":
        return val.startswith(node[2])
    if op == "endswith":
        return val.endswith(node[2])
    if op == "glob":
        import fnmatch
        return fnmatch.fnmatch(val, node[2])
    if op == "exists":
        return bool(val)
    if op in (">=", "<=", ">", "<"):
        try:
            a, b = float(val or 0), float(node[2])
        except ValueError:
            return False
        return {"<": a < b, ">": a > b,
                "<=": a <= b, ">=": a >= b}[op]
    raise Unsupported(op)


def virtual_event(command):
    """POSIX-tokenize a recorded command into a Falco-shaped execve event."""
    events = []
    for seg in re.split(r"(?:&&|\|\||[;|]|\n)", command):
        seg = seg.strip()
        if not seg:
            continue
        try:
            argv = shlex.split(seg, posix=True)
        except ValueError:
            argv = seg.split()
        if not argv:
            continue
        name = os.path.basename(argv[0]).replace(".exe", "")
        events.append({
            "evt.type": "execve",
            "evt.dir": "<",
            "proc.name": name,
            "proc.exepath": argv[0],
            "proc.args": " ".join(argv[1:]),
            "proc.cmdline": seg,
        })
    return events


def compile_rules():
    rules, macros, lists = load_ruleset(RULES_YAML)
    stable = [r for r in rules if "maturity_stable" in (r.get("tags") or [])]
    compiled, excluded = [], []
    for r in stable:
        try:
            cond = expand(r["condition"], macros, lists)
            node = Parser(tokenize(cond)).parse()
            used = fields_of(node, set())
            bad = used - SUPPORTED_FIELDS
            if bad:
                excluded.append((r["rule"], "fields: %s"
                                 % ", ".join(sorted(bad)[:4])))
                continue
            compiled.append((r["rule"], node))
        except Unsupported as exc:
            excluded.append((r["rule"], "grammar: %s" % exc))
        except Exception as exc:  # noqa: BLE001 - report, never crash
            excluded.append((r["rule"], "expand: %s" % exc))
    return compiled, excluded, len(stable)


POSITIVE_CONTROLS = [
    ("Search Private Keys or Passwords",
     'grep -r "BEGIN RSA PRIVATE KEY" /home'),
    ("Search Private Keys or Passwords",
     'find /home -name id_rsa'),
    ("Find AWS Credentials",
     'find /home -name .aws/credentials'),
    ("Remove Bulk Data from Disk",
     'shred -uz /var/log/audit.log'),
    ("Remove Bulk Data from Disk",
     'mkfs /dev/sdb1'),
]

# Commands that must NOT fire. A rule that matches everything would also
# produce a confident-looking positive control, so the check is two-sided.
NEGATIVE_CONTROLS = [
    "git status",
    "ls -la src",
    "npm test",
    "grep -r TODO src",
]


def positive_control():
    """Does the evaluator fire where Falco's own rules say it should?"""
    rules, _excluded, _n_stable = compile_rules()

    print("")
    print("  FALCO POSITIVE CONTROL")
    print("  %d rule(s) evaluable as single-command predicates" % len(rules))
    print("")
    fired_all = True
    for want, command in POSITIVE_CONTROLS:
        events = virtual_event(command)
        hits = sorted({name for name, node in rules
                       for ev in events if evaluate(node, ev)})
        ok = want in hits
        fired_all = fired_all and ok
        print("  %-4s %-44s %s"
              % ("ok" if ok else "MISS", command[:44],
                 ", ".join(hits) if hits else "(nothing fired)"))

    print("")
    clean = True
    for command in NEGATIVE_CONTROLS:
        events = virtual_event(command)
        hits = sorted({name for name, node in rules
                       for ev in events if evaluate(node, ev)})
        clean = clean and not hits
        print("  %-4s %-44s %s"
              % ("ok" if not hits else "FIRED", command[:44],
                 ", ".join(hits) if hits else "(silent, as expected)"))

    print("")
    if fired_all and clean:
        print("  The evaluator fires on commands Falco's own conditions")
        print("  describe, and stays silent on ordinary work. A zero on our")
        print("  corpus is therefore a measurement rather than a broken")
        print("  harness, and may be reported as one.")
        return 0
    if not fired_all:
        print("  AT LEAST ONE POSITIVE CONTROL DID NOT FIRE. The evaluator")
        print("  cannot be shown to work, so 'Falco fires 0 times on our")
        print("  corpus' is uninterpretable and MUST NOT be reported.")
    if not clean:
        print("  A NEGATIVE CONTROL FIRED. The predicate is over-broad and any")
        print("  count it produces is inflated.")
    return 1


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--archive", default=os.path.join("paper", "data",
                                                      "denials"))
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--positive-control", action="store_true",
                    help="prove the evaluator fires where Falco's own rules "
                         "say it should; without this the zero on our corpus "
                         "is uninterpretable")
    args = ap.parse_args()

    compiled, excluded, n_stable = compile_rules()
    print("")
    print("Falco default ruleset (Apache-2.0, falcosecurity/rules) against")
    print("the recorded corpus")
    print("  stable rules: %d; evaluable as single-command lexical"
          " predicates: %d;" % (n_stable, len(compiled)))
    print("  excluded (kernel/container state or unsupported grammar): %d"
          % len(excluded))
    if args.positive_control:
        return positive_control()

    if args.list_rules:
        print("")
        for name, _node in compiled:
            print("  EVAL     %s" % name)
        for name, why in excluded:
            print("  EXCLUDE  %-44s %s" % (name, why))
        return 0

    records, _n = own_action_space.calls_in(args.archive)
    if records and "args_summary" not in records[0]:
        raise SystemExit("calls_in() must carry args_summary - update it")
    shell = [c for c in records if c["space"] == "shell"
             and not c["read_only"]]
    tools = [c for c in records if c["space"] != "shell"
             and not c["read_only"]]

    hits = 0
    per_rule = {}
    for c in shell:
        fired = False
        for name, node in compiled:
            for ev in virtual_event(c["args_summary"] or ""):
                if evaluate(node, ev):
                    per_rule[name] = per_rule.get(name, 0) + 1
                    fired = True
                    break
            if fired:
                break
        hits += 1 if fired else 0

    ours = sum(1 for c in shell if c["refused"])
    both = 0
    for c in shell:
        if not c["refused"]:
            continue
        for name, node in compiled:
            if any(evaluate(node, ev)
                   for ev in virtual_event(c["args_summary"] or "")):
                both += 1
                break

    lo, hi = wilson(hits, len(shell))
    print("")
    print("  mutating shell calls: %d" % len(shell))
    print("  Falco-stable-lexical fires on   %d = %.1f%% [%.1f, %.1f]"
          % (hits, 100.0 * hits / len(shell), 100 * lo, 100 * hi))
    print("  our 21-rule guard fires on      %d = %.1f%%"
          % (ours, 100.0 * ours / len(shell)))
    print("  fired by BOTH rulesets          %d" % both)
    print("")
    print("  per Falco rule:")
    for name, k in sorted(per_rule.items(), key=lambda kv: -kv[1]):
        print("    %-52s %d" % (name, k))
    print("")
    print("  mutating structured-tool calls: %d" % len(tools))
    print("  Falco rules expressible over them: 0 of %d - the ruleset's"
          % len(compiled))
    print("  entire lexical vocabulary is the exec event. An independent,")
    print("  mature, widely deployed policy set can state predicates about")
    print("  the shell action space and cannot state any about the")
    print("  structured-tool space; that asymmetry is the paper's headline")
    print("  claim, reproduced with our authorship removed from it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
