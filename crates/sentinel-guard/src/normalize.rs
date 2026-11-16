use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Posix,
    PowerShell,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Sep {
    Semi,
    AndAnd,
    OrOr,
    Pipe,
}

#[derive(Debug, Clone)]
struct Word {
    text: String,
    substitution: bool,
    variable: bool,
}

const TRANSPARENT: &[&str] = &[
    "sudo",
    "doas",
    "env",
    "command",
    "builtin",
    "nohup",
    "time",
    "exec",
    "xargs",
    "nice",
    "stdbuf",
    "setsid",
    "eval",
    // Run-under-a-constraint wrappers. Each one execs its argument tail
    // unchanged; the constraint is on scheduling, tracing or a timer, never on
    // what the program does.
    "timeout",
    "gtimeout",
    "flock",
    "ionice",
    "watch",
    "parallel",
    "strace",
    "ltrace",
    "systemd-run",
    "proxychains",
    "proxychains4",
    "torsocks",
    "taskset",
    "chrt",
    "setarch",
    "unbuffer",
    "caffeinate",
    "chroot",
];

fn wrapper_operands(wrapper: &str, flags: &[String]) -> usize {
    let saw = |names: &[&str]| {
        flags.iter().any(|f| {
            names
                .iter()
                .any(|n| f == n || f.starts_with(&format!("{n}=")))
        })
    };
    match wrapper {
        // `timeout [opts] DURATION CMD`
        "timeout" | "gtimeout" => 1,
        // `flock [opts] FILE|FD CMD` — the `-c "…"` spelling never reaches
        // here, because `command_string_wrapper` diverts it first.
        "flock" => 1,
        // `chroot NEWROOT CMD`
        "chroot" => 1,
        // `setarch ARCH [opts] CMD`, but `setarch --list` and the
        // `setarch -R CMD` shorthand have no arch operand.
        "setarch" => usize::from(!saw(&["-R", "--addr-no-randomize", "--list"])),
        // `taskset MASK CMD`, unless `-c/--cpu-list` supplied it as a value.
        "taskset" => usize::from(!saw(&["-c", "--cpu-list"])),
        // `chrt [policy] PRIORITY CMD`, unless `-p` targeted a running pid.
        "chrt" => usize::from(!saw(&["-p", "--pid"])),
        _ => 0,
    }
}

const COMMAND_STRING_WRAPPERS: &[&str] = &["script", "su", "runuser", "flock"];

fn command_string_wrapper(base: &str, rest: &[Word]) -> bool {
    COMMAND_STRING_WRAPPERS.contains(&base)
        && rest.iter().any(|w| w.text == "-c" || w.text == "--command")
}

fn global_flag_takes_value(program: &str, flag: &str) -> bool {
    let (shorts, longs): (&[&str], &[&str]) = match program {
        "git" => (
            &["C", "c"],
            &[
                "exec-path",
                "git-dir",
                "work-tree",
                "namespace",
                "super-prefix",
                "config-env",
                "attr-source",
            ],
        ),
        "kubectl" => (
            &["n", "s"],
            &[
                "namespace",
                "context",
                "kubeconfig",
                "cluster",
                "user",
                "server",
                "as",
                "as-group",
                "token",
                "cache-dir",
                "request-timeout",
            ],
        ),
        "helm" => (
            &["n"],
            &[
                "namespace",
                "kube-context",
                "kubeconfig",
                "kube-apiserver",
                "kube-token",
                "registry-config",
                "repository-config",
                "repository-cache",
            ],
        ),
        "docker" | "podman" => (
            &["c", "H", "l"],
            &[
                "config",
                "context",
                "host",
                "log-level",
                "tlscacert",
                "tlscert",
                "tlskey",
            ],
        ),
        "aws" => (
            &[],
            &[
                "profile",
                "region",
                "endpoint-url",
                "output",
                "ca-bundle",
                "cli-read-timeout",
                "cli-connect-timeout",
            ],
        ),
        "gcloud" => (
            &[],
            &[
                "project",
                "account",
                "configuration",
                "billing-project",
                "impersonate-service-account",
            ],
        ),
        "npm" | "pnpm" | "yarn" => (
            &["w", "C"],
            &[
                "prefix",
                "workspace",
                "userconfig",
                "globalconfig",
                "cache",
                "registry",
            ],
        ),
        "cargo" => (&["Z"], &["config", "color", "manifest-path"]),
        "systemctl" => (
            &["H", "M", "t", "p"],
            &["host", "machine", "type", "property", "state", "signal"],
        ),
        _ => (&[], &[]),
    };
    match flag.strip_prefix("--") {
        Some(long) => longs.contains(&long),
        // Only an unclustered short flag takes a separate value; `-rf` is two
        // booleans, never a flag plus an argument.
        None => flag.strip_prefix('-').is_some_and(|s| shorts.contains(&s)),
    }
}

#[derive(Debug, Clone)]
pub struct Cmd {
    pub raw: String,
    pub program: String,
    pub argv: Vec<String>,
    pub short_flags: BTreeSet<char>,
    pub long_flags: BTreeSet<String>,
    pub operands: Vec<String>,
    subcommand_at: usize,
    /// A `$(...)` or backtick expansion appeared, so at least one argument is
    /// not knowable before execution.
    pub has_substitution: bool,
    pub has_variable: bool,
    pub shell: Shell,
}

impl Cmd {
    pub fn has_flag(&self, short: char, long: &str) -> bool {
        self.short_flags.contains(&short) || self.long_flags.contains(long)
    }

    /// The operands from the subcommand onward: `git -C . push origin main`
    /// gives `["push", "origin", "main"]`.
    pub fn command_words(&self) -> &[String] {
        self.operands.get(self.subcommand_at..).unwrap_or(&[])
    }

    pub fn subcommand(&self) -> Option<&str> {
        self.command_words().first().map(|s| s.as_str())
    }

    /// Operands with any leading subcommand dropped, e.g. the paths of
    /// `git clean -fdx path/`.
    pub fn targets(&self) -> &[String] {
        self.command_words().get(1..).unwrap_or(&[])
    }
}

#[derive(Debug, Clone)]
pub struct Pipeline {
    pub cmds: Vec<Cmd>,
    pub piped: bool,
}

#[allow(unused_assignments)]
fn lex(input: &str, shell: Shell) -> Vec<Result<Word, Sep>> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut subst = false;
    let mut var = false;
    let mut started = false;
    let mut i = 0;

    macro_rules! flush {
        () => {
            if started {
                out.push(Ok(Word {
                    text: std::mem::take(&mut cur),
                    substitution: subst,
                    variable: var,
                }));
                subst = false;
                var = false;
                started = false;
            }
        };
    }

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' => {
                started = true;
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    cur.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                started = true;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if shell == Shell::Posix && chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                    }
                    if chars[i] == '$' {
                        var = true;
                    }
                    cur.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '\\' if shell == Shell::Posix => {
                // A leading backslash is the classic alias-bypass (`\rm`); it
                // escapes the character but does not change the program.
                started = true;
                i += 1;
                if i < chars.len() {
                    cur.push(chars[i]);
                    i += 1;
                }
            }
            '`' if shell == Shell::PowerShell => {
                started = true;
                i += 1;
                if i < chars.len() {
                    cur.push(chars[i]);
                    i += 1;
                }
            }
            '`' => {
                started = true;
                subst = true;
                i += 1;
                while i < chars.len() && chars[i] != '`' {
                    cur.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '$' if i + 1 < chars.len() && chars[i + 1] == '(' => {
                started = true;
                subst = true;
                let mut depth = 0;
                i += 1;
                while i < chars.len() {
                    if chars[i] == '(' {
                        depth += 1;
                    } else if chars[i] == ')' {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    } else {
                        cur.push(chars[i]);
                    }
                    i += 1;
                }
            }
            '$' | '%' => {
                started = true;
                var = true;
                cur.push(c);
                i += 1;
            }
            ';' | '\n' | '\r' => {
                flush!();
                out.push(Err(Sep::Semi));
                i += 1;
            }
            '&' => {
                flush!();
                if i + 1 < chars.len() && chars[i + 1] == '&' {
                    out.push(Err(Sep::AndAnd));
                    i += 2;
                } else {
                    out.push(Err(Sep::Semi));
                    i += 1;
                }
            }
            '|' => {
                flush!();
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    out.push(Err(Sep::OrOr));
                    i += 2;
                } else {
                    out.push(Err(Sep::Pipe));
                    i += 1;
                }
            }
            '>' | '<' => {
                if !cur.chars().all(|c| c.is_ascii_digit()) {
                    flush!();
                }
                started = true;
                cur.push(c);
                i += 1;
                while i < chars.len() && chars[i] == c {
                    cur.push(chars[i]);
                    i += 1;
                }
                if c == '>' && i < chars.len() && chars[i] == '|' {
                    cur.push('|');
                    i += 1;
                }
                flush!();
            }
            c if c.is_whitespace() => {
                flush!();
                i += 1;
            }
            c => {
                started = true;
                cur.push(c);
                i += 1;
            }
        }
    }
    flush!();
    out
}

fn is_redirect_op(word: &str) -> bool {
    let digits = word.chars().take_while(char::is_ascii_digit).count();
    let rest = &word[digits..];
    let rest = rest.strip_suffix('|').unwrap_or(rest);
    !rest.is_empty() && rest.chars().all(|c| c == '>' || c == '<')
}

fn basename(s: &str) -> String {
    let s = s.rsplit(['/', '\\']).next().unwrap_or(s);
    let s = s
        .strip_suffix(".exe")
        .or_else(|| s.strip_suffix(".EXE"))
        .unwrap_or(s);
    s.to_ascii_lowercase()
}

fn wrapper_flag_takes_value(wrapper: &str, flag: &str) -> bool {
    let (shorts, longs): (&str, &[&str]) = match wrapper {
        "sudo" | "doas" => (
            "ugpCDRTh",
            &["user", "group", "prompt", "chdir", "close-from"],
        ),
        "xargs" => (
            "nPIsaEdL",
            &["max-args", "max-procs", "replace", "delimiter", "arg-file"],
        ),
        "env" => ("uCS", &["unset", "chdir", "split-string"]),
        "nice" => ("n", &["adjustment"]),
        "time" => ("of", &["output", "format"]),
        "stdbuf" => ("ioe", &["input", "output", "error"]),
        // `timeout -s KILL 60 CMD` — the signal is a separate word, so without
        // this the duration is skipped as the signal and `60` becomes the
        // program.
        "timeout" | "gtimeout" => ("sk", &["signal", "kill-after"]),
        "flock" => ("wE", &["wait", "timeout", "conflict-exit-code"]),
        "ionice" => ("cnp", &["class", "classdata", "pid"]),
        "watch" => ("n", &["interval"]),
        "parallel" => ("jSP", &["jobs", "sshlogin"]),
        "strace" | "ltrace" => ("oepsEP", &["output", "expression"]),
        "systemd-run" => (
            "puMHE",
            &[
                "property",
                "unit",
                "machine",
                "host",
                "setenv",
                "description",
                "slice",
                "uid",
                "gid",
                "nice",
                "service-type",
                "working-directory",
                "on-active",
                "on-calendar",
            ],
        ),
        "proxychains" | "proxychains4" => ("f", &[]),
        "torsocks" => ("up", &["user", "pass", "address", "port"]),
        "taskset" => ("cp", &["cpu-list", "pid"]),
        "chrt" => ("p", &["pid"]),
        "caffeinate" => ("tw", &[]),
        "chroot" => ("", &["userspec", "groups"]),
        _ => ("", &[]),
    };
    if let Some(long) = flag.strip_prefix("--") {
        return longs.contains(&long);
    }
    flag.chars().next_back().is_some_and(|c| shorts.contains(c))
}

fn build_cmd(words: Vec<Word>, shell: Shell) -> Option<Cmd> {
    let raw = words
        .iter()
        .map(|w| w.text.clone())
        .collect::<Vec<_>>()
        .join(" ");
    let has_substitution = words.iter().any(|w| w.substitution);
    let has_variable = words.iter().any(|w| w.variable);

    let mut idx = 0;
    loop {
        let w = words.get(idx)?;
        let text = w.text.as_str();
        // `FOO=bar cmd` — leading assignments are environment, not the program.
        if !text.starts_with('-') && text.contains('=') && !text.starts_with('=') {
            idx += 1;
            continue;
        }
        let base = basename(text);
        // `script -c "rm -rf ~" /dev/null` hides the command in a quoted
        // string, so the wrapper is kept as the program and `expand_nested`
        // re-parses the string, exactly as for `sh -c`.
        if command_string_wrapper(&base, &words[idx + 1..]) {
            break;
        }
        if TRANSPARENT.contains(&base.as_str()) {
            idx += 1;
            // `sudo -u root rm` / `xargs -n1 rm` — skip the wrapper's own flags,
            // and the separate argument when the flag takes one.
            let mut flags = Vec::new();
            let skip_flags = |idx: &mut usize, flags: &mut Vec<String>| {
                while let Some(flag) = words
                    .get(*idx)
                    .map(|w| w.text.clone())
                    .filter(|t| t.starts_with('-'))
                {
                    *idx += 1;
                    if !flag.contains('=') && wrapper_flag_takes_value(&base, &flag) {
                        *idx += 1;
                    }
                    flags.push(flag);
                }
            };
            skip_flags(&mut idx, &mut flags);
            // `timeout 60 rm` / `flock /tmp/lock rm` — the wrapper's own
            // positional arguments, which are not flags and so survive the loop
            // above and would otherwise be read as the program.
            idx += wrapper_operands(&base, &flags);
            // …and any flags written after them (`ionice /x -t rm`).
            skip_flags(&mut idx, &mut flags);
            continue;
        }
        break;
    }

    let argv: Vec<String> = words[idx..].iter().map(|w| w.text.clone()).collect();
    let program = basename(argv.first()?);

    let mut short_flags = BTreeSet::new();
    let mut long_flags = BTreeSet::new();
    let mut operands = Vec::new();
    let mut end_of_flags = false;
    // Set when the flag just seen consumes the next word as its value, so that
    // word is not mistaken for the subcommand.
    let mut pending_value = false;
    let mut subcommand_at = 0usize;

    for arg in &argv[1..] {
        if is_redirect_op(arg) {
            continue;
        }
        if end_of_flags {
            operands.push(arg.clone());
            continue;
        }
        if arg == "--" {
            end_of_flags = true;
            pending_value = false;
        } else if let Some(rest) = arg.strip_prefix("--") {
            let name = rest.split('=').next().unwrap_or(rest);
            long_flags.insert(name.to_ascii_lowercase());
            pending_value = !rest.contains('=') && global_flag_takes_value(&program, arg);
        } else if arg.starts_with('-') && arg.len() > 1 {
            let rest = &arg[1..];
            match shell {
                // PowerShell has no short-flag clusters: `-Recurse` is one flag.
                Shell::PowerShell => {
                    let name = rest.split(':').next().unwrap_or(rest);
                    long_flags.insert(name.to_ascii_lowercase());
                }
                Shell::Posix => {
                    let name = rest.split('=').next().unwrap_or(rest);
                    short_flags.extend(name.chars().filter(|c| c.is_ascii_alphanumeric()));
                    long_flags.insert(name.to_ascii_lowercase());
                }
            }
            pending_value = !rest.contains('=') && global_flag_takes_value(&program, arg);
        } else if arg.starts_with('/') && shell == Shell::PowerShell && arg.len() <= 3 {
            // cmd.exe style switches: `del /s /q`
            long_flags.insert(arg[1..].to_ascii_lowercase());
        } else {
            // Only LEADING option values shift the subcommand: once a real
            // operand has been seen, the subcommand is fixed and a later
            // value-taking option belongs to it, not to the program.
            if pending_value && subcommand_at == operands.len() {
                subcommand_at += 1;
            }
            pending_value = false;
            operands.push(arg.clone());
        }
    }

    Some(Cmd {
        raw,
        program,
        argv,
        short_flags,
        long_flags,
        operands,
        subcommand_at,
        has_substitution,
        has_variable,
        shell,
    })
}

const NESTED_SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "cmd",
    "powershell",
    "pwsh",
    // Not shells, but they take their command as a `-c` string and hand it to
    // one, so the string has to be re-parsed the same way. See
    // COMMAND_STRING_WRAPPERS, which keeps them out of TRANSPARENT for this.
    "script",
    "su",
    "runuser",
    "flock",
];

/// `sh -c "rm -rf ~"` hides the real command inside a quoted argument. Parse it
/// too and hand the inner commands to the rules alongside the outer one.
fn expand_nested(pipelines: &mut [Pipeline], depth: usize) {
    for pipeline in pipelines.iter_mut() {
        let mut inner = Vec::new();
        let mut inner_piped = false;
        for cmd in &pipeline.cmds {
            if !NESTED_SHELLS.contains(&cmd.program.as_str()) {
                continue;
            }
            let takes_command = cmd.short_flags.contains(&'c')
                || ["c", "command", "k"]
                    .iter()
                    .any(|f| cmd.long_flags.contains(*f));
            if !takes_command {
                continue;
            }
            let shell = match cmd.program.as_str() {
                "powershell" | "pwsh" | "cmd" => Shell::PowerShell,
                _ => Shell::Posix,
            };
            for operand in &cmd.operands {
                for nested in parse_depth(operand, shell, depth - 1) {
                    // A pipe inside `sh -c "..."` is still a pipe. Carrying the
                    // flag outward keeps the inner commands judged the same way
                    // they would be if they had been written directly.
                    inner_piped |= nested.piped;
                    inner.extend(nested.cmds);
                }
            }
        }
        pipeline.cmds.extend(inner);
        pipeline.piped |= inner_piped;
    }
}

pub fn parse(input: &str, shell: Shell) -> Vec<Pipeline> {
    parse_depth(input, shell, 2)
}

fn parse_depth(input: &str, shell: Shell, depth: usize) -> Vec<Pipeline> {
    let mut pipelines = parse_flat(input, shell);
    if depth > 0 {
        expand_nested(&mut pipelines, depth);
    }
    pipelines
}

fn parse_flat(input: &str, shell: Shell) -> Vec<Pipeline> {
    let mut pipelines = Vec::new();
    let mut cmds = Vec::new();
    let mut words = Vec::new();
    let mut piped = false;

    for item in lex(input, shell) {
        match item {
            Ok(w) => words.push(w),
            Err(sep) => {
                if let Some(cmd) = build_cmd(std::mem::take(&mut words), shell) {
                    cmds.push(cmd);
                }
                if sep == Sep::Pipe {
                    piped = true;
                } else if !cmds.is_empty() {
                    pipelines.push(Pipeline {
                        cmds: std::mem::take(&mut cmds),
                        piped: std::mem::take(&mut piped),
                    });
                }
            }
        }
    }
    if let Some(cmd) = build_cmd(words, shell) {
        cmds.push(cmd);
    }
    if !cmds.is_empty() {
        pipelines.push(Pipeline { cmds, piped });
    }
    pipelines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(input: &str) -> Cmd {
        parse(input, Shell::Posix).remove(0).cmds.remove(0)
    }

    #[test]
    fn short_flag_clusters_are_equivalent_however_written() {
        for variant in [
            "rm -rf x",
            "rm -fr x",
            "rm -r -f x",
            "rm -f -r x",
            "rm --recursive --force x",
        ] {
            let c = one(variant);
            assert_eq!(c.program, "rm", "{variant}");
            assert!(c.has_flag('r', "recursive"), "{variant}");
            assert!(c.has_flag('f', "force"), "{variant}");
            assert_eq!(c.operands, vec!["x"], "{variant}");
        }
    }

    #[test]
    fn quoting_and_escaping_do_not_hide_the_program() {
        for variant in [
            r#""rm" -rf x"#,
            r#"'rm' -rf x"#,
            r"\rm -rf x",
            "/bin/rm -rf x",
            r"r''m -rf x",
        ] {
            assert_eq!(one(variant).program, "rm", "{variant}");
        }
    }

    #[test]
    fn wrappers_and_env_assignments_are_seen_through() {
        for variant in [
            "sudo rm -rf x",
            "env FOO=1 rm -rf x",
            "FOO=1 BAR=2 rm -rf x",
            "sudo -u root rm -rf x",
            "nohup time rm -rf x",
        ] {
            let c = one(variant);
            assert_eq!(c.program, "rm", "{variant}");
            assert!(c.has_flag('r', "recursive"), "{variant}");
        }
    }

    #[test]
    fn substitution_and_variables_are_flagged() {
        assert!(one("rm -rf $(cat target.txt)").has_substitution);
        assert!(one("rm -rf `cat target.txt`").has_substitution);
        assert!(one("rm -rf $TARGET").has_variable);
        assert!(!one("rm -rf ./build").has_substitution);
    }

    #[test]
    fn separators_split_into_separate_commands() {
        let p = parse("cargo build && rm -rf dist; echo done", Shell::Posix);
        assert_eq!(p.len(), 3);
        assert_eq!(p[1].cmds[0].program, "rm");
    }

    #[test]
    fn pipes_stay_within_one_pipeline() {
        let p = parse("curl https://x.sh | sh", Shell::Posix);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].cmds.len(), 2);
        assert_eq!(p[0].cmds[1].program, "sh");
    }

    #[test]
    fn powershell_flags_are_whole_words() {
        let c = parse("Remove-Item -Recurse -Force C:\\x", Shell::PowerShell)
            .remove(0)
            .cmds
            .remove(0);
        assert_eq!(c.program, "remove-item");
        assert!(c.long_flags.contains("recurse"));
        assert!(c.long_flags.contains("force"));
        assert!(c.short_flags.is_empty(), "PowerShell has no flag clusters");
    }

    #[test]
    fn double_dash_ends_flag_parsing() {
        let c = one("rm -rf -- -weird-file");
        assert_eq!(c.operands, vec!["-weird-file"]);
    }
}
