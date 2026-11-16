use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    Deny,
    Warn,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardConfig {
    pub enabled: bool,
    pub protected_branches: Vec<String>,
    pub protected_paths: Vec<String>,
    /// Paths owned by the operating system. Destroying or relaxing permissions
    /// on one outlives the session; writing to one is ordinary sysadmin work.
    pub system_paths: Vec<String>,
    pub allowed_hosts: Vec<String>,
    /// Substrings that mark a database connection as safe to destroy.
    pub test_dsn_markers: Vec<String>,
    pub rules: BTreeMap<String, RuleMode>,
    /// Fingerprints of specific commands the user chose to always allow here.
    pub allow: Vec<String>,
    #[serde(skip)]
    pub load_errors: Vec<String>,
}

pub const CONTROL_PLANE_PATHS: &[&str] = &[
    "**/.sentinel",
    "**/.sentinel/**",
    "**/.claude/settings.json",
    "**/.claude/settings*.json",
    "~/.config/sentinel/**",
];

pub const CONTROL_PLANE_DIRS: &[&str] = &["**/.claude"];

fn default_protected_paths() -> Vec<String> {
    let mut paths: Vec<String> = [
        "~/.ssh/**",
        "~/.ssh",
        "~/.aws/**",
        "~/.aws",
        "~/.config/**",
        "~/.gnupg/**",
        "~/.kube/**",
        "~/.docker/config.json",
        "~/.npmrc",
        "~/.pypirc",
        "~/.netrc",
        "~/.gitconfig",
        "~/Library/Keychains/**",
        "~/AppData/Roaming/Microsoft/Crypto/**",
        "**/.env",
        "**/.env.*",
        "**/id_rsa*",
        "**/id_ed25519*",
        "**/*.pem",
        "**/*.p12",
        "**/credentials",
        "**/serviceAccount*.json",
    ]
    .map(String::from)
    .to_vec();
    paths.extend(CONTROL_PLANE_PATHS.iter().map(|s| String::from(*s)));
    if let Some(global) = global_path() {
        let s = global.to_string_lossy().replace('\\', "/");
        if !paths.contains(&s) {
            paths.push(s);
        }
    }
    paths
}

impl Default for GuardConfig {
    fn default() -> Self {
        GuardConfig {
            enabled: true,
            protected_branches: [
                "main",
                "master",
                "release/**",
                "develop",
                "prod",
                "production",
            ]
            .map(String::from)
            .to_vec(),
            protected_paths: default_protected_paths(),
            system_paths: [
                "/etc",
                "/etc/**",
                "/boot/**",
                "/sbin/**",
                "/usr/sbin/**",
                "/var/spool/cron/**",
                "/System/**",
                "/Library/LaunchDaemons/**",
                "/Library/LaunchAgents/**",
                "C:/Windows/**",
                "C:/Program Files/**",
            ]
            .map(String::from)
            .to_vec(),
            allowed_hosts: [
                "sh.rustup.rs",
                "get.docker.com",
                "install.python-poetry.org",
            ]
            .map(String::from)
            .to_vec(),
            test_dsn_markers: [
                "localhost",
                "127.0.0.1",
                "::1",
                "test",
                "dev",
                "local",
                "sandbox",
            ]
            .map(String::from)
            .to_vec(),
            rules: BTreeMap::new(),
            allow: Vec::new(),
            load_errors: Vec::new(),
        }
    }
}

impl GuardConfig {
    pub fn mode(&self, rule: &str) -> RuleMode {
        self.rules.get(rule).copied().unwrap_or(RuleMode::Deny)
    }

    pub fn is_allowed(&self, fingerprint: &str) -> bool {
        self.allow.iter().any(|a| a == fingerprint)
    }

    pub fn load(repo: &Path) -> GuardConfig {
        Self::load_layered(global_path().as_deref(), &repo_path(repo))
    }

    pub fn load_layered(global: Option<&Path>, repo_file: &Path) -> GuardConfig {
        let mut errors = Vec::new();
        let mut table = toml::Table::new();
        for path in global.into_iter().chain(std::iter::once(repo_file)) {
            match read_table(path) {
                Ok(Some(t)) => table.extend(t),
                Ok(None) => {}
                Err(e) => errors.push(e),
            }
        }

        let mut cfg: GuardConfig = toml::Value::Table(table).try_into().unwrap_or_else(|e| {
            errors.push(format!("{}: {e}", repo_file.display()));
            GuardConfig::default()
        });
        if !errors.is_empty() {
            for e in &errors {
                eprintln!(
                    "sentinel: REFUSING TO READ GUARD CONFIG — {e}\n\
                     sentinel: the guard is running fully locked down until this is fixed: \
                     every rule denies, and no allowlist entry is in effect."
                );
            }
            cfg.enabled = true;
            cfg.rules.clear();
            cfg.allow.clear();
            cfg.load_errors = errors;
        }
        cfg
    }

    pub fn save_repo(&self, repo: &Path) -> Result<()> {
        let path = repo_path(repo);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn allow_always(repo: &Path, fingerprint: &str) -> Result<()> {
        let path = repo_path(repo);
        let table = read_table(&path).map_err(|e| {
            anyhow::anyhow!(
                "{e}\nRefusing to touch it: writing now would replace your settings with \
                 defaults. Fix the file by hand, then run this again."
            )
        })?;
        let mut cfg: GuardConfig = match table {
            Some(t) => toml::Value::Table(t).try_into().map_err(|e| {
                anyhow::anyhow!("{}: {e}\nRefusing to overwrite it.", path.display())
            })?,
            None => GuardConfig::default(),
        };
        if !cfg.allow.iter().any(|a| a == fingerprint) {
            cfg.allow.push(fingerprint.to_string());
        }
        cfg.save_repo(repo)
    }
}

/// `Ok(None)` for a file that is not there, `Err` for one that is there and is
/// not valid TOML. Conflating those two was the whole of the config defect:
/// "you have no config" and "your config is broken" want opposite responses.
fn read_table(path: &Path) -> std::result::Result<Option<toml::Table>, String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Ok(None);
    };
    text.parse()
        .map(Some)
        .map_err(|e| format!("{}: {e}", path.display()))
}

pub fn repo_path(repo: &Path) -> PathBuf {
    repo.join(".sentinel").join("guard.toml")
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

pub fn global_path() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(x).join("sentinel").join("guard.toml"));
    }
    #[cfg(windows)]
    {
        if let Some(a) = std::env::var_os("APPDATA") {
            return Some(PathBuf::from(a).join("sentinel").join("guard.toml"));
        }
    }
    Some(
        home_dir()?
            .join(".config")
            .join("sentinel")
            .join("guard.toml"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_settings_layer_over_global_instead_of_replacing_it() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tmp.path().join("global.toml");
        fs::write(&global, "protected_branches = [\"trunk\"]\n").unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".sentinel")).unwrap();
        fs::write(repo_path(&repo), "allow = [\"abc\"]\n").unwrap();

        let cfg = GuardConfig::load_layered(Some(&global), &repo_path(&repo));

        assert!(cfg.load_errors.is_empty(), "both files parse");
        assert_eq!(cfg.allow, vec!["abc"], "the repo file must apply");
        assert_eq!(
            cfg.protected_branches,
            vec!["trunk"],
            "a global setting the repo file does not mention must survive"
        );
    }

    /// A repository with no `guard.toml` is the common case, not an error, and
    /// must not be mistaken for a broken one.
    #[test]
    fn an_absent_config_is_not_a_broken_config() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = GuardConfig::load_layered(None, &tmp.path().join("nothing-here.toml"));
        assert!(cfg.load_errors.is_empty());
        assert!(cfg.enabled);
        assert_eq!(
            cfg.protected_branches,
            GuardConfig::default().protected_branches
        );
    }

    #[test]
    fn a_config_that_does_not_parse_fails_closed_and_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        // A valid global file that switches the guard off and permits a
        // command — everything an attacker or an accident would want to keep.
        let global = tmp.path().join("global.toml");
        fs::write(
            &global,
            "enabled = false\nallow = [\"deadbeef\"]\n\
             [rules]\n\"fs.remove_protected\" = \"off\"\n",
        )
        .unwrap();
        // …and a repo file with a missing bracket.
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".sentinel")).unwrap();
        fs::write(repo_path(&repo), "protected_paths = [\"~/x/**\"\n").unwrap();

        let cfg = GuardConfig::load_layered(Some(&global), &repo_path(&repo));

        assert_eq!(cfg.load_errors.len(), 1, "the failure must be recorded");
        assert!(
            cfg.load_errors[0].contains("guard.toml"),
            "the record must name the file: {:?}",
            cfg.load_errors
        );
        assert!(cfg.enabled, "a broken config must not leave the guard off");
        assert!(
            cfg.allow.is_empty(),
            "a broken config must not leave allowlist entries in force"
        );
        assert_eq!(
            cfg.mode("fs.remove_protected"),
            RuleMode::Deny,
            "a broken config must not leave a rule switched off"
        );
    }

    /// The loud path must not fire on a config that is merely unusual. A file
    /// that parses is honoured exactly as written, `enabled = false` included.
    #[test]
    fn a_config_that_parses_is_honoured_even_when_it_relaxes_things() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".sentinel")).unwrap();
        fs::write(
            repo_path(&repo),
            "enabled = false\nallow = [\"deadbeef\"]\n\
             [rules]\n\"fs.remove_protected\" = \"warn\"\n",
        )
        .unwrap();

        let cfg = GuardConfig::load_layered(None, &repo_path(&repo));
        assert!(cfg.load_errors.is_empty());
        assert!(!cfg.enabled);
        assert_eq!(cfg.allow, vec!["deadbeef"]);
        assert_eq!(cfg.mode("fs.remove_protected"), RuleMode::Warn);
    }

    #[test]
    fn allow_always_refuses_to_overwrite_a_config_it_could_not_parse() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".sentinel")).unwrap();
        // One missing bracket. Everything below it is still the user's policy.
        let original = "protected_branches = [\"trunk\", \"staging\"\n\
                        protected_paths = [\"~/.secrets/**\"]\n\
                        allow = [\"already-allowed\"]\n";
        fs::write(repo_path(&repo), original).unwrap();

        let result = GuardConfig::allow_always(&repo, "new-fingerprint");
        assert!(
            result.is_err(),
            "allowlisting against an unparseable config must fail loudly"
        );
        assert_eq!(
            fs::read_to_string(repo_path(&repo)).unwrap(),
            original,
            "the user's config was overwritten"
        );
    }

    /// The same call against a config that parses must still work, or the
    /// guard above is just a broken feature.
    #[test]
    fn allow_always_still_appends_to_a_config_that_parses() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".sentinel")).unwrap();
        fs::write(repo_path(&repo), "allow = [\"first\"]\n").unwrap();

        GuardConfig::allow_always(&repo, "second").unwrap();
        let text = fs::read_to_string(repo_path(&repo)).unwrap();
        assert!(text.contains("first"), "the existing entry must survive");
        assert!(text.contains("second"), "the new entry must be recorded");

        // A repo with no config yet is not an error; it is the common case.
        let fresh = tmp.path().join("fresh");
        fs::create_dir_all(&fresh).unwrap();
        GuardConfig::allow_always(&fresh, "only").unwrap();
        assert!(fs::read_to_string(repo_path(&fresh))
            .unwrap()
            .contains("only"));
    }
}
