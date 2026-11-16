//! Credential scrubbing for `args_summary`. The full argument payload goes to
//! the blob store; this is what lands in the human-readable log line.

const REDACTED: &str = "<redacted>";

const PREFIXES: &[&str] = &[
    "AKIA",
    "ASIA",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "sk-",
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "rk_live_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxs-",
    "AIza",
    "ya29.",
    "SG.",
    "npm_",
    "dop_v1_",
    "shpat_",
    "hf_",
];

const KEY_HINTS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "apikey",
    "api_key",
    "access_key",
    "secret_key",
    "private_key",
    "credential",
    "auth",
    "session",
];

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_like_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts[0].starts_with("ey")
        && parts.iter().all(|p| {
            p.len() >= 8
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn high_entropy_secret(s: &str) -> bool {
    if s.len() < 24 || s.contains('/') || s.contains('\\') {
        return false;
    }
    let alnum = s.bytes().filter(|b| b.is_ascii_alphanumeric()).count();
    alnum * 10 >= s.len() * 8 && shannon_entropy(s) > 4.0
}

fn is_secret_value(s: &str) -> bool {
    let t = s.trim_matches(|c| c == '"' || c == '\'' || c == ',');
    // Split on URL/host punctuation so a key embedded in a URL is still caught,
    // without matching a prefix in the middle of an ordinary word.
    t.split(['/', '@', ':', '?', '&'])
        .any(|part| PREFIXES.iter().any(|p| part.starts_with(p)) || looks_like_jwt(part))
        || high_entropy_secret(t)
}

/// Replaces credential-shaped material in place. Conservative by design: a
/// missed secret is a leak, but an over-eager redaction destroys the summary's
/// usefulness, so we only fire on strong signals.
pub fn scrub(input: &str) -> String {
    if input.contains("-----BEGIN") {
        return format!("{REDACTED} (private key material)");
    }
    let mut out = String::with_capacity(input.len());
    let mut prev_was_auth_flag = false;
    for (i, token) in input.split_whitespace().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        // `--token=VALUE` / `PASSWORD=VALUE` — redact only the value half.
        if let Some((key, value)) = token.split_once('=') {
            let k = key
                .trim_start_matches('-')
                .to_ascii_lowercase()
                .replace('-', "_");
            if !value.is_empty()
                && (KEY_HINTS.iter().any(|h| k.contains(h)) || is_secret_value(value))
            {
                out.push_str(key);
                out.push('=');
                out.push_str(REDACTED);
                prev_was_auth_flag = false;
                continue;
            }
        }
        if prev_was_auth_flag || is_secret_value(token) {
            out.push_str(REDACTED);
            prev_was_auth_flag = false;
            continue;
        }
        let lower = token.to_ascii_lowercase();
        prev_was_auth_flag = matches!(
            lower.as_str(),
            "bearer" | "--password" | "--token" | "--secret" | "--api-key"
        );
        out.push_str(token);
    }
    out
}

/// Scrubbed and truncated to the 200-char budget the event schema allows.
pub fn summary(input: &str) -> String {
    let flat = input.replace(['\n', '\r'], " ");
    let mut s = scrub(&flat);
    if s.chars().count() > 200 {
        s = s.chars().take(197).collect::<String>() + "...";
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_key_shapes() {
        assert!(scrub("aws --key AKIAIOSFODNN7EXAMPLE").contains(REDACTED));
        assert!(scrub("git remote add o https://ghp_16CharsAndMoreHere1234567").contains(REDACTED));
        assert!(!scrub("curl -H Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U").contains("eyJzdWIi"));
    }

    #[test]
    fn redacts_assignment_values_by_key_name() {
        let out = scrub("DATABASE_PASSWORD=hunter2 cargo run");
        assert_eq!(out, "DATABASE_PASSWORD=<redacted> cargo run");
        assert!(scrub("--api-key=abc123").contains(REDACTED));
    }

    #[test]
    fn redacts_after_bearer() {
        assert_eq!(scrub("Bearer abc"), "Bearer <redacted>");
    }

    #[test]
    fn private_keys_never_survive() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----";
        assert!(!scrub(pem).contains("MIIEow"));
    }

    #[test]
    fn leaves_ordinary_commands_alone() {
        for cmd in [
            "cargo test --workspace",
            "git commit -m fix",
            "rm -rf ./target/debug/build",
            "npm install --save-dev typescript",
            "SELECT * FROM users WHERE id = 1",
        ] {
            assert_eq!(scrub(cmd), cmd, "over-redacted: {cmd}");
        }
    }

    #[test]
    fn paths_are_not_mistaken_for_secrets() {
        let p = "/Users/author/Documents/GitHub/sentinel/crates/sentinel-store/src/scrub.rs";
        assert_eq!(scrub(p), p);
    }

    #[test]
    fn summary_respects_the_200_char_budget() {
        let s = summary(&"x".repeat(500));
        assert_eq!(s.chars().count(), 200);
        assert!(s.ends_with("..."));
    }

    #[test]
    fn summary_is_single_line() {
        assert!(!summary("line one\nline two").contains('\n'));
    }
}
