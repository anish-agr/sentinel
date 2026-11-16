use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Default, Clone, Copy, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
    #[serde(default)]
    pub cache_read_input_tokens: u64,
    #[serde(default)]
    pub cache_creation_input_tokens: u64,
}

impl Usage {
    /// Everything the model had to read this turn, cached or not. This is the
    /// number that matters for "what did re-reading that file cost".
    pub fn total_input(&self) -> u64 {
        self.input_tokens + self.cache_read_input_tokens + self.cache_creation_input_tokens
    }
}

#[derive(Debug)]
pub struct Turn {
    pub text: String,
    pub usage: Usage,
    pub model: Option<String>,
}

#[derive(Deserialize)]
struct Line {
    #[serde(rename = "type")]
    kind: String,
    message: Option<Message>,
}

#[derive(Deserialize)]
struct Message {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    content: serde_json::Value,
    #[serde(default)]
    usage: Option<Usage>,
}

/// Assistant turns appended since `offset`, plus the new offset. A partially
/// written final line is left for the next call.
pub fn read_since(path: &Path, offset: u64) -> Result<(Vec<Turn>, u64)> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    // A different session reusing the path, or a truncated file, restarts.
    let start = if offset > len { 0 } else { offset };
    file.seek(SeekFrom::Start(start))?;

    let mut reader = BufReader::new(file);
    let mut turns = Vec::new();
    let mut consumed = start;
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 || !buf.ends_with('\n') {
            break;
        }
        consumed += n as u64;
        let Ok(line) = serde_json::from_str::<Line>(buf.trim()) else {
            continue;
        };
        if line.kind != "assistant" {
            continue;
        }
        let Some(message) = line.message else {
            continue;
        };
        let text = message
            .content
            .as_array()
            .map(|blocks| {
                blocks
                    .iter()
                    .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                    .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        if text.trim().is_empty() && message.usage.is_none() {
            continue;
        }
        turns.push(Turn {
            text,
            usage: message.usage.unwrap_or_default(),
            model: message.model,
        });
    }
    Ok((turns, consumed))
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Rate {
    pub input: f64,
    pub output: f64,
    #[serde(default)]
    pub cache_write: f64,
    #[serde(default)]
    pub cache_read: f64,
}

#[derive(Debug, Default)]
pub struct Pricing(HashMap<String, Rate>);

impl Pricing {
    pub fn load() -> Pricing {
        let path = crate::sentinel_home().join("pricing.toml");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Pricing::default();
        };
        match toml::from_str(&text) {
            Ok(rates) => Pricing(rates),
            Err(e) => {
                eprintln!("sentinel: ignoring {} ({e})", path.display());
                Pricing::default()
            }
        }
    }

    pub fn cost(&self, model: Option<&str>, usage: &Usage) -> f64 {
        let model = model.unwrap_or_default();
        let Some(rate) = self
            .0
            .iter()
            .filter(|(prefix, _)| model.contains(prefix.as_str()))
            .map(|(_, rate)| rate)
            .next()
        else {
            return 0.0;
        };
        let per_million = |tokens: u64, price: f64| tokens as f64 * price / 1_000_000.0;
        per_million(usage.input_tokens, rate.input)
            + per_million(usage.output_tokens, rate.output)
            + per_million(usage.cache_creation_input_tokens, rate.cache_write)
            + per_million(usage.cache_read_input_tokens, rate.cache_read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(path: &Path, lines: &[&str]) {
        let mut f = File::create(path).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
    }

    #[test]
    fn reads_assistant_turns_with_usage() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("t.jsonl");
        write(
            &path,
            &[
                r#"{"type":"user","message":{"content":"hi"}}"#,
                r#"{"type":"assistant","message":{"model":"claude-opus-5","content":[{"type":"text","text":"working on it"}],"usage":{"input_tokens":10,"output_tokens":20,"cache_read_input_tokens":5}}}"#,
            ],
        );
        let (turns, offset) = read_since(&path, 0).unwrap();
        assert_eq!(turns.len(), 1, "user lines are not agent turns");
        assert_eq!(turns[0].text, "working on it");
        assert_eq!(turns[0].usage.output_tokens, 20);
        assert_eq!(turns[0].usage.total_input(), 15);
        assert_eq!(offset, std::fs::metadata(&path).unwrap().len());
    }

    #[test]
    fn only_new_lines_are_returned() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("t.jsonl");
        write(
            &path,
            &[r#"{"type":"assistant","message":{"content":[{"type":"text","text":"one"}]}}"#],
        );
        let (_, offset) = read_since(&path, 0).unwrap();

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(
            f,
            r#"{{"type":"assistant","message":{{"content":[{{"type":"text","text":"two"}}]}}}}"#
        )
        .unwrap();

        let (turns, _) = read_since(&path, offset).unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].text, "two");
    }

    #[test]
    fn a_truncated_or_replaced_transcript_restarts_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("t.jsonl");
        write(
            &path,
            &[r#"{"type":"assistant","message":{"content":[{"type":"text","text":"one"}]}}"#],
        );
        let (turns, _) = read_since(&path, 999_999).unwrap();
        assert_eq!(
            turns.len(),
            1,
            "an offset past the end must not skip the file"
        );
    }

    #[test]
    fn cost_is_zero_until_prices_are_configured() {
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            ..Default::default()
        };
        assert_eq!(Pricing::default().cost(Some("claude-opus-5"), &usage), 0.0);

        let priced: HashMap<String, Rate> =
            toml::from_str("[\"claude-opus\"]\ninput = 15.0\noutput = 75.0\n").unwrap();
        assert_eq!(Pricing(priced).cost(Some("claude-opus-5"), &usage), 90.0);
    }
}
