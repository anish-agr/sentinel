use anyhow::Result;
use sentinel_store::Store;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct Stats {
    pub kinds: BTreeMap<String, usize>,
    pub detectors: BTreeMap<String, usize>,
    pub rules: BTreeMap<String, usize>,
    pub tools: BTreeMap<String, usize>,
    pub runs: usize,
    pub first_ts: Option<String>,
    pub last_ts: Option<String>,
    /// tool_call events carrying an exit code, i.e. those whose result landed.
    pub with_exit_code: usize,
    /// Blocks that stood, and blocks the agent cleared with `allow --once`.
    /// The ratio between them is the honest measure of whether the guard is
    /// stopping anything: a guard overridden every time is a logging feature.
    pub blocks: usize,
    pub overrides: usize,
    pub models: BTreeMap<String, (usize, usize)>,
    /// (calls, results) per day. A lifetime ratio is the wrong health signal —
    /// one bad week poisons it forever, so a recorder that is fine today still
    /// reports as broken. Per-day shows both the history and the present.
    pub by_day: BTreeMap<String, (usize, usize)>,
}

impl Stats {
    pub fn calls(&self) -> usize {
        *self.kinds.get("tool_call").unwrap_or(&0)
    }

    pub fn results(&self) -> usize {
        *self.kinds.get("tool_result").unwrap_or(&0)
    }

    /// The health metric. 1.0 means every call's result was captured; a
    /// sustained gap means the post hook is dead and exit codes are being lost.
    pub fn result_ratio(&self) -> f64 {
        match self.calls() {
            0 => 0.0,
            n => self.results() as f64 / n as f64,
        }
    }

    /// The ratio on the most recent day that recorded any calls — the number
    /// that says whether the recorder is working *now*.
    pub fn latest_day(&self) -> Option<(&String, f64, usize)> {
        self.by_day
            .iter()
            .rfind(|(_, (calls, _))| *calls > 0)
            .map(|(day, (calls, results))| (day, *results as f64 / *calls as f64, *calls))
    }

    pub fn silent_detectors(&self) -> Vec<&'static str> {
        sentinel_detect::detector_ids()
            .iter()
            .filter(|id| !self.detectors.contains_key(**id))
            .copied()
            .collect()
    }

    pub fn total(&self) -> usize {
        self.kinds.values().sum()
    }
}

pub fn collect(store: &Store, limit: u32) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut runs = std::collections::BTreeSet::new();
    let mut current_model: Option<String> = None;

    for event in store.events_json(None, limit)? {
        let kind = event["kind"].as_str().unwrap_or("unknown").to_string();

        // The transcript reader stores the model name on the agent's message.
        if kind == "agent_message" {
            if let Some(model) = event["tool"].as_str() {
                current_model = Some(model.to_string());
            }
        }
        if matches!(kind.as_str(), "tool_call" | "guard_decision") {
            if let Some(model) = &current_model {
                let entry = stats.models.entry(model.clone()).or_default();
                if kind == "tool_call" {
                    entry.0 += 1;
                } else {
                    entry.1 += 1;
                }
            }
        }

        if let Some(ts) = event["ts"].as_str() {
            if stats.first_ts.as_deref().is_none_or(|f| ts < f) {
                stats.first_ts = Some(ts.to_string());
            }
            if stats.last_ts.as_deref().is_none_or(|l| ts > l) {
                stats.last_ts = Some(ts.to_string());
            }
        }
        if let Some(run) = event["run_id"].as_str() {
            runs.insert(run.to_string());
        }
        if !event["exit_code"].is_null() {
            stats.with_exit_code += 1;
        }

        let day = event["ts"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(10)
            .collect::<String>();

        match kind.as_str() {
            "tool_call" => {
                let tool = event["tool"].as_str().unwrap_or("unknown").to_string();
                *stats.tools.entry(tool).or_insert(0) += 1;
                stats.by_day.entry(day).or_default().0 += 1;
            }
            "tool_result" => {
                stats.by_day.entry(day).or_default().1 += 1;
            }
            "detection" => {
                if let Some(d) = event["meta"]["detector"].as_str() {
                    *stats.detectors.entry(d.to_string()).or_insert(0) += 1;
                }
            }
            "guard_decision" => {
                if let Some(r) = event["meta"]["rule"].as_str() {
                    *stats.rules.entry(r.to_string()).or_insert(0) += 1;
                }
                match event["meta"]["verdict"].as_str() {
                    Some("overridden") => stats.overrides += 1,
                    Some(_) | None => stats.blocks += 1,
                }
            }
            _ => {}
        }

        *stats.kinds.entry(kind).or_insert(0) += 1;
    }

    stats.runs = runs.len();
    Ok(stats)
}
