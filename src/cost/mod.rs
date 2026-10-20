//! cost — token and list-price accounting from Claude Code transcript `usage` (#63).
//!
//! Walks `~/.claude/projects/**` (top-level sessions and `subagents/*.jsonl`), counts each API
//! message once, prices it from the pinned `prices.toml`, and rolls up by model / actor / project /
//! session / day / week. List price only: a subscription does not bill this, and the module never
//! pretends it does. A model id missing from the table is an UNPRICED row, never zero.

use crate::json::{parse, to_json_string, JsonValue};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Everything that can go wrong in cost accounting.
#[derive(Debug)]
pub enum CostError {
    /// `prices.toml` is malformed or incomplete.
    Prices(String),
    /// A file or directory could not be read or written.
    Io(String),
    /// A bad command-line value.
    BadArg(String),
}

impl std::fmt::Display for CostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CostError::Prices(m) => write!(f, "prices table: {m}"),
            CostError::Io(m) => write!(f, "io: {m}"),
            CostError::BadArg(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CostError {}

// ---------------------------------------------------------------- price table

/// USD per million tokens for one model id.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelPrice {
    pub id: String,
    pub input: f64,
    pub output: f64,
    pub cache_write_5m: f64,
    pub cache_write_1h: f64,
    pub cache_read: f64,
}

/// The pinned, dated price table.
#[derive(Debug, Clone)]
pub struct Prices {
    pub valid_from: String,
    pub reviewed_until: String,
    pub source: String,
    pub models: Vec<ModelPrice>,
}

const BUILTIN_PRICES: &str = include_str!("../../prices.toml");

impl Prices {
    pub fn builtin() -> Result<Prices, CostError> {
        Prices::parse(BUILTIN_PRICES)
    }

    pub fn load(path: &Path) -> Result<Prices, CostError> {
        let text = fs::read_to_string(path)
            .map_err(|e| CostError::Io(format!("read {}: {e}", path.display())))?;
        Prices::parse(&text)
    }

    /// Parse the small TOML subset `prices.toml` uses: `[meta]`, `[[model]]`, `key = "str"|number`.
    pub fn parse(text: &str) -> Result<Prices, CostError> {
        enum Sec {
            None,
            Meta,
            Model,
        }
        let (mut sec, mut meta) = (Sec::None, HashMap::<String, String>::new());
        let mut rows: Vec<HashMap<String, String>> = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let line = strip_comment(raw).trim().to_string();
            if line.is_empty() {
                continue;
            }
            let at = |m: &str| CostError::Prices(format!("line {}: {m}", n + 1));
            if line == "[meta]" {
                sec = Sec::Meta;
            } else if line == "[[model]]" {
                sec = Sec::Model;
                rows.push(HashMap::new());
            } else if let Some((k, v)) = line.split_once('=') {
                let (k, v) = (k.trim().to_string(), v.trim().trim_matches('"').to_string());
                let target = match sec {
                    Sec::Meta => &mut meta,
                    Sec::Model => rows.last_mut().ok_or_else(|| at("key outside a section"))?,
                    Sec::None => return Err(at("key outside a section")),
                };
                if target.insert(k.clone(), v).is_some() {
                    return Err(at(&format!("duplicate key {k}")));
                }
            } else {
                return Err(at(&format!("unparseable line {line:?}")));
            }
        }
        let get = |m: &HashMap<String, String>, k: &str| {
            m.get(k)
                .cloned()
                .ok_or_else(|| CostError::Prices(format!("missing key {k}")))
        };
        let valid_from = get(&meta, "valid_from")?;
        let reviewed_until = get(&meta, "reviewed_until")?;
        for d in [&valid_from, &reviewed_until] {
            parse_day(d)?;
        }
        if reviewed_until < valid_from {
            return Err(CostError::Prices(
                "reviewed_until precedes valid_from".into(),
            ));
        }
        let mut models = Vec::new();
        for r in &rows {
            let id = get(r, "id")?;
            let num = |k: &str| -> Result<f64, CostError> {
                let v: f64 = get(r, k)?
                    .parse()
                    .map_err(|_| CostError::Prices(format!("{id}: {k} is not a number")))?;
                if v.is_finite() && v >= 0.0 {
                    Ok(v)
                } else {
                    Err(CostError::Prices(format!("{id}: {k} must be >= 0")))
                }
            };
            if models.iter().any(|m: &ModelPrice| m.id == id) {
                return Err(CostError::Prices(format!("duplicate model {id}")));
            }
            models.push(ModelPrice {
                input: num("input")?,
                output: num("output")?,
                cache_write_5m: num("cache_write_5m")?,
                cache_write_1h: num("cache_write_1h")?,
                cache_read: num("cache_read")?,
                id,
            });
        }
        Ok(Prices {
            valid_from,
            reviewed_until,
            source: get(&meta, "source")?,
            models,
        })
    }

    pub fn lookup(&self, model: &str) -> Option<&ModelPrice> {
        let id = normalize_model(model);
        self.models.iter().find(|m| m.id == id)
    }
}

fn strip_comment(s: &str) -> &str {
    let mut in_str = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &s[..i],
            _ => {}
        }
    }
    s
}

/// `claude-haiku-4-5-20251001` -> `claude-haiku-4-5`; `claude-opus-5-5[1m]` -> `claude-opus-5-5`.
pub fn normalize_model(m: &str) -> String {
    let m = m.split('[').next().unwrap_or(m);
    if let Some((head, tail)) = m.rsplit_once('-') {
        if tail.len() == 8 && tail.bytes().all(|b| b.is_ascii_digit()) {
            return head.to_string();
        }
    }
    m.to_string()
}

// ---------------------------------------------------------------- calendar helpers (UTC)

fn parse_day(s: &str) -> Result<i64, CostError> {
    let bad = || CostError::BadArg(format!("invalid date {s:?} (expected YYYY-MM-DD)"));
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return Err(bad());
    }
    let y: i64 = s[0..4].parse().map_err(|_| bad())?;
    let m: i64 = s[5..7].parse().map_err(|_| bad())?;
    let d: i64 = s[8..10].parse().map_err(|_| bad())?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }
    Ok(days_from_civil(y, m, d))
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Monday of the week containing `day` (a `YYYY-MM-DD` string), as `YYYY-MM-DD`.
fn week_start(day: &str) -> String {
    match parse_day(day) {
        Ok(n) => {
            let (y, m, d) = civil_from_days(n - (n + 3).rem_euclid(7));
            format!("{y:04}-{m:02}-{d:02}")
        }
        Err(_) => "unknown".into(),
    }
}

fn today_utc() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 86400) as i64
}

// ---------------------------------------------------------------- scan

/// One counted API message.
#[derive(Debug, Clone)]
pub struct Record {
    pub session: String,
    pub project: String,
    pub actor: &'static str,
    pub model: String,
    pub day: String,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write_5m: u64,
    pub cache_write_1h: u64,
}

/// What the scan saw, so every number can be read against its event count.
#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub files: u64,
    pub lines: u64,
    pub usage_lines: u64,
    pub messages: u64,
    pub duplicates_skipped: u64,
    pub synthetic_skipped: u64,
    pub no_id: u64,
    pub malformed: u64,
}

#[derive(Debug, Default, Clone)]
pub struct ScanOptions {
    pub since: Option<String>,
    pub session: Option<String>,
}

fn collect_files(root: &Path, min_mtime: Option<u64>) -> Vec<(PathBuf, String, String, bool)> {
    // (path, project, session, in_subagents)
    let mut out = Vec::new();
    let recent = |p: &Path| match min_mtime {
        None => true,
        Some(t) => p
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() >= t)
            .unwrap_or(true),
    };
    let jsonl = |dir: &Path| -> Vec<PathBuf> {
        fs::read_dir(dir)
            .map(|it| {
                it.flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("jsonl")
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let name = |p: &Path| {
        p.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string()
    };
    let Ok(projects) = fs::read_dir(root) else {
        return out;
    };
    for pd in projects.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
        let project = name(&pd);
        for f in jsonl(&pd) {
            if recent(&f) {
                let s = f
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_string();
                out.push((f, project.clone(), s, false));
            }
        }
        if let Ok(it) = fs::read_dir(&pd) {
            for sd in it.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
                let session = name(&sd);
                for f in jsonl(&sd.join("subagents")) {
                    if recent(&f) {
                        out.push((f, project.clone(), session.clone(), true));
                    }
                }
            }
        }
    }
    out.sort();
    out
}

fn u(v: Option<&JsonValue>) -> u64 {
    v.and_then(|v| v.as_f64()).map(|n| n as u64).unwrap_or(0)
}

/// Scan `root` and return one deduplicated [`Record`] per API message.
///
/// Claude Code writes one transcript line per content block, each repeating the whole message
/// `usage`; counting lines inflates a message by its block count (7x observed), so messages are
/// keyed on `message.id`, keeping the largest value of each field (the final streamed usage).
pub fn scan(root: &Path, opts: &ScanOptions) -> Result<(Vec<Record>, ScanStats), CostError> {
    let since_day = match &opts.since {
        Some(s) => Some(parse_day(s)?),
        None => None,
    };
    let min_mtime = since_day.map(|d| (d.max(0) as u64) * 86400);
    let mut stats = ScanStats::default();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut recs = Vec::new();
    for (path, project, session, in_sub) in collect_files(root, min_mtime) {
        if let Some(want) = &opts.session {
            if !session.starts_with(want.as_str()) {
                continue;
            }
        }
        let file = fs::File::open(&path)
            .map_err(|e| CostError::Io(format!("open {}: {e}", path.display())))?;
        stats.files += 1;
        let mut rd = BufReader::with_capacity(1 << 20, file);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let n = rd
                .read_until(b'\n', &mut buf)
                .map_err(|e| CostError::Io(format!("read {}: {e}", path.display())))?;
            if n == 0 {
                break;
            }
            stats.lines += 1;
            // Cheap byte prefilter before the JSON parse: only assistant lines carry usage.
            if !contains(&buf, b"\"input_tokens\"") {
                continue;
            }
            let line = String::from_utf8_lossy(&buf);
            let Ok(v) = parse(line.trim()) else {
                // A partial last line of a live file is expected; count it, do not guess.
                stats.malformed += 1;
                continue;
            };
            let Some(msg) = v.get("message") else {
                continue;
            };
            let Some(usage) = msg.get("usage") else {
                continue;
            };
            stats.usage_lines += 1;
            let model = msg.get("model").and_then(|m| m.as_str()).unwrap_or("");
            let day = v
                .get("timestamp")
                .and_then(|t| t.as_str())
                .and_then(|t| t.get(..10))
                .unwrap_or("unknown")
                .to_string();
            if let Some(s) = &opts.since {
                if day.as_str() < s.as_str() {
                    continue;
                }
            }
            let key = msg
                .get("id")
                .and_then(|i| i.as_str())
                .or_else(|| v.get("requestId").and_then(|i| i.as_str()));
            let (input, output) = (u(usage.get("input_tokens")), u(usage.get("output_tokens")));
            let cache_read = u(usage.get("cache_read_input_tokens"));
            let created = u(usage.get("cache_creation_input_tokens"));
            // TTL split when present; an unsplit total is priced as 5-minute writes.
            let (w5, w1) = match usage.get("cache_creation") {
                Some(c) => (
                    u(c.get("ephemeral_5m_input_tokens")),
                    u(c.get("ephemeral_1h_input_tokens")),
                ),
                None => (created, 0),
            };
            match key {
                Some(k) => {
                    if let Some(&i) = seen.get(k) {
                        // Streaming writes the same message several times and only
                        // `output_tokens` grows (4.7% of messages on the live corpus);
                        // keep the largest of every field, i.e. the final usage.
                        let r: &mut Record = &mut recs[i];
                        r.input = r.input.max(input);
                        r.output = r.output.max(output);
                        r.cache_read = r.cache_read.max(cache_read);
                        r.cache_write_5m = r.cache_write_5m.max(w5);
                        r.cache_write_1h = r.cache_write_1h.max(w1);
                        stats.duplicates_skipped += 1;
                        continue;
                    }
                    seen.insert(k.to_string(), recs.len());
                }
                None => stats.no_id += 1,
            }
            if model == "<synthetic>" && input + output + cache_read + w5 + w1 == 0 {
                stats.synthetic_skipped += 1;
                continue;
            }
            let sidechain = v
                .get("isSidechain")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            stats.messages += 1;
            recs.push(Record {
                session: session.clone(),
                project: project.clone(),
                actor: if in_sub || sidechain {
                    "subagent"
                } else {
                    "driver"
                },
                model: normalize_model(model),
                day,
                input,
                output,
                cache_read,
                cache_write_5m: w5,
                cache_write_1h: w1,
            });
        }
    }
    Ok((recs, stats))
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------- aggregation

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    Model,
    Actor,
    Project,
    Session,
    Day,
    Week,
}

impl GroupBy {
    pub fn parse(s: &str) -> Result<GroupBy, CostError> {
        Ok(match s {
            "model" => GroupBy::Model,
            "actor" => GroupBy::Actor,
            "project" => GroupBy::Project,
            "session" => GroupBy::Session,
            "day" => GroupBy::Day,
            "week" => GroupBy::Week,
            _ => {
                return Err(CostError::BadArg(format!(
                    "invalid --by {s} (expected model|actor|project|session|day|week)"
                )))
            }
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            GroupBy::Model => "model",
            GroupBy::Actor => "actor",
            GroupBy::Project => "project",
            GroupBy::Session => "session",
            GroupBy::Day => "day",
            GroupBy::Week => "week",
        }
    }

    fn key(self, r: &Record) -> String {
        match self {
            GroupBy::Model => r.model.clone(),
            GroupBy::Actor => r.actor.to_string(),
            GroupBy::Project => r.project.clone(),
            GroupBy::Session => r.session.clone(),
            GroupBy::Day => r.day.clone(),
            GroupBy::Week => week_start(&r.day),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Row {
    pub key: String,
    pub messages: u64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write_5m: u64,
    pub cache_write_1h: u64,
    /// List-price USD of the priced messages only.
    pub cost_usd: f64,
    pub unpriced_messages: u64,
    pub unpriced_models: Vec<String>,
}

impl Row {
    fn add(&mut self, r: &Record, prices: &Prices) {
        self.messages += 1;
        self.input += r.input;
        self.output += r.output;
        self.cache_read += r.cache_read;
        self.cache_write_5m += r.cache_write_5m;
        self.cache_write_1h += r.cache_write_1h;
        match prices.lookup(&r.model) {
            Some(p) => self.cost_usd += message_cost(p, r),
            None => {
                self.unpriced_messages += 1;
                if !self.unpriced_models.contains(&r.model) {
                    self.unpriced_models.push(r.model.clone());
                }
            }
        }
    }

    fn all_unpriced(&self) -> bool {
        self.unpriced_messages > 0 && self.unpriced_messages == self.messages
    }
}

/// List-price USD for one message.
pub fn message_cost(p: &ModelPrice, r: &Record) -> f64 {
    (r.input as f64 * p.input
        + r.output as f64 * p.output
        + r.cache_read as f64 * p.cache_read
        + r.cache_write_5m as f64 * p.cache_write_5m
        + r.cache_write_1h as f64 * p.cache_write_1h)
        / 1e6
}

#[derive(Debug, Clone)]
pub struct Report {
    pub by: GroupBy,
    pub rows: Vec<Row>,
    pub total: Row,
    /// Messages dated after the table's `reviewed_until`.
    pub stale_messages: u64,
}

pub fn aggregate(recs: &[Record], by: GroupBy, prices: &Prices) -> Report {
    let mut map: HashMap<String, Row> = HashMap::new();
    let mut total = Row {
        key: "TOTAL".into(),
        ..Default::default()
    };
    let mut stale = 0;
    for r in recs {
        if r.day.as_str() > prices.reviewed_until.as_str() {
            stale += 1;
        }
        let k = by.key(r);
        let row = map.entry(k.clone()).or_insert_with(|| Row {
            key: k,
            ..Default::default()
        });
        row.add(r, prices);
        total.add(r, prices);
    }
    let mut rows: Vec<Row> = map.into_values().collect();
    match by {
        GroupBy::Day | GroupBy::Week => rows.sort_by(|a, b| a.key.cmp(&b.key)),
        _ => rows.sort_by(|a, b| {
            b.cost_usd
                .partial_cmp(&a.cost_usd)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.key.cmp(&b.key))
        }),
    }
    Report {
        by,
        rows,
        total,
        stale_messages: stale,
    }
}

// ---------------------------------------------------------------- rendering

pub fn warnings(rep: &Report, prices: &Prices) -> Vec<String> {
    let mut w = Vec::new();
    if rep.stale_messages > 0 {
        w.push(format!(
            "STALE PRICES: {} message(s) are dated after prices.toml reviewed_until {}; re-review the table",
            rep.stale_messages, prices.reviewed_until
        ));
    }
    if rep.total.unpriced_messages > 0 {
        w.push(format!(
            "UNPRICED: {} message(s) on model(s) not in prices.toml: {} (excluded from cost, not counted as zero)",
            rep.total.unpriced_messages,
            rep.total.unpriced_models.join(", ")
        ));
    }
    w
}

fn money(r: &Row) -> String {
    if r.all_unpriced() {
        "UNPRICED".into()
    } else if r.unpriced_messages > 0 {
        format!("${:.2}+UNPRICED({})", r.cost_usd, r.unpriced_messages)
    } else {
        format!("${:.2}", r.cost_usd)
    }
}

pub fn render_table(rep: &Report, prices: &Prices) -> String {
    let mut out = format!(
        "prices: valid_from {} reviewed_until {} (list price, not a subscription bill)\n",
        prices.valid_from, prices.reviewed_until
    );
    let head = [
        rep.by.as_str(),
        "msgs",
        "input",
        "output",
        "cache_read",
        "cache_w5m",
        "cache_w1h",
        "list_usd",
    ];
    let line = |r: &Row| {
        [
            r.key.clone(),
            r.messages.to_string(),
            r.input.to_string(),
            r.output.to_string(),
            r.cache_read.to_string(),
            r.cache_write_5m.to_string(),
            r.cache_write_1h.to_string(),
            money(r),
        ]
    };
    let mut table: Vec<[String; 8]> = vec![head.map(String::from)];
    table.extend(rep.rows.iter().map(line));
    table.push(line(&rep.total));
    let widths: Vec<usize> = (0..8)
        .map(|c| {
            table
                .iter()
                .map(|r| r[c].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    for (i, r) in table.iter().enumerate() {
        let cells: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(c, s)| {
                if c == 0 {
                    format!("{s:<w$}", w = widths[c])
                } else {
                    format!("{s:>w$}", w = widths[c])
                }
            })
            .collect();
        out.push_str(cells.join("  ").trim_end());
        out.push('\n');
        if i == 0 || i + 2 == table.len() {
            out.push_str(&"-".repeat(widths.iter().sum::<usize>() + 2 * 7));
            out.push('\n');
        }
    }
    out
}

fn n(x: u64) -> JsonValue {
    JsonValue::Number(x as f64)
}

fn row_json(r: &Row) -> JsonValue {
    JsonValue::Object(vec![
        ("key".into(), JsonValue::Str(r.key.clone())),
        ("messages".into(), n(r.messages)),
        ("input".into(), n(r.input)),
        ("output".into(), n(r.output)),
        ("cache_read".into(), n(r.cache_read)),
        ("cache_write_5m".into(), n(r.cache_write_5m)),
        ("cache_write_1h".into(), n(r.cache_write_1h)),
        (
            "cost_usd".into(),
            if r.all_unpriced() {
                JsonValue::Null
            } else {
                JsonValue::Number(r.cost_usd)
            },
        ),
        ("unpriced_messages".into(), n(r.unpriced_messages)),
        (
            "unpriced_models".into(),
            JsonValue::Array(
                r.unpriced_models
                    .iter()
                    .cloned()
                    .map(JsonValue::Str)
                    .collect(),
            ),
        ),
    ])
}

pub fn render_json(
    rep: &Report,
    prices: &Prices,
    stats: &ScanStats,
    since: Option<&str>,
) -> String {
    let v = JsonValue::Object(vec![
        (
            "prices".into(),
            JsonValue::Object(vec![
                (
                    "valid_from".into(),
                    JsonValue::Str(prices.valid_from.clone()),
                ),
                (
                    "reviewed_until".into(),
                    JsonValue::Str(prices.reviewed_until.clone()),
                ),
                ("source".into(), JsonValue::Str(prices.source.clone())),
                (
                    "basis".into(),
                    JsonValue::Str("list price, not a subscription bill".into()),
                ),
            ]),
        ),
        ("by".into(), JsonValue::Str(rep.by.as_str().into())),
        (
            "since".into(),
            since.map_or(JsonValue::Null, |s| JsonValue::Str(s.into())),
        ),
        (
            "rows".into(),
            JsonValue::Array(rep.rows.iter().map(row_json).collect()),
        ),
        ("total".into(), row_json(&rep.total)),
        (
            "scan".into(),
            JsonValue::Object(vec![
                ("files".into(), n(stats.files)),
                ("lines".into(), n(stats.lines)),
                ("usage_lines".into(), n(stats.usage_lines)),
                ("messages".into(), n(stats.messages)),
                ("duplicates_skipped".into(), n(stats.duplicates_skipped)),
                ("synthetic_skipped".into(), n(stats.synthetic_skipped)),
                ("no_id".into(), n(stats.no_id)),
                ("malformed".into(), n(stats.malformed)),
            ]),
        ),
        (
            "warnings".into(),
            JsonValue::Array(
                warnings(rep, prices)
                    .into_iter()
                    .map(JsonValue::Str)
                    .collect(),
            ),
        ),
    ]);
    to_json_string(&v)
}

// ---------------------------------------------------------------- persisted roll-up

/// Days of history the daemon's persisted roll-up covers.
pub const ROLLUP_DAYS: i64 = 8;

/// Write `<data_dir>/cost-rollup.json`: by-day and by-model rows for the last [`ROLLUP_DAYS`] days.
/// Called on the daemon watcher's 5-minute report cadence. Written atomically (tmp + rename).
pub fn write_rollup(watch_dir: &Path, data_dir: &Path) -> Result<(), CostError> {
    let prices = Prices::builtin()?;
    let (y, m, d) = civil_from_days(today_utc() - ROLLUP_DAYS);
    let since = format!("{y:04}-{m:02}-{d:02}");
    let (recs, stats) = scan(
        watch_dir,
        &ScanOptions {
            since: Some(since.clone()),
            session: None,
        },
    )?;
    let day = aggregate(&recs, GroupBy::Day, &prices);
    let model = aggregate(&recs, GroupBy::Model, &prices);
    let v = JsonValue::Object(vec![
        (
            "by_day".into(),
            parse(&render_json(&day, &prices, &stats, Some(&since))).unwrap_or(JsonValue::Null),
        ),
        (
            "by_model".into(),
            parse(&render_json(&model, &prices, &stats, Some(&since))).unwrap_or(JsonValue::Null),
        ),
    ]);
    fs::create_dir_all(data_dir)
        .map_err(|e| CostError::Io(format!("mkdir {}: {e}", data_dir.display())))?;
    let tmp = data_dir.join("cost-rollup.json.tmp");
    let dst = data_dir.join("cost-rollup.json");
    fs::write(&tmp, to_json_string(&v))
        .and_then(|_| fs::rename(&tmp, &dst))
        .map_err(|e| CostError::Io(format!("write {}: {e}", dst.display())))
}

// ---------------------------------------------------------------- CLI entry

/// `ember-agent cost [--since D] [--session ID] [--by K] [--json] [--strict] [--root DIR] [--prices FILE]`.
/// Returns the process exit code: 0 ok, 3 when `--strict` and any message is UNPRICED.
pub fn run_cli(args: Vec<String>, default_root: PathBuf) -> Result<u8, CostError> {
    let (mut opts, mut by, mut json, mut strict) =
        (ScanOptions::default(), GroupBy::Model, false, false);
    let (mut root, mut price_file) = (default_root, None);
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut val = |f: &str| {
            it.next()
                .ok_or_else(|| CostError::BadArg(format!("{f} requires a value")))
        };
        match a.as_str() {
            "--since" => {
                let v = val("--since")?;
                parse_day(&v)?;
                opts.since = Some(v);
            }
            "--session" => opts.session = Some(val("--session")?),
            "--by" => by = GroupBy::parse(&val("--by")?)?,
            "--root" => root = PathBuf::from(val("--root")?),
            "--prices" => price_file = Some(PathBuf::from(val("--prices")?)),
            "--json" => json = true,
            "--strict" => strict = true,
            _ => return Err(CostError::BadArg(format!("unknown cost flag: {a}"))),
        }
    }
    let prices = match price_file {
        Some(p) => Prices::load(&p)?,
        None => Prices::builtin()?,
    };
    let t0 = std::time::Instant::now();
    let (recs, stats) = scan(&root, &opts)?;
    let rep = aggregate(&recs, by, &prices);
    let elapsed = t0.elapsed();
    if json {
        println!(
            "{}",
            render_json(&rep, &prices, &stats, opts.since.as_deref())
        );
    } else {
        print!("{}", render_table(&rep, &prices));
    }
    for w in warnings(&rep, &prices) {
        eprintln!("ember-agent: cost — {w}");
    }
    eprintln!(
        "ember-agent: cost — scanned files={} lines={} usage_lines={} messages={} duplicates_skipped={} synthetic_skipped={} no_id={} malformed={} in {:.2}s",
        stats.files, stats.lines, stats.usage_lines, stats.messages, stats.duplicates_skipped,
        stats.synthetic_skipped, stats.no_id, stats.malformed, elapsed.as_secs_f64()
    );
    Ok(if strict && rep.total.unpriced_messages > 0 {
        3
    } else {
        0
    })
}
