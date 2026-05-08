//! Hash-pinned file integrity watcher.
//!
//! Reads a manifest of `(path, sha256)` pairs and emits a
//! `frozen_file_modification` finding when a pinned file's content drifts
//! from its expected hash, when the file becomes unreadable, or when it
//! disappears.
//!
//! Designed for substrates where a fixed set of files must not change at
//! runtime — e.g. the Ember presence agent's `chmod 444` workspace
//! (`SOUL.md`, `IDENTITY.md`, `USER.md`, `AGENTS.md`, `TOOLS.md`,
//! `HEARTBEAT.md`, `STYLE.md`). It generalises to any caller that wants a
//! hash-pinned read-only manifest enforced.
//!
//! # Why this lives in agent-monitor
//!
//! Same observability point as the existing `watcher` (filesystem under the
//! agent's workspace), same intervention semantics (emit finding to the
//! shared findings log), same trust posture (zero-dep, in-process). It
//! does not extend agent-monitor across layers — it deepens the existing
//! workspace-watcher layer with a new rule. Per the suite-overview
//! discipline, "agent monitor will not grow into a network tool"; this is
//! not network, host-attestation, or persistence — it is the workspace
//! layer agent-monitor already owns.
//!
//! # Why findings, not events
//!
//! Integrity violations are not session-scoped — a frozen file can be
//! modified between sessions, during one, or while no agent is running.
//! Findings flow under the sentinel session id `__integrity__`, which the
//! findings store and CLI handle via the same `findings/<id>.jsonl`
//! convention. Downstream consumers (persistent, dashboards) can choose to
//! special-case the sentinel or treat it uniformly.
//!
//! # Performance
//!
//! Each poll: stat each pinned file (`O(n)`, n ≤ ~16 in practice). If size
//! and mtime are unchanged since the last successful hash, skip the read.
//! Every `FORCE_REHASH_EVERY_N` polls (~60 s at the 250 ms watcher tick),
//! re-hash unconditionally to defend against mtime-preserving tampers.

use crate::crypto::sha256::{hex_encode, Sha256};
use crate::detect::finding::{Finding, FindingScope};
use crate::json::JsonValue;
use crate::types::Severity;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Sentinel session id under which integrity findings are recorded.
pub const INTEGRITY_SESSION_ID: &str = "__integrity__";

/// Force a full rehash every N polls regardless of stat result. At the
/// daemon's 250 ms tick this corresponds to roughly once per minute, which
/// is the spec's stated integrity-check cadence (presence-agent §8.3).
const FORCE_REHASH_EVERY_N: u64 = 240;

/// One pinned-file entry from the manifest.
#[derive(Debug, Clone)]
pub struct PinnedFile {
    pub path: PathBuf,
    pub expected_sha256: String,
}

/// Parsed manifest. Loaded once at daemon start; reload requires a daemon
/// restart so an attacker cannot rotate the manifest in place.
#[derive(Debug, Clone, Default)]
pub struct Manifest {
    pub files: Vec<PinnedFile>,
}

impl Manifest {
    /// Parse a manifest from disk.
    ///
    /// Format:
    /// ```json
    /// {
    ///   "version": 1,
    ///   "files": [
    ///     {"path": "/path/to/SOUL.md", "sha256": "abc...64hex"},
    ///     ...
    ///   ]
    /// }
    /// ```
    ///
    /// `version` must be `1`. Unknown top-level keys are ignored
    /// (forward-compatible). Each entry must have both `path` and a
    /// 64-char lowercase-hex `sha256`.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("integrity: read {}: {e}", path.display()))?;
        let v = crate::json::parse(&content)
            .map_err(|e| format!("integrity: parse {}: {e}", path.display()))?;
        let obj = v
            .as_object()
            .ok_or_else(|| format!("integrity: {}: top-level must be object", path.display()))?;

        let mut version: Option<f64> = None;
        let mut files: Option<&[JsonValue]> = None;
        for (k, val) in obj {
            match k.as_str() {
                "version" => version = val.as_f64(),
                "files" => files = val.as_array(),
                _ => {}
            }
        }
        let version = version.ok_or_else(|| {
            format!(
                "integrity: {}: missing required `version` field",
                path.display()
            )
        })?;
        if (version - 1.0).abs() > f64::EPSILON {
            return Err(format!(
                "integrity: {}: unsupported manifest version {} (expected 1)",
                path.display(),
                version
            ));
        }
        let files = files.ok_or_else(|| {
            format!(
                "integrity: {}: missing required `files` array",
                path.display()
            )
        })?;

        let mut pinned = Vec::with_capacity(files.len());
        for entry in files {
            let entry_obj = entry.as_object().ok_or_else(|| {
                format!(
                    "integrity: {}: every files[] entry must be an object",
                    path.display()
                )
            })?;
            let mut p: Option<&str> = None;
            let mut s: Option<&str> = None;
            for (kk, vv) in entry_obj {
                match (kk.as_str(), vv) {
                    ("path", JsonValue::Str(v)) => p = Some(v.as_str()),
                    ("sha256", JsonValue::Str(v)) => s = Some(v.as_str()),
                    _ => {}
                }
            }
            let path_s = p.ok_or_else(|| {
                format!("integrity: {}: file entry missing `path`", path.display())
            })?;
            let sha = s.ok_or_else(|| {
                format!(
                    "integrity: {}: file entry for {} missing `sha256`",
                    path.display(),
                    path_s
                )
            })?;
            if !is_valid_sha256_hex(sha) {
                return Err(format!(
                    "integrity: {}: `sha256` for {} is not 64 lowercase hex chars",
                    path.display(),
                    path_s
                ));
            }
            pinned.push(PinnedFile {
                path: PathBuf::from(path_s),
                expected_sha256: sha.to_ascii_lowercase(),
            });
        }
        if pinned.is_empty() {
            return Err(format!(
                "integrity: {}: manifest contains zero files",
                path.display()
            ));
        }
        Ok(Manifest { files: pinned })
    }
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// In-memory observation cache.
///
/// `seen[path]` records the most recent successful hash check; if size and
/// mtime are unchanged since then we skip re-reading the file. This is a
/// performance optimisation, not a security boundary — the periodic forced
/// rehash (§ `FORCE_REHASH_EVERY_N`) is what catches a tamper that
/// preserves stat metadata.
#[derive(Debug, Clone, Default)]
pub struct IntegrityState {
    seen: HashMap<PathBuf, FileObs>,
    poll_count: u64,
}

#[derive(Debug, Clone, Default)]
struct FileObs {
    mtime_secs: i64,
    size: u64,
    last_hash_ok: bool,
    /// The actual hash that was last *reported* in a finding. Used to
    /// suppress duplicate firings while a file remains tampered: a stable
    /// mismatch produces one finding, not one per poll. A *different*
    /// actual hash reopens the firing path (new tamper). The empty string
    /// means "no finding has been reported yet for this path".
    last_reported_actual: String,
}

impl IntegrityState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run one integrity pass over the manifest. Returns the findings
    /// emitted by this pass; the caller is responsible for persisting
    /// them.
    pub fn check(&mut self, manifest: &Manifest) -> Vec<Finding> {
        self.poll_count = self.poll_count.wrapping_add(1);
        let force_rehash = self.poll_count % FORCE_REHASH_EVERY_N == 0;
        let mut findings = Vec::new();
        for pinned in &manifest.files {
            if let Some(f) = self.check_one(pinned, force_rehash) {
                findings.push(f);
            }
        }
        findings
    }

    fn check_one(&mut self, pinned: &PinnedFile, force_rehash: bool) -> Option<Finding> {
        let metadata = match fs::metadata(&pinned.path) {
            Ok(m) => m,
            Err(e) => {
                let prev = self.seen.remove(&pinned.path).unwrap_or_default();
                let already_reported_unreadable = prev.last_reported_actual == "<unreadable>";
                if already_reported_unreadable {
                    return None;
                }
                self.seen.insert(
                    pinned.path.clone(),
                    FileObs {
                        last_reported_actual: "<unreadable>".into(),
                        ..FileObs::default()
                    },
                );
                return Some(unreadable_finding(pinned, &format!("stat: {e}")));
            }
        };
        let mtime_secs = mtime_secs(&metadata);
        let size = metadata.len();
        let prev = self.seen.get(&pinned.path).cloned().unwrap_or_default();
        let stat_unchanged = prev.mtime_secs == mtime_secs && prev.size == size;
        if !force_rehash && stat_unchanged && prev.last_hash_ok {
            return None;
        }

        let actual = match hash_file(&pinned.path) {
            Ok(h) => h,
            Err(e) => {
                self.seen.remove(&pinned.path);
                return Some(unreadable_finding(pinned, &format!("read: {e}")));
            }
        };
        let ok = actual.eq_ignore_ascii_case(&pinned.expected_sha256);
        // Suppress repeated firings while the same tampered hash persists.
        let already_reported = !ok && prev.last_reported_actual == actual;
        let last_reported_actual = if ok {
            String::new()
        } else if already_reported {
            prev.last_reported_actual
        } else {
            actual.clone()
        };
        self.seen.insert(
            pinned.path.clone(),
            FileObs {
                mtime_secs,
                size,
                last_hash_ok: ok,
                last_reported_actual,
            },
        );
        match (ok, already_reported) {
            (true, _) => None,
            (false, true) => None,
            (false, false) => Some(mismatch_finding(pinned, &actual)),
        }
    }
}

fn mtime_secs(metadata: &fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex_encode(&h.finalize()))
}

fn mismatch_finding(pinned: &PinnedFile, actual: &str) -> Finding {
    Finding {
        finding_type: "frozen_file_modification".into(),
        scope: FindingScope::Static,
        severity: Severity::High,
        session_id: INTEGRITY_SESSION_ID.into(),
        event_id: None,
        tool: None,
        argument: Some(pinned.path.display().to_string()),
        matched_value: Some(actual.to_string()),
        pattern: Some(pinned.expected_sha256.clone()),
        trust_zone: None,
        rationale: format!(
            "pinned file {} hash mismatch (expected {}, got {})",
            pinned.path.display(),
            pinned.expected_sha256,
            actual
        ),
        score: Severity::High.weight(),
    }
}

fn unreadable_finding(pinned: &PinnedFile, why: &str) -> Finding {
    Finding {
        finding_type: "frozen_file_modification".into(),
        scope: FindingScope::Static,
        severity: Severity::High,
        session_id: INTEGRITY_SESSION_ID.into(),
        event_id: None,
        tool: None,
        argument: Some(pinned.path.display().to_string()),
        matched_value: None,
        pattern: Some(pinned.expected_sha256.clone()),
        trust_zone: None,
        rationale: format!("pinned file {} unreadable: {}", pinned.path.display(), why),
        score: Severity::High.weight(),
    }
}

/// Append a finding to the integrity findings log under `data_dir`.
/// Best-effort: a write failure is logged to stderr but never blocks the
/// integrity loop, mirroring the proxy's lossy-on-failure stance for
/// observability writes.
pub fn append_finding(data_dir: &Path, finding: &Finding) {
    let path = data_dir
        .join("findings")
        .join(format!("{INTEGRITY_SESSION_ID}.jsonl"));
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("integrity: mkdir {}: {e}", parent.display());
            return;
        }
    }
    match fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut f) => {
            use std::io::Write;
            if let Err(e) = f.write_all(finding.to_jsonl().as_bytes()) {
                eprintln!("integrity: write {}: {e}", path.display());
            }
        }
        Err(e) => eprintln!("integrity: open {}: {e}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_manifest(dir: &Path, manifest: &str) -> PathBuf {
        let p = dir.join("manifest.json");
        fs::write(&p, manifest).unwrap();
        p
    }

    fn sha_of(content: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(content);
        hex_encode(&h.finalize())
    }

    #[test]
    fn manifest_roundtrip_minimal() {
        let tmp = tempdir();
        let target = tmp.join("file.txt");
        fs::write(&target, b"hello").unwrap();
        let sha = sha_of(b"hello");
        let manifest_text = format!(
            "{{\"version\":1,\"files\":[{{\"path\":\"{}\",\"sha256\":\"{}\"}}]}}",
            target.display(),
            sha
        );
        let mp = write_manifest(&tmp, &manifest_text);
        let m = Manifest::load(&mp).unwrap();
        assert_eq!(m.files.len(), 1);
        assert_eq!(m.files[0].path, target);
        assert_eq!(m.files[0].expected_sha256, sha);
    }

    #[test]
    fn manifest_rejects_unsupported_version() {
        let tmp = tempdir();
        let mp = write_manifest(&tmp, "{\"version\":2,\"files\":[]}");
        let err = Manifest::load(&mp).unwrap_err();
        assert!(err.contains("unsupported manifest version"), "{err}");
    }

    #[test]
    fn manifest_rejects_empty_files() {
        let tmp = tempdir();
        let mp = write_manifest(&tmp, "{\"version\":1,\"files\":[]}");
        let err = Manifest::load(&mp).unwrap_err();
        assert!(err.contains("zero files"), "{err}");
    }

    #[test]
    fn manifest_rejects_short_sha() {
        let tmp = tempdir();
        let mp = write_manifest(
            &tmp,
            "{\"version\":1,\"files\":[{\"path\":\"/tmp/x\",\"sha256\":\"deadbeef\"}]}",
        );
        let err = Manifest::load(&mp).unwrap_err();
        assert!(err.contains("64 lowercase hex"), "{err}");
    }

    #[test]
    fn integrity_state_clean_file_emits_no_finding() {
        let tmp = tempdir();
        let target = tmp.join("clean.md");
        fs::write(&target, b"frozen content").unwrap();
        let manifest = Manifest {
            files: vec![PinnedFile {
                path: target,
                expected_sha256: sha_of(b"frozen content"),
            }],
        };
        let mut state = IntegrityState::new();
        let findings = state.check(&manifest);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn integrity_state_modified_file_fires_high() {
        let tmp = tempdir();
        let target = tmp.join("tampered.md");
        // Use clearly different lengths so the stat fast-path detects the
        // change even on filesystems with coarse (1 s) mtime resolution.
        fs::write(&target, b"original_baseline_content").unwrap();
        let manifest = Manifest {
            files: vec![PinnedFile {
                path: target.clone(),
                expected_sha256: sha_of(b"original_baseline_content"),
            }],
        };
        let mut state = IntegrityState::new();
        assert!(state.check(&manifest).is_empty());

        fs::write(&target, b"hijacked").unwrap();
        let findings = state.check(&manifest);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].finding_type, "frozen_file_modification");
        assert_eq!(findings[0].severity.as_str(), "high");
        assert_eq!(findings[0].session_id, INTEGRITY_SESSION_ID);
    }

    #[test]
    fn integrity_state_force_rehash_catches_size_preserving_tamper() {
        let tmp = tempdir();
        let target = tmp.join("size_preserving.md");
        fs::write(&target, b"AAAAAAAA").unwrap();
        let manifest = Manifest {
            files: vec![PinnedFile {
                path: target.clone(),
                expected_sha256: sha_of(b"AAAAAAAA"),
            }],
        };
        let mut state = IntegrityState::new();
        assert!(state.check(&manifest).is_empty());

        // Same size, same mtime second on coarse FS — the stat fast-path
        // would miss it. We bypass that path by directly invoking the
        // forced-rehash code path (poll_count multiple of N).
        fs::write(&target, b"BBBBBBBB").unwrap();
        // Roll forward to the next forced-rehash boundary.
        state.poll_count = FORCE_REHASH_EVERY_N - 1;
        let findings = state.check(&manifest);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].finding_type, "frozen_file_modification");
    }

    #[test]
    fn integrity_state_missing_file_fires() {
        let manifest = Manifest {
            files: vec![PinnedFile {
                path: PathBuf::from("/this/path/does/not/exist/SOUL.md"),
                expected_sha256: "0".repeat(64),
            }],
        };
        let mut state = IntegrityState::new();
        let findings = state.check(&manifest);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].rationale.contains("unreadable"));
    }

    /// Tiny helper: get a unique temp dir without pulling in `tempfile`.
    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid = std::process::id();
        let p = base.join(format!("ember-integrity-test-{pid}-{nanos}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

}
