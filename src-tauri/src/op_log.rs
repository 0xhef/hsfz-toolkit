//! Shared per-operation log buffer used by every feature command
//! that produces a user-visible artifact (calibration read, capture
//! save, proxy export, simulator flash export, clone-from-car).
//!
//! Each command creates an `OpLog` at entry, pushes a timestamped
//! line for every significant event, and stashes the final formatted
//! text in `AppState.last_op_log` before returning. The frontend
//! pulls it via `pull_last_op_log` and writes it as a sibling `.log`
//! file next to the artifact using the same `plugin-fs writeFile`
//! call the artifact itself rides on — so on Android the log lands
//! in the same SAF-granted URI without needing any extra permissions.

use std::time::Instant;

/// Maximum number of lines a single operation log may contain on disk.
/// A calibration read with zero retries writes ~130 lines; a capture
/// session ~40. This cap is deliberately generous so normal operations
/// are uncapped, and only pathologically long runs (e.g. a read that
/// retries every block) get pruned. When we exceed the cap we keep
/// the first and last windows and drop the middle with an elision
/// marker — the head has the prep/connect context, the tail has the
/// failure/summary, and the middle is repetitive block noise.
pub const MAX_LOG_LINES: usize = 2_000;
/// Number of head lines to keep when eliding. Prep + first failures.
pub const HEAD_KEEP: usize = 200;
/// Number of tail lines to keep when eliding. Final errors + summary.
pub const TAIL_KEEP: usize = 1_200;

/// Hard cap on the formatted text size written to disk, in bytes.
/// Belt-and-braces: even if a single line is pathologically long,
/// the final written file won't exceed this. ~512 KB keeps headroom
/// for a developer to tail the file on a phone without running the
/// device out of memory.
pub const MAX_LOG_BYTES: usize = 512 * 1024;

/// Per-operation log with millisecond-relative timestamps.
pub struct OpLog {
    started: Instant,
    lines: Vec<String>,
}

impl OpLog {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            lines: Vec::with_capacity(512),
        }
    }

    /// Append a timestamped line. Also mirrored to `log::info!` so
    /// desktop crash logs show the sequence of events if the process
    /// dies mid-operation.
    pub fn push(&mut self, msg: impl Into<String>) {
        let ms = self.started.elapsed().as_millis();
        let line = format!("[{:>7} ms] {}", ms, msg.into());
        log::info!("{}", line);
        self.lines.push(line);
    }

    /// Format the log as a single string with the given header and
    /// footer blocks sandwiching the timeline. Applies two-stage
    /// pruning to keep the on-disk size bounded:
    ///
    ///   1. Line-count prune: if the timeline exceeds `MAX_LOG_LINES`
    ///      we keep the first `HEAD_KEEP` and last `TAIL_KEEP` lines
    ///      and replace the middle with an elision marker showing
    ///      how many lines were dropped.
    ///   2. Byte-budget prune: the final string is then hard-capped
    ///      at `MAX_LOG_BYTES`, truncating at a line boundary if it
    ///      would otherwise exceed the cap. Belt-and-braces against
    ///      pathologically long individual lines.
    pub fn format(&self, header: &str, footer: &str) -> String {
        let total = self.lines.len();
        let mut out = String::with_capacity(header.len() + footer.len() + total * 80);
        out.push_str(header);
        if !header.ends_with('\n') {
            out.push('\n');
        }

        if total <= MAX_LOG_LINES {
            for line in &self.lines {
                out.push_str(line);
                out.push('\n');
            }
        } else {
            // Stage 1: line-count prune. Head + elision + tail.
            let elided = total - HEAD_KEEP - TAIL_KEEP;
            for line in &self.lines[..HEAD_KEEP] {
                out.push_str(line);
                out.push('\n');
            }
            out.push_str(&format!(
                "... [{} line(s) elided to keep the log within \
                 {} lines — tail follows] ...\n",
                elided, MAX_LOG_LINES
            ));
            for line in &self.lines[total - TAIL_KEEP..] {
                out.push_str(line);
                out.push('\n');
            }
        }

        out.push_str("------------------------------------------------\n");
        out.push_str(footer);
        if !footer.ends_with('\n') {
            out.push('\n');
        }

        // Stage 2: byte-budget prune. Truncate at the last newline
        // before the cap so we never cut a line mid-character, then
        // append an explicit truncation marker.
        if out.len() > MAX_LOG_BYTES {
            let cut = out[..MAX_LOG_BYTES]
                .rfind('\n')
                .unwrap_or(MAX_LOG_BYTES.saturating_sub(1));
            out.truncate(cut);
            out.push_str("\n... [log truncated to hard byte cap] ...\n");
        }

        out
    }
}

/// Build a standard operation-log header with the tool name, the
/// operation title, unix timestamp, and caller-provided detail lines.
pub fn header(operation: &str, details: &[(&str, String)]) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out = String::with_capacity(256 + details.len() * 64);
    out.push_str("BMSecResearch — ");
    out.push_str(operation);
    out.push_str(" Operation Log\n");
    out.push_str("================================================\n");
    out.push_str(&format!("Started (unix):   {now}\n"));
    for (k, v) in details {
        out.push_str(&format!("{:<17} {}\n", format!("{}:", k), v));
    }
    out.push_str("================================================\n");
    out
}

/// Stash the given log text in `AppState.last_op_log`. Best-effort:
/// a poisoned mutex just drops the log silently rather than cascading
/// into the caller's error path.
pub fn stash(state: &tauri::State<'_, crate::commands::AppState>, text: String) {
    if let Ok(mut lock) = state.last_op_log.lock() {
        *lock = Some(text);
    }
}
