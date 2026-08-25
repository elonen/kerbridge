//! What is wrong right now, as it is written to disk.
//!
//! The record and its severity live here, and not beside the notifier that
//! writes them, because the problem directory is an integration surface: an
//! operator CLI and a monitoring agent read those files without sending
//! anything. A reader that had to link the notifier would take an HTTP and TLS
//! dependency tree to parse one JSON object.
//!
//! `kerbridge-notify` owns everything else about a problem -- when it is raised,
//! how often it repeats, when it clears.

use serde::{Deserialize, Serialize};

/// How loud an event is. Ordered, because `notify.min_severity` suppresses
/// everything below the configured level.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// The spellings `notify.min_severity` accepts, for the error that refuses
    /// anything else.
    pub const SPELLINGS: &'static str = "info, warning, error";

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "info" => Some(Self::Info),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// One condition, as it is written to disk. The body is authoritative for what
/// this is about -- the file name is derived from it and is only a name.
#[derive(Clone, Serialize, Deserialize)]
pub struct Problem {
    pub event: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subject: String,
    pub component: String,
    /// The severity it was *raised* at, kept so a recovery can be judged against
    /// the same `notify.min_severity` floor its event passed. Without this an
    /// operator who raises the floor to quiet things down would receive alarms
    /// and never the all-clears, which is the worst of both.
    pub severity: Severity,
    pub message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// Still true?
    pub open: bool,
    /// When it was first raised, so a recovery can say how long it lasted.
    pub since: u64,
    /// When delivery was last *attempted*, not last succeeded. A receiver that
    /// is down would otherwise be retried on every cycle, which is the retry
    /// storm one bounded attempt exists to avoid; the failure is logged locally
    /// either way. `None` when nothing has been attempted, which is a different
    /// thing from having been attempted at time zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_at: Option<u64>,
    /// The countdown step that attempt was for. Absent for a persisting event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub band: Option<i64>,
}

impl Problem {
    /// How long this has been true, coarsely: an operator reading a recovery
    /// wants "about two hours", not seven thousand seconds.
    pub fn lasted(&self, now: u64) -> String {
        let secs = now.saturating_sub(self.since);
        match secs {
            s if s < 90 => format!("{s}s"),
            s if s < 5_400 => format!("{}m", s / 60),
            s if s < 172_800 => format!("{}h", s / 3_600),
            s => format!("{}d", s / 86_400),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_from_quietest_to_loudest() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        for (raw, want) in
            [("info", Severity::Info), ("warning", Severity::Warning), ("error", Severity::Error)]
        {
            assert_eq!(Severity::parse(raw), Some(want));
            assert_eq!(want.as_str(), raw);
        }
        // Only the three documented spellings, for the reason `env::flag` gives:
        // a value nobody recognizes must not silently pick a level.
        for bad in ["INFO", "warn", "critical", ""] {
            assert_eq!(Severity::parse(bad), None, "{bad}");
        }
    }
}
