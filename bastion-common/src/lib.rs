pub mod crypto;
pub mod protocol;
pub mod paths;
pub mod puzzle;

use serde::{Deserialize, Serialize};

/// Bastion configuration, signed at install time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BastionConfig {
    /// Time-lock difficulty parameter T (number of squarings = 2^t_bits).
    pub t_bits: u32,
    /// Pre-shared key for watchdog mutual authentication (hex-encoded).
    pub watchdog_psk: String,
    /// Paths to monitor for integrity.
    pub watched_paths: Vec<String>,
    /// Maximum allowed clock drift in seconds before lockdown.
    pub max_clock_drift_secs: u64,
}

/// A signed envelope wrapping arbitrary data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Watchdog identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WatchdogRole {
    Alpha,
    Beta,
    Gamma,
}

impl WatchdogRole {
    pub fn socket_name(&self) -> &'static str {
        match self {
            WatchdogRole::Alpha => "bastion-alpha",
            WatchdogRole::Beta => "bastion-beta",
            WatchdogRole::Gamma => "bastion-gamma",
        }
    }

    pub fn all() -> &'static [WatchdogRole] {
        &[WatchdogRole::Alpha, WatchdogRole::Beta, WatchdogRole::Gamma]
    }

    pub fn peers(&self) -> Vec<WatchdogRole> {
        WatchdogRole::all()
            .iter()
            .copied()
            .filter(|r| r != self)
            .collect()
    }

    pub fn from_arg(s: &str) -> Option<WatchdogRole> {
        match s {
            "alpha" => Some(WatchdogRole::Alpha),
            "beta" => Some(WatchdogRole::Beta),
            "gamma" => Some(WatchdogRole::Gamma),
            _ => None,
        }
    }
}

impl std::fmt::Display for WatchdogRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatchdogRole::Alpha => write!(f, "alpha"),
            WatchdogRole::Beta => write!(f, "beta"),
            WatchdogRole::Gamma => write!(f, "gamma"),
        }
    }
}
