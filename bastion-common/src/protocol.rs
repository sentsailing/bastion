use serde::{Deserialize, Serialize};

use crate::WatchdogRole;

/// Messages exchanged between watchdog processes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WatchdogMessage {
    /// Challenge: prove you know the PSK.
    Challenge { from: WatchdogRole, nonce: Vec<u8> },
    /// Response to a challenge.
    ChallengeResponse { from: WatchdogRole, mac: Vec<u8> },
    /// Heartbeat: I'm alive, here's my state.
    Heartbeat {
        from: WatchdogRole,
        timestamp_secs: u64,
    },
    /// Tamper alert: something was modified.
    TamperAlert {
        from: WatchdogRole,
        path: String,
        detail: String,
    },
    /// Request to respawn a dead peer.
    RespawnRequest {
        from: WatchdogRole,
        target: WatchdogRole,
    },
}

/// Messages between CLI and the watchdog ring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CliMessage {
    /// Request to apply a config change (includes puzzle solution proof).
    ConfigChangeRequest {
        puzzle_id: u64,
        solution: Vec<u8>,
        new_rules: Vec<String>,
    },
    /// Response from watchdog about config change.
    ConfigChangeResponse { success: bool, message: String },
    /// Status query.
    StatusRequest,
    /// Status response.
    StatusResponse {
        watchdogs_alive: Vec<WatchdogRole>,
        puzzles_remaining: u64,
        last_tamper_event: Option<String>,
        lockdown_active: bool,
    },
}
