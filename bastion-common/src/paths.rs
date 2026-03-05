/// Canonical paths for Bastion installation.
/// All paths can be overridden via BASTION_DATA_DIR env var for testing.

use std::sync::OnceLock;

static DATA_DIR: OnceLock<String> = OnceLock::new();

fn data_dir() -> &'static str {
    DATA_DIR.get_or_init(|| {
        std::env::var("BASTION_DATA_DIR").unwrap_or_else(|_| "/var/lib/bastion".to_string())
    })
}

pub fn bastion_dir() -> String {
    std::env::var("BASTION_BIN_DIR").unwrap_or_else(|_| "/usr/lib/bastion".to_string())
}

pub fn puzzle_dir() -> String {
    format!("{}/puzzles", data_dir())
}

pub fn config_path() -> String {
    format!("{}/config.signed", data_dir())
}

pub fn pubkey_path() -> String {
    format!("{}/pubkey.bin", data_dir())
}

pub fn chronos_state() -> String {
    format!("{}/chronos.state", data_dir())
}

pub fn audit_log() -> String {
    format!("{}/audit.log", data_dir())
}

pub fn rsa_modulus_path() -> String {
    format!("{}/rsa_modulus.bin", data_dir())
}

pub fn data_path() -> String {
    data_dir().to_string()
}

pub fn puzzle_hashes_path() -> String {
    format!("{}/puzzle_hashes.json", data_dir())
}

pub fn integrity_manifest_path() -> String {
    format!("{}/integrity.manifest", data_dir())
}

pub const PLUCKY_BASE: &str = "/var/opt/pluck";
pub const PLUCKY_RULES: &str = "/var/opt/pluck/rules";

pub const NFTABLES_LOCKDOWN: &str = "/etc/nftables-bastion-lockdown.conf";
