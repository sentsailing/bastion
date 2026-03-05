use anyhow::{Context, Result};
use bastion_common::paths;
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Persistent time oracle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronosState {
    /// Last known wall-clock time (Unix seconds).
    pub last_wall_secs: u64,
    /// Monotonic counter: increments each time we update state.
    pub monotonic_counter: u64,
    /// Last monotonic clock reading (nanos since arbitrary epoch) — for drift detection.
    pub last_mono_nanos: u64,
    /// Accumulated drift warnings.
    pub drift_warnings: u32,
}

impl Default for ChronosState {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            last_wall_secs: now,
            monotonic_counter: 0,
            last_mono_nanos: 0,
            drift_warnings: 0,
        }
    }
}

/// Time oracle that cross-checks multiple sources.
pub struct Chronos {
    state: ChronosState,
    mono_epoch: Instant,
    max_drift_secs: u64,
}

impl Chronos {
    pub fn new(max_drift_secs: u64) -> Result<Self> {
        let state = Self::load_state().unwrap_or_default();
        Ok(Self {
            state,
            mono_epoch: Instant::now(),
            max_drift_secs,
        })
    }

    /// Check if time appears consistent (not tampered).
    pub fn validate_time(&mut self) -> Result<bool> {
        let wall_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before epoch")?
            .as_secs();

        let mono_now = self.mono_epoch.elapsed().as_nanos() as u64;

        // Check 1: Wall clock should not go backward
        if wall_now < self.state.last_wall_secs {
            let delta = self.state.last_wall_secs - wall_now;
            log::error!(
                "CLOCK TAMPER: wall clock went backward by {} seconds",
                delta
            );
            self.state.drift_warnings += 1;
            self.save_state()?;
            return Ok(false);
        }

        // Check 2: Wall clock advance should roughly match monotonic advance
        if self.state.last_mono_nanos > 0 {
            let mono_delta_secs = (mono_now - self.state.last_mono_nanos) / 1_000_000_000;
            let wall_delta_secs = wall_now - self.state.last_wall_secs;

            let drift = if wall_delta_secs > mono_delta_secs {
                wall_delta_secs - mono_delta_secs
            } else {
                mono_delta_secs - wall_delta_secs
            };

            if drift > self.max_drift_secs {
                log::error!(
                    "CLOCK TAMPER: wall/monotonic drift of {} secs exceeds threshold {}",
                    drift,
                    self.max_drift_secs
                );
                self.state.drift_warnings += 1;
                self.save_state()?;
                return Ok(false);
            }
        }

        // Check 3: TSC-based sanity (x86_64)
        #[cfg(target_arch = "x86_64")]
        {
            if !self.tsc_sanity_check() {
                log::warn!("TSC sanity check failed");
            }
        }

        // Update state
        self.state.last_wall_secs = wall_now;
        self.state.last_mono_nanos = mono_now;
        self.state.monotonic_counter += 1;
        self.save_state()?;

        Ok(true)
    }

    /// Get current validated timestamp.
    pub fn now(&mut self) -> Result<u64> {
        if self.validate_time()? {
            Ok(self.state.last_wall_secs)
        } else {
            anyhow::bail!("time validation failed — possible clock tampering")
        }
    }

    /// TSC-based elapsed time sanity check.
    #[cfg(target_arch = "x86_64")]
    fn tsc_sanity_check(&self) -> bool {
        // Read TSC twice with a known sleep and check it advances reasonably
        let tsc1 = unsafe { core::arch::x86_64::_rdtsc() };
        std::thread::sleep(Duration::from_millis(10));
        let tsc2 = unsafe { core::arch::x86_64::_rdtsc() };

        // TSC should advance by at least ~10M cycles for 10ms on a >1GHz CPU
        let delta = tsc2.wrapping_sub(tsc1);
        delta > 1_000_000 // very conservative lower bound
    }

    fn load_state() -> Result<ChronosState> {
        let data = fs::read_to_string(paths::chronos_state())
            .context("failed to read chronos state")?;
        serde_json::from_str(&data).context("failed to parse chronos state")
    }

    fn save_state(&self) -> Result<()> {
        let data = serde_json::to_string_pretty(&self.state)?;
        fs::write(paths::chronos_state(), &data).context("failed to write chronos state")
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("validate") => {
            let mut chronos = Chronos::new(30)?;
            match chronos.validate_time()? {
                true => {
                    println!("Time validation: OK (t={})", chronos.state.last_wall_secs);
                    std::process::exit(0);
                }
                false => {
                    println!("Time validation: FAILED — possible tampering detected");
                    std::process::exit(1);
                }
            }
        }
        Some("daemon") => {
            println!("Chronos time oracle starting...");
            let mut chronos = Chronos::new(30)?;
            loop {
                match chronos.validate_time() {
                    Ok(true) => log::debug!("time check OK"),
                    Ok(false) => log::error!("TIME TAMPER DETECTED"),
                    Err(e) => log::error!("time check error: {}", e),
                }
                std::thread::sleep(Duration::from_secs(10));
            }
        }
        Some("status") => {
            match Chronos::load_state() {
                Ok(state) => {
                    println!("Chronos State:");
                    println!("  Last wall time:    {} ({})", state.last_wall_secs, format_time(state.last_wall_secs));
                    println!("  Monotonic counter: {}", state.monotonic_counter);
                    println!("  Drift warnings:    {}", state.drift_warnings);
                }
                Err(_) => println!("No chronos state found. Run `bastion-chronos daemon` first."),
            }
        }
        _ => {
            println!("Usage: bastion-chronos <validate|daemon|status>");
        }
    }

    Ok(())
}

fn format_time(secs: u64) -> String {
    // Simple UTC formatting without chrono dependency
    let d = UNIX_EPOCH + Duration::from_secs(secs);
    format!("{:?}", d)
}
