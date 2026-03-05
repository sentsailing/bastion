use anyhow::{Context, Result};
use bastion_common::crypto;
use bastion_common::paths;
use bastion_common::puzzle;
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

#[derive(Parser)]
#[command(
    name = "bastion",
    about = "Bastion: tamper-resistant content filter with time-lock puzzles"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Unlock: solve a time-lock puzzle to make a config change.
    Unlock {
        /// Rule to add (e.g., "allow youtube.com").
        #[arg(long)]
        rule: String,
    },
    /// Remove a rule (requires solving a puzzle).
    Block {
        /// Domain or pattern to block.
        #[arg(long)]
        domain: String,
    },
    /// Show system status.
    Status,
    /// Initialize Bastion (generates keys, puzzles, configs).
    Init {
        /// Number of puzzles to pre-generate.
        #[arg(long, default_value = "100")]
        puzzle_count: u64,
        /// Time-lock difficulty: squarings = 2^t_bits.
        #[arg(long, default_value = "25")]
        t_bits: u32,
        /// Watchdog PSK (hex). Auto-generated if not provided.
        #[arg(long)]
        psk: Option<String>,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Unlock { rule } => cmd_unlock(&rule),
        Commands::Block { domain } => cmd_block(&domain),
        Commands::Status => cmd_status(),
        Commands::Init {
            puzzle_count,
            t_bits,
            psk,
        } => cmd_init(puzzle_count, t_bits, psk),
    }
}

fn cmd_init(puzzle_count: u64, t_bits: u32, psk: Option<String>) -> Result<()> {
    println!("=== Bastion Initialization ===\n");

    // Create directories
    for dir in &[
        paths::bastion_dir(),
        paths::data_path(),
        paths::puzzle_dir(),
    ] {
        fs::create_dir_all(dir)
            .with_context(|| format!("failed to create directory: {}", dir))?;
    }

    // Generate or use provided PSK
    let psk_hex = match psk {
        Some(p) => p,
        None => {
            let mut psk_bytes = [0u8; 32];
            getrandom::getrandom(&mut psk_bytes)?;
            psk_bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }
    };

    // Generate Ed25519 keypair
    println!("[1/4] Generating Ed25519 signing keypair...");
    let (signing_key, verifying_key) = crypto::generate_ed25519_keypair();
    fs::write(paths::pubkey_path(), verifying_key.as_bytes())?;

    // Generate RSA modulus
    println!("[2/4] Generating RSA-2048 modulus...");
    let (n, p, q) = puzzle::generate_rsa_modulus();
    let n_bytes = rug::integer::Order::Msf;
    let modulus_bytes = n.to_digits::<u8>(n_bytes);
    fs::write(paths::rsa_modulus_path(), &modulus_bytes)?;
    println!("  RSA modulus: {} bits", n.significant_bits());

    // Pre-generate puzzles
    let t: u64 = 1u64 << t_bits;
    println!(
        "[3/4] Pre-generating {} puzzles (T=2^{}={} squarings)...",
        puzzle_count, t_bits, t
    );

    let pb = ProgressBar::new(puzzle_count);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40} {pos}/{len} puzzles")
            .unwrap(),
    );

    // Collect SHA-256(secret) for each puzzle for cryptographic verification
    let mut puzzle_hashes: HashMap<String, String> = HashMap::new();

    for id in 0..puzzle_count {
        let gen = puzzle::generate_puzzle(id, &n, &p, &q, t);
        let puzzle_json = serde_json::to_string_pretty(&gen.puzzle)?;
        let puzzle_path = format!("{}/puzzle_{:04}.json", paths::puzzle_dir(), id);
        fs::write(&puzzle_path, &puzzle_json)?;

        // Sign and save signature
        let envelope = crypto::sign(&signing_key, puzzle_json.as_bytes());
        let sig_path = format!("{}/puzzle_{:04}.sig", paths::puzzle_dir(), id);
        fs::write(&sig_path, &envelope.signature)?;

        // Store hash of the secret (== puzzle.secret_hash, already SHA-256)
        // This lets uninstall.sh verify tokens without the bastion binary
        let secret_hash_hex: String = gen.puzzle.secret_hash.iter().map(|b| format!("{:02x}", b)).collect();
        puzzle_hashes.insert(format!("puzzle_{:04}", id), secret_hash_hex);

        pb.inc(1);
    }
    pb.finish_with_message("done");

    // Write puzzle hashes for cryptographic uninstall verification
    let hashes_json = serde_json::to_string_pretty(&puzzle_hashes)?;
    fs::write(paths::puzzle_hashes_path(), &hashes_json)?;
    println!("  Puzzle hashes: {}", paths::puzzle_hashes_path());

    // Write and sign config
    println!("[4/4] Writing configuration...");
    let config = bastion_common::BastionConfig {
        t_bits,
        watchdog_psk: psk_hex,
        watched_paths: default_watched_paths(),
        max_clock_drift_secs: 30,
    };
    let config_json = serde_json::to_string_pretty(&config)?;
    let config_envelope = crypto::sign(&signing_key, config_json.as_bytes());
    // Save config with signature
    let config_with_sig = serde_json::to_string_pretty(&serde_json::json!({
        "config": config,
        "signature": hex_encode(&config_envelope.signature),
    }))?;
    fs::write(paths::config_path(), &config_with_sig)?;

    // Destroy secrets
    drop(signing_key);
    drop(p);
    drop(q);

    println!("\n=== Initialization Complete ===");
    println!("  Puzzles:    {} generated in {}", puzzle_count, paths::puzzle_dir());
    println!("  Public key: {}", paths::pubkey_path());
    println!("  Config:     {}", paths::config_path());
    println!("  Private key: DESTROYED");
    println!("\nNext steps:");
    println!("  1. sudo cp target/release/bastion-cerberus {}/", paths::bastion_dir());
    println!("  2. sudo systemctl enable --now bastion-alpha bastion-beta bastion-gamma");

    Ok(())
}

fn cmd_unlock(rule: &str) -> Result<()> {
    println!("=== Bastion Unlock ===\n");
    println!("Requested rule: {}\n", rule);

    // Load puzzle inventory
    let puzzles = puzzle::load_puzzles(&paths::puzzle_dir())?;
    let puz = puzzle::next_puzzle(&puzzles)
        .context("no puzzles available — system is permanently locked")?;

    println!(
        "Puzzle #{}: {} sequential squarings required.",
        puz.id, puz.t
    );
    println!("This will take approximately {} to solve.\n", estimate_time(puz.t));
    println!("Starting puzzle solve...\n");

    let pb = ProgressBar::new(puz.t);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:50.cyan/blue} {percent}% [{eta_precise} remaining]")
            .unwrap(),
    );

    let secret = puzzle::solve_puzzle(puz, |current, total| {
        pb.set_position(current);
        if current == total {
            pb.finish_with_message("SOLVED");
        }
    })?;

    println!("\nPuzzle solved! Applying rule change...");

    // For uninstall-authorized, output the cryptographic token so the
    // uninstall script can verify it against pre-stored puzzle hashes.
    // A fake bastion binary can't produce a token whose SHA-256 matches.
    if rule == "uninstall-authorized" {
        let hex: String = secret.iter().map(|b| format!("{:02x}", b)).collect();
        println!("BASTION_UNINSTALL_TOKEN={}", hex);
    }

    // Mark puzzle as consumed
    puzzle::consume_puzzle(&paths::puzzle_dir(), puz.id)?;

    // "uninstall-authorized" is a signal for the uninstall script, not a Plucky rule
    if rule != "uninstall-authorized" {
        apply_plucky_rule(rule)?;
        println!("Rule applied successfully: {}", rule);
    } else {
        println!("Uninstall authorization granted.");
    }
    println!(
        "Puzzles remaining: {}",
        puzzles.iter().filter(|p| !p.consumed && p.id != puz.id).count()
    );

    Ok(())
}

fn cmd_block(domain: &str) -> Result<()> {
    println!("Adding block rule for: {}", domain);

    // Blocking doesn't require a puzzle — only unblocking does
    let rule_line = format!("block {}", domain);
    append_plucky_rule(&rule_line)?;

    println!("Blocked: {}", domain);
    Ok(())
}

fn cmd_status() -> Result<()> {
    println!("=== Bastion Status ===\n");

    // Puzzle inventory
    if Path::new(&paths::puzzle_dir()).exists() {
        let puzzles = puzzle::load_puzzles(&paths::puzzle_dir())?;
        let total = puzzles.len();
        let consumed = puzzles.iter().filter(|p| p.consumed).count();
        println!("Puzzles:      {}/{} available", total - consumed, total);
        if let Some(next) = puzzle::next_puzzle(&puzzles) {
            println!("Next puzzle:  #{} (T={})", next.id, next.t);
        }
    } else {
        println!("Puzzles:      NOT INITIALIZED");
    }

    // Watchdog status
    println!("\nWatchdogs:");
    for role in bastion_common::WatchdogRole::all() {
        let service = format!("bastion-{}.service", role);
        let status = Command::new("systemctl")
            .args(["is-active", &service])
            .output();
        match status {
            Ok(out) => {
                let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
                println!("  {}: {}", role, state);
            }
            Err(_) => println!("  {}: unknown", role),
        }
    }

    // Lockdown status
    if Path::new(paths::NFTABLES_LOCKDOWN).exists() {
        println!("\nLOCKDOWN: ACTIVE");
    } else {
        println!("\nLockdown: inactive");
    }

    // Audit log tail
    if Path::new(&paths::audit_log()).exists() {
        if let Ok(log) = fs::read_to_string(paths::audit_log()) {
            let lines: Vec<&str> = log.lines().collect();
            let last = lines.len().saturating_sub(5);
            if !lines[last..].is_empty() {
                println!("\nRecent audit events:");
                for line in &lines[last..] {
                    println!("  {}", line);
                }
            }
        }
    }

    Ok(())
}

fn apply_plucky_rule(rule: &str) -> Result<()> {
    // Parse rule format: "allow <domain>" or "remove <pattern>"
    let parts: Vec<&str> = rule.splitn(2, ' ').collect();
    match parts.get(0).map(|s| *s) {
        Some("allow") => {
            let domain = parts.get(1).context("missing domain")?;
            // Plucky uses "allow" rules — add to rules file
            let rule_line = format!("allow {}", domain);
            append_plucky_rule(&rule_line)?;
            reload_plucky()?;
        }
        Some("remove") => {
            let pattern = parts.get(1).context("missing pattern")?;
            remove_plucky_rule(pattern)?;
            reload_plucky()?;
        }
        _ => {
            // Raw rule passthrough
            append_plucky_rule(rule)?;
            reload_plucky()?;
        }
    }
    Ok(())
}

fn append_plucky_rule(rule: &str) -> Result<()> {
    let rules_path = paths::PLUCKY_RULES;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(rules_path)
        .context("failed to open plucky rules file")?;
    writeln!(f, "{}", rule)?;
    Ok(())
}

fn remove_plucky_rule(pattern: &str) -> Result<()> {
    let rules_path = paths::PLUCKY_RULES;
    let content = fs::read_to_string(rules_path).unwrap_or_default();
    let filtered: Vec<&str> = content
        .lines()
        .filter(|line| !line.contains(pattern))
        .collect();
    fs::write(rules_path, filtered.join("\n") + "\n")?;
    Ok(())
}

fn reload_plucky() -> Result<()> {
    // Plucky reloads on SIGHUP to boss process
    let _ = Command::new("pkill")
        .args(["-HUP", "boss"])
        .status();
    Ok(())
}

fn default_watched_paths() -> Vec<String> {
    vec![
        format!("{}/bastion-cerberus", paths::bastion_dir()),
        format!("{}/bastion-chronos", paths::bastion_dir()),
        format!("{}/bastion-timelock", paths::bastion_dir()),
        paths::config_path(),
        paths::pubkey_path(),
        // Plucky paths
        "/opt/pluck".to_string(),
        "/usr/lib/x86_64-linux-gnu/pluckeye.so".to_string(),
        "/etc/ld.so.preload".to_string(),
    ]
}

fn estimate_time(t: u64) -> String {
    // Rough estimate: ~30M squarings/sec on modern CPU
    let secs = t / 30_000_000;
    if secs < 60 {
        format!("~{} seconds", secs.max(1))
    } else if secs < 3600 {
        format!("~{} minutes", secs / 60)
    } else {
        format!("~{:.1} hours", secs as f64 / 3600.0)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
