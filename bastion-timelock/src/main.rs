use anyhow::{Context, Result};
use bastion_common::crypto;
use bastion_common::paths;
use bastion_common::puzzle;
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rug::integer::Order;
use std::fs;
use std::path::Path;

#[derive(Parser)]
#[command(name = "bastion-timelock", about = "RSA time-lock puzzle engine")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize: generate RSA modulus, Ed25519 keypair, and pre-generate puzzles.
    Init {
        /// Number of puzzles to pre-generate.
        #[arg(long, default_value = "100")]
        count: u64,
        /// Time-lock difficulty: number of sequential squarings = 2^t_bits.
        #[arg(long, default_value = "25")]
        t_bits: u32,
    },
    /// Solve a puzzle (for testing or actual unlock flow).
    Solve {
        /// Puzzle ID to solve.
        #[arg(long)]
        id: u64,
    },
    /// List puzzle inventory status.
    Status,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { count, t_bits } => cmd_init(count, t_bits),
        Commands::Solve { id } => cmd_solve(id),
        Commands::Status => cmd_status(),
    }
}

fn cmd_init(count: u64, t_bits: u32) -> Result<()> {
    // Create directories
    fs::create_dir_all(paths::puzzle_dir()).context("failed to create puzzle directory")?;
    fs::create_dir_all(paths::data_path()).context("failed to create data directory")?;

    // Generate Ed25519 keypair
    println!("Generating Ed25519 signing keypair...");
    let (signing_key, verifying_key) = crypto::generate_ed25519_keypair();

    // Save public key
    fs::write(paths::pubkey_path(), verifying_key.as_bytes())
        .context("failed to write public key")?;
    println!("Public key saved to {}", paths::pubkey_path());

    // Generate RSA-2048 modulus
    println!("Generating RSA-2048 modulus (this takes a moment)...");
    let (n, p, q) = puzzle::generate_rsa_modulus();

    // Save modulus (public)
    let n_bytes = n.to_digits::<u8>(Order::Msf);
    fs::write(paths::rsa_modulus_path(), &n_bytes).context("failed to write RSA modulus")?;
    println!(
        "RSA modulus saved to {} ({} bits)",
        paths::rsa_modulus_path(),
        n.significant_bits()
    );

    // Pre-generate puzzles
    let t: u64 = 1u64 << t_bits;
    println!(
        "Pre-generating {} puzzles with T=2^{}={} squarings...",
        count, t_bits, t
    );

    let pb = ProgressBar::new(count);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40} {pos}/{len} puzzles")
            .unwrap(),
    );

    for id in 0..count {
        let gen = puzzle::generate_puzzle(id, &n, &p, &q, t);

        // Sign the puzzle
        let puzzle_json = serde_json::to_string_pretty(&gen.puzzle)?;
        let envelope = crypto::sign(&signing_key, puzzle_json.as_bytes());

        // Save puzzle
        let puzzle_path = format!("{}/puzzle_{:04}.json", paths::puzzle_dir(), id);
        fs::write(&puzzle_path, &puzzle_json).context("failed to write puzzle")?;

        // Save signature alongside
        let sig_path = format!("{}/puzzle_{:04}.sig", paths::puzzle_dir(), id);
        fs::write(&sig_path, &envelope.signature).context("failed to write puzzle signature")?;

        pb.inc(1);
    }
    pb.finish_with_message("done");

    // Destroy private key and factors
    println!("\nDestroying private signing key and RSA factors (p, q)...");
    // The signing_key, p, q go out of scope here and are dropped.
    // In production, we'd also want to memzero them, but Rust's drop is sufficient
    // since we never persist them.
    drop(signing_key);
    drop(p);
    drop(q);

    println!(
        "\nInitialization complete!\n  {} puzzles generated\n  Public key: {}\n  RSA modulus: {}\n  Private key: DESTROYED",
        count,
        paths::pubkey_path(),
        paths::rsa_modulus_path()
    );

    Ok(())
}

fn cmd_solve(id: u64) -> Result<()> {
    let puzzle_path = format!("{}/puzzle_{:04}.json", paths::puzzle_dir(), id);
    let data = fs::read_to_string(&puzzle_path).context("failed to read puzzle")?;
    let puz: puzzle::TimeLockPuzzle = serde_json::from_str(&data)?;

    if puz.consumed {
        anyhow::bail!("puzzle {} has already been consumed", id);
    }

    println!(
        "Solving puzzle {} ({} sequential squarings)...",
        id, puz.t
    );

    let pb = ProgressBar::new(puz.t);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40} {pos}/{len} squarings [{eta_precise} remaining]")
            .unwrap(),
    );

    let secret = puzzle::solve_puzzle(&puz, |current, total| {
        pb.set_position(current);
        if current == total {
            pb.finish_with_message("solved!");
        }
    })?;

    println!("Puzzle solved! Secret ({} bytes) recovered.", secret.len());
    println!("Secret (hex): {}", hex_encode(&secret));

    Ok(())
}

fn cmd_status() -> Result<()> {
    let puzzle_dir = paths::puzzle_dir();
    if !Path::new(&puzzle_dir).exists() {
        println!("Bastion not initialized. Run `bastion-timelock init` first.");
        return Ok(());
    }

    let puzzles = puzzle::load_puzzles(&puzzle_dir)?;
    let total = puzzles.len();
    let consumed = puzzles.iter().filter(|p| p.consumed).count();
    let available = total - consumed;

    println!("Puzzle Inventory:");
    println!("  Total:     {}", total);
    println!("  Available: {}", available);
    println!("  Consumed:  {}", consumed);

    if let Some(next) = puzzle::next_puzzle(&puzzles) {
        println!("  Next:      puzzle_{:04} (T={})", next.id, next.t);
    } else {
        println!("  WARNING: No puzzles available! Generate more with `bastion-timelock init`.");
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
