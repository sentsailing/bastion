use anyhow::{Context, Result};
use rug::integer::Order;
use rug::Integer;
use serde::{Deserialize, Serialize};

/// An RSA time-lock puzzle (Rivest-Shamir-Wagner construction).
///
/// To solve: compute x^(2^T) mod N by repeated squaring.
/// The solution reveals `secret` which was encrypted as: secret + x^(2^T) mod N.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeLockPuzzle {
    /// Unique puzzle ID.
    pub id: u64,
    /// RSA modulus N (big-endian bytes).
    pub n: Vec<u8>,
    /// Base value x (big-endian bytes).
    pub x: Vec<u8>,
    /// Number of squarings T.
    pub t: u64,
    /// Encrypted secret: secret + x^(2^T) mod N (big-endian bytes).
    pub encrypted_secret: Vec<u8>,
    /// SHA-256 hash of the plaintext secret (for verification).
    pub secret_hash: [u8; 32],
    /// Whether this puzzle has been consumed.
    pub consumed: bool,
}

/// Result of generating a puzzle (includes the secret for the generator).
pub struct PuzzleGenResult {
    pub puzzle: TimeLockPuzzle,
    pub secret: Vec<u8>,
}

/// Generate RSA-2048 modulus (p * q) and return (n, p, q).
pub fn generate_rsa_modulus() -> (Integer, Integer, Integer) {
    use rug::rand::RandState;
    let mut rng = RandState::new();
    // Seed from OS randomness
    let mut seed_bytes = [0u8; 32];
    getrandom::getrandom(&mut seed_bytes).expect("getrandom failed");
    let seed = Integer::from_digits(&seed_bytes, Order::Lsf);
    rng.seed(&seed);

    let p = Integer::from(Integer::random_bits(1024, &mut rng)).next_prime();
    let q = Integer::from(Integer::random_bits(1024, &mut rng)).next_prime();
    let n = Integer::from(&p * &q);
    (n, p, q)
}

/// Generate a time-lock puzzle.
///
/// With knowledge of p and q, we can compute x^(2^T) mod N efficiently
/// using Euler's totient: x^(2^T mod φ(N)) mod N.
pub fn generate_puzzle(
    id: u64,
    n: &Integer,
    p: &Integer,
    q: &Integer,
    t: u64,
) -> PuzzleGenResult {
    use sha2::{Digest, Sha256};

    // Random base x
    let mut rng_state = rug::rand::RandState::new();
    let mut seed_bytes = [0u8; 32];
    getrandom::getrandom(&mut seed_bytes).expect("getrandom failed");
    let seed = Integer::from_digits(&seed_bytes, Order::Lsf);
    rng_state.seed(&seed);
    let x = n.clone().random_below(&mut rng_state) + 1u32;

    // Compute φ(N) = (p-1)(q-1)
    let phi = Integer::from(p - 1u32) * Integer::from(q - 1u32);

    // Compute 2^T mod φ(N)
    let two = Integer::from(2u32);
    let exp = two.pow_mod(&Integer::from(t), &phi).unwrap();

    // Compute x^(2^T) mod N efficiently using the trapdoor
    let result = x.clone().pow_mod(&exp, n).unwrap();

    // Generate random secret
    let mut secret_bytes = [0u8; 32];
    getrandom::getrandom(&mut secret_bytes).expect("getrandom failed");
    let secret = Integer::from_digits(&secret_bytes, Order::Lsf);

    // Encrypt: encrypted = secret + result mod N
    let encrypted = Integer::from(&secret + &result) % n;

    // Hash the secret for verification
    let secret_raw = secret.to_digits::<u8>(Order::Msf);
    let mut hasher = Sha256::new();
    hasher.update(&secret_raw);
    let secret_hash: [u8; 32] = hasher.finalize().into();

    PuzzleGenResult {
        puzzle: TimeLockPuzzle {
            id,
            n: n.to_digits(Order::Msf),
            x: x.to_digits(Order::Msf),
            t,
            encrypted_secret: encrypted.to_digits(Order::Msf),
            secret_hash,
            consumed: false,
        },
        secret: secret_raw,
    }
}

/// Solve a time-lock puzzle by sequential squaring.
/// Returns the decrypted secret bytes.
///
/// `progress_callback` is called with (current_step, total_steps) periodically.
pub fn solve_puzzle<F>(puzzle: &TimeLockPuzzle, mut progress_callback: F) -> Result<Vec<u8>>
where
    F: FnMut(u64, u64),
{
    use sha2::{Digest, Sha256};

    let n = Integer::from_digits(&puzzle.n, Order::Msf);
    let mut val = Integer::from_digits(&puzzle.x, Order::Msf);
    let t = puzzle.t;

    // Sequential squaring: val = x^(2^T) mod N
    let report_interval = std::cmp::max(t / 1000, 1);
    for i in 0..t {
        val = val.clone().pow_mod(&Integer::from(2u32), &n).unwrap();
        if i % report_interval == 0 {
            progress_callback(i, t);
        }
    }
    progress_callback(t, t);

    // Decrypt: secret = encrypted - val mod N
    let encrypted = Integer::from_digits(&puzzle.encrypted_secret, Order::Msf);
    let secret = (encrypted - &val + &n) % &n;
    let secret_bytes = secret.to_digits::<u8>(Order::Msf);

    // Verify hash
    let mut hasher = Sha256::new();
    hasher.update(&secret_bytes);
    let hash: [u8; 32] = hasher.finalize().into();
    if hash != puzzle.secret_hash {
        anyhow::bail!("puzzle solution verification failed — hash mismatch");
    }

    Ok(secret_bytes)
}

/// Load puzzles from the puzzle directory.
pub fn load_puzzles(dir: &str) -> Result<Vec<TimeLockPuzzle>> {
    let mut puzzles = Vec::new();
    let entries = std::fs::read_dir(dir).context("failed to read puzzle directory")?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "json") {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read puzzle {}", path.display()))?;
            let puzzle: TimeLockPuzzle =
                serde_json::from_str(&data).with_context(|| format!("failed to parse puzzle {}", path.display()))?;
            puzzles.push(puzzle);
        }
    }
    puzzles.sort_by_key(|p| p.id);
    Ok(puzzles)
}

/// Get the next available (unconsumed) puzzle.
pub fn next_puzzle(puzzles: &[TimeLockPuzzle]) -> Option<&TimeLockPuzzle> {
    puzzles.iter().find(|p| !p.consumed)
}

/// Mark a puzzle as consumed and save back to disk.
pub fn consume_puzzle(dir: &str, puzzle_id: u64) -> Result<()> {
    let path = format!("{}/puzzle_{:04}.json", dir, puzzle_id);
    let data = std::fs::read_to_string(&path).context("failed to read puzzle file")?;
    let mut puzzle: TimeLockPuzzle = serde_json::from_str(&data)?;
    puzzle.consumed = true;
    let updated = serde_json::to_string_pretty(&puzzle)?;
    std::fs::write(&path, updated).context("failed to write puzzle file")?;
    Ok(())
}
