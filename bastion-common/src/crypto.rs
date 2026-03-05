use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;

use crate::SignedEnvelope;

type HmacSha256 = Hmac<Sha256>;

/// Generate a new Ed25519 keypair.
pub fn generate_ed25519_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign data with Ed25519.
pub fn sign(signing_key: &SigningKey, data: &[u8]) -> SignedEnvelope {
    let signature = signing_key.sign(data);
    SignedEnvelope {
        data: data.to_vec(),
        signature: signature.to_bytes().to_vec(),
    }
}

/// Verify a signed envelope.
pub fn verify(verifying_key: &VerifyingKey, envelope: &SignedEnvelope) -> Result<()> {
    let sig_bytes: [u8; 64] = envelope
        .signature
        .as_slice()
        .try_into()
        .context("invalid signature length")?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(&envelope.data, &signature)
        .context("signature verification failed")
}

/// Load verifying key from bytes.
pub fn load_verifying_key(bytes: &[u8]) -> Result<VerifyingKey> {
    let key_bytes: [u8; 32] = bytes.try_into().context("invalid public key length")?;
    Ok(VerifyingKey::from_bytes(&key_bytes)?)
}

/// Compute HMAC-SHA256 challenge response.
pub fn hmac_challenge(psk: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(psk).expect("HMAC accepts any key length");
    mac.update(challenge);
    mac.finalize().into_bytes().to_vec()
}

/// Verify HMAC-SHA256 challenge response.
pub fn hmac_verify(psk: &[u8], challenge: &[u8], response: &[u8]) -> bool {
    let expected = hmac_challenge(psk, challenge);
    // Constant-time comparison
    if expected.len() != response.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(response.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
