//! BIP-39 24-word recovery phrase generation and parsing.

use bip39::{Language, Mnemonic};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;
use crate::mem::SecretKey;

/// Generate 256 bits of OS CSPRNG entropy for a vault recovery slot.
pub fn generate_recovery_entropy() -> SecretKey {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let key = SecretKey::new(bytes);
    bytes.zeroize();
    key
}

/// Format 32-byte recovery entropy as a 24-word English BIP-39 mnemonic.
pub fn entropy_to_mnemonic(entropy: &SecretKey) -> Result<Zeroizing<String>, CryptoError> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy.as_bytes())
        .map_err(|e| CryptoError::InvalidFormat(format!("recovery encoding failed: {e}")))?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

/// Parse and checksum-verify a 24-word BIP-39 phrase back into 32-byte entropy.
pub fn mnemonic_to_entropy(phrase: &str) -> Result<SecretKey, CryptoError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase.trim())
        .map_err(|e| CryptoError::InvalidFormat(format!("invalid recovery phrase: {e}")))?;
    let mut raw = mnemonic.to_entropy();
    if raw.len() != 32 {
        raw.zeroize();
        return Err(CryptoError::InvalidFormat(
            "recovery phrase must be 24 words (256-bit entropy)".into(),
        ));
    }
    let key = SecretKey::from_slice(&raw)
        .ok_or_else(|| CryptoError::InvalidFormat("unexpected entropy length".into()))?;
    raw.zeroize();
    Ok(key)
}
