//! Key derivation (Argon2id) and authenticated encryption (XChaCha20-Poly1305).
//!
//! The whole vault is a single AEAD blob. The KDF header travels in the clear
//! but is bound into the ciphertext as associated data, so an attacker cannot
//! downgrade the parameters without invalidating the tag.

use crate::error::{AppError, Result};
use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

pub type MasterKey = Zeroizing<[u8; KEY_LEN]>;

/// Defaults are the OWASP-recommended second-choice profile for Argon2id
/// (64 MiB / t=3 / p=4), which takes well under a second on desktop hardware.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            memory_kib: 65536,
            iterations: 3,
            parallelism: 4,
        }
    }
}

impl KdfParams {
    /// Reject absurd values from a tampered vault header before we try to
    /// allocate against them.
    fn validate(&self) -> Result<()> {
        if !(8..=1_048_576).contains(&self.memory_kib) {
            return Err(AppError::invalid("KDF 메모리 파라미터가 범위를 벗어났습니다."));
        }
        if !(1..=64).contains(&self.iterations) {
            return Err(AppError::invalid("KDF 반복 파라미터가 범위를 벗어났습니다."));
        }
        if !(1..=16).contains(&self.parallelism) {
            return Err(AppError::invalid("KDF 병렬도 파라미터가 범위를 벗어났습니다."));
        }
        Ok(())
    }
}

pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf)
        .map_err(|e| AppError::msg(format!("난수 생성에 실패했습니다: {e}")))?;
    Ok(buf)
}

pub fn random_salt() -> Result<Vec<u8>> {
    random_bytes(SALT_LEN)
}

pub fn random_nonce() -> Result<Vec<u8>> {
    random_bytes(NONCE_LEN)
}

pub fn derive_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<MasterKey> {
    params.validate()?;
    if salt.len() < 8 {
        return Err(AppError::invalid("솔트 길이가 너무 짧습니다."));
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| AppError::msg(format!("KDF 파라미터 오류: {e}")))?;

    let argon = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key: MasterKey = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| AppError::msg(format!("키 파생에 실패했습니다: {e}")))?;

    Ok(key)
}

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(AppError::invalid("논스 길이가 올바르지 않습니다."));
    }
    cipher(key)
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| AppError::msg("암호화에 실패했습니다."))
}

/// Returns `BadPassword` on tag mismatch: for a vault, a failed tag check is
/// indistinguishable from (and overwhelmingly likely to be) a wrong password.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return Err(AppError::invalid("논스 길이가 올바르지 않습니다."));
    }
    let plaintext = cipher(key)
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AppError::BadPassword)?;
    Ok(Zeroizing::new(plaintext))
}

/// Rough password strength signal for the setup screen. Deliberately simple:
/// length dominates, character variety is a secondary bonus.
pub fn password_strength(password: &str) -> u8 {
    let len = password.chars().count();
    if len == 0 {
        return 0;
    }
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_symbol = password.chars().any(|c| !c.is_alphanumeric());
    let variety = [has_lower, has_upper, has_digit, has_symbol]
        .iter()
        .filter(|b| **b)
        .count();

    let score = match len {
        0..=7 => 0,
        8..=11 => 1,
        12..=15 => 2,
        16..=19 => 3,
        _ => 4,
    } + match variety {
        0..=1 => 0,
        2..=3 => 1,
        _ => 2,
    };

    score.min(4) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        KdfParams {
            memory_kib: 512,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn derive_is_deterministic_and_password_sensitive() {
        let salt = vec![7u8; SALT_LEN];
        let a = derive_key("correct horse", &salt, &fast_params()).unwrap();
        let b = derive_key("correct horse", &salt, &fast_params()).unwrap();
        let c = derive_key("correct horsf", &salt, &fast_params()).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
        assert_ne!(a.as_ref(), c.as_ref());
    }

    #[test]
    fn derive_is_salt_sensitive() {
        let a = derive_key("pw", &[1u8; SALT_LEN], &fast_params()).unwrap();
        let b = derive_key("pw", &[2u8; SALT_LEN], &fast_params()).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [3u8; KEY_LEN];
        let nonce = random_nonce().unwrap();
        let aad = b"header";
        let ct = encrypt(&key, &nonce, b"top secret", aad).unwrap();
        let pt = decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt.as_slice(), b"top secret");
    }

    #[test]
    fn tampered_aad_or_ciphertext_fails() {
        let key = [3u8; KEY_LEN];
        let nonce = random_nonce().unwrap();
        let mut ct = encrypt(&key, &nonce, b"top secret", b"header").unwrap();

        assert!(decrypt(&key, &nonce, &ct, b"HEADER").is_err());

        ct[0] ^= 0xFF;
        assert!(decrypt(&key, &nonce, &ct, b"header").is_err());
    }

    #[test]
    fn wrong_key_reports_bad_password() {
        let nonce = random_nonce().unwrap();
        let ct = encrypt(&[3u8; KEY_LEN], &nonce, b"x", b"").unwrap();
        let err = decrypt(&[4u8; KEY_LEN], &nonce, &ct, b"").unwrap_err();
        assert!(matches!(err, AppError::BadPassword));
    }

    #[test]
    fn rejects_out_of_range_kdf_params() {
        let bad = KdfParams {
            memory_kib: 4,
            iterations: 1,
            parallelism: 1,
        };
        assert!(derive_key("pw", &[0u8; SALT_LEN], &bad).is_err());
    }

    #[test]
    fn random_bytes_are_not_constant() {
        let a = random_bytes(32).unwrap();
        let b = random_bytes(32).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn strength_increases_with_length_and_variety() {
        assert_eq!(password_strength(""), 0);
        assert_eq!(password_strength("short"), 0);
        assert!(password_strength("correct horse battery staple") >= 3);
        assert!(password_strength("Tr0ub4dor&3xyz!") > password_strength("aaaaaaaaaaaaaaa"));
    }
}
