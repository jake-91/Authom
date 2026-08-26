//! RFC 4226 (HOTP) / RFC 6238 (TOTP) implementation plus the Steam Guard variant.

use crate::error::{AppError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            other => Err(AppError::invalid(format!(
                "지원하지 않는 알고리즘입니다: {other}"
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtpKind {
    #[default]
    Totp,
    Hotp,
    /// Steam Guard: five characters from a custom alphabet, 30s period, SHA1.
    Steam,
}

impl OtpKind {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "totp" => Ok(OtpKind::Totp),
            "hotp" => Ok(OtpKind::Hotp),
            "steam" => Ok(OtpKind::Steam),
            other => Err(AppError::invalid(format!("알 수 없는 OTP 종류: {other}"))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            OtpKind::Totp => "totp",
            OtpKind::Hotp => "hotp",
            OtpKind::Steam => "steam",
        }
    }

    pub fn is_time_based(&self) -> bool {
        matches!(self, OtpKind::Totp | OtpKind::Steam)
    }
}

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

/// Decode RFC 4648 base32. Padding, whitespace, dashes and lowercase are all
/// tolerated because real-world secrets get pasted in every imaginable shape.
pub fn base32_decode(input: &str) -> Result<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8 + 1);

    for ch in input.chars() {
        if ch.is_whitespace() || ch == '=' || ch == '-' || ch == '_' {
            continue;
        }
        let upper = ch.to_ascii_uppercase();
        let idx: u32 = match upper {
            'A'..='Z' => upper as u32 - 'A' as u32,
            '2'..='7' => upper as u32 - '2' as u32 + 26,
            _ => {
                return Err(AppError::invalid(format!(
                    "시크릿에 base32가 아닌 문자가 있습니다: '{ch}'"
                )))
            }
        };
        value = (value << 5) | idx;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((value >> bits) & 0xFF) as u8);
        }
    }

    if out.is_empty() {
        return Err(AppError::invalid("시크릿이 비어 있습니다."));
    }
    Ok(out)
}

pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    for &byte in data {
        value = (value << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((value >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((value << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

fn hmac_digest(algorithm: Algorithm, key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    macro_rules! run {
        ($hash:ty) => {{
            let mut mac = <Hmac<$hash> as Mac>::new_from_slice(key)
                .map_err(|_| AppError::invalid("시크릿 키 길이가 올바르지 않습니다."))?;
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }};
    }

    Ok(match algorithm {
        Algorithm::Sha1 => run!(Sha1),
        Algorithm::Sha256 => run!(Sha256),
        Algorithm::Sha512 => run!(Sha512),
    })
}

/// RFC 4226 dynamic truncation, shared by every variant.
fn truncate(digest: &[u8]) -> u32 {
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    ((digest[offset] & 0x7f) as u32) << 24
        | (digest[offset + 1] as u32) << 16
        | (digest[offset + 2] as u32) << 8
        | (digest[offset + 3] as u32)
}

/// HOTP for an explicit counter. `digits` is clamped to 6..=9 because the
/// 31-bit truncated value cannot fill more decimal places meaningfully.
pub fn hotp(key: &[u8], counter: u64, algorithm: Algorithm, digits: u8) -> Result<String> {
    let digits = digits.clamp(6, 9) as u32;
    let digest = hmac_digest(algorithm, key, &counter.to_be_bytes())?;
    let code = truncate(&digest) % 10u32.pow(digits);
    Ok(format!("{:0width$}", code, width = digits as usize))
}

pub fn steam(key: &[u8], counter: u64) -> Result<String> {
    let digest = hmac_digest(Algorithm::Sha1, key, &counter.to_be_bytes())?;
    let mut value = truncate(&digest) as u64;
    let mut out = String::with_capacity(5);
    for _ in 0..5 {
        out.push(STEAM_ALPHABET[(value % STEAM_ALPHABET.len() as u64) as usize] as char);
        value /= STEAM_ALPHABET.len() as u64;
    }
    Ok(out)
}

/// The time step index for a given unix timestamp.
pub fn time_counter(unix_seconds: i64, period: u32) -> u64 {
    let period = period.max(1) as i64;
    unix_seconds.div_euclid(period).max(0) as u64
}

/// Seconds left before the current time step rolls over.
pub fn seconds_remaining(unix_seconds: i64, period: u32) -> u32 {
    let period = period.max(1) as i64;
    (period - unix_seconds.rem_euclid(period)) as u32
}

/// Generate a code for a time-based entry at `unix_seconds`.
pub fn code_at(
    key: &[u8],
    unix_seconds: i64,
    period: u32,
    algorithm: Algorithm,
    digits: u8,
    kind: OtpKind,
) -> Result<String> {
    let counter = time_counter(unix_seconds, period);
    match kind {
        OtpKind::Steam => steam(key, counter),
        _ => hotp(key, counter, algorithm, digits),
    }
}

/// A decoded secret that wipes itself when dropped.
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    pub fn from_base32(secret: &str) -> Result<Self> {
        Ok(SecretKey(base32_decode(secret)?))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    /// RFC 4226 Appendix D.
    #[test]
    fn rfc4226_hotp_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            let got = hotp(SEED_SHA1, counter as u64, Algorithm::Sha1, 6).unwrap();
            assert_eq!(&got, want, "counter {counter}");
        }
    }

    /// RFC 6238 Appendix B.
    #[test]
    fn rfc6238_totp_vectors() {
        let cases: [(i64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];

        for (t, sha1, sha256, sha512) in cases {
            assert_eq!(
                code_at(SEED_SHA1, t, 30, Algorithm::Sha1, 8, OtpKind::Totp).unwrap(),
                sha1,
                "SHA1 at T={t}"
            );
            assert_eq!(
                code_at(SEED_SHA256, t, 30, Algorithm::Sha256, 8, OtpKind::Totp).unwrap(),
                sha256,
                "SHA256 at T={t}"
            );
            assert_eq!(
                code_at(SEED_SHA512, t, 30, Algorithm::Sha512, 8, OtpKind::Totp).unwrap(),
                sha512,
                "SHA512 at T={t}"
            );
        }
    }

    #[test]
    fn base32_roundtrip_and_tolerance() {
        let raw = b"Hello!\xDE\xAD\xBE\xEF";
        let encoded = base32_encode(raw);
        assert_eq!(base32_decode(&encoded).unwrap(), raw);

        // Lowercase, spaces, dashes and padding must all decode identically.
        let messy = format!("{} ", encoded.to_lowercase())
            .chars()
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("-");
        assert_eq!(base32_decode(&messy).unwrap(), raw);
    }

    #[test]
    fn base32_rejects_invalid_characters() {
        assert!(base32_decode("ABC1DEF").is_err()); // '1' is not in the alphabet
        assert!(base32_decode("").is_err());
    }

    #[test]
    fn remaining_seconds_wraps_correctly() {
        assert_eq!(seconds_remaining(0, 30), 30);
        assert_eq!(seconds_remaining(1, 30), 29);
        assert_eq!(seconds_remaining(29, 30), 1);
        assert_eq!(seconds_remaining(30, 30), 30);
    }

    #[test]
    fn steam_codes_are_five_chars_from_the_alphabet() {
        let code = steam(SEED_SHA1, 1).unwrap();
        assert_eq!(code.len(), 5);
        assert!(code.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
    }
}
