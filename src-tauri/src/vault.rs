//! Vault model and on-disk format.
//!
//! The file is a small JSON envelope: a cleartext header describing how to
//! derive the key, plus one base64 AEAD blob holding every account. Nothing
//! about an account — issuer, label, secret — is readable without the key.

use crate::crypto::{self, KdfParams, MasterKey};
use crate::error::{AppError, Result};
use crate::otp::{Algorithm, OtpKind};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const VAULT_VERSION: u32 = 1;
const KDF_NAME: &str = "argon2id";
const CIPHER_NAME: &str = "xchacha20poly1305";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub version: u32,
    pub vault_id: String,
    pub kdf: String,
    pub kdf_params: KdfParams,
    pub salt: String,
    pub cipher: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub header: VaultHeader,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    #[serde(default)]
    pub kind: OtpKind,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub label: String,
    /// Base32, exactly as the provider issued it.
    pub secret: String,
    #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default = "default_digits")]
    pub digits: u8,
    #[serde(default = "default_period")]
    pub period: u32,
    /// HOTP only; ignored for time-based entries.
    #[serde(default)]
    pub counter: u64,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub sort_index: i32,
}

fn default_digits() -> u8 {
    6
}

fn default_period() -> u32 {
    30
}

impl Account {
    /// Normalise and range-check user input before it reaches the vault.
    pub fn sanitize(&mut self) -> Result<()> {
        self.issuer = self.issuer.trim().to_string();
        self.label = self.label.trim().to_string();
        self.secret = self.secret.split_whitespace().collect::<String>();

        if self.issuer.is_empty() && self.label.is_empty() {
            return Err(AppError::invalid("발급자나 계정 이름 중 하나는 필요합니다."));
        }

        // Validates the base32 as a side effect; the decoded key is discarded.
        crate::otp::SecretKey::from_base32(&self.secret)?;

        if self.kind == OtpKind::Steam {
            self.algorithm = Algorithm::Sha1;
            self.digits = 5;
            self.period = 30;
        } else {
            if !(6..=9).contains(&self.digits) {
                return Err(AppError::invalid("자릿수는 6~9 사이여야 합니다."));
            }
            if !(5..=300).contains(&self.period) {
                return Err(AppError::invalid("주기는 5~300초 사이여야 합니다."));
            }
        }

        if let Some(g) = &self.group {
            let g = g.trim();
            self.group = if g.is_empty() {
                None
            } else {
                Some(g.to_string())
            };
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// 0 disables automatic locking.
    #[serde(default = "default_auto_lock")]
    pub auto_lock_seconds: u64,
    /// 0 disables clipboard clearing.
    #[serde(default = "default_clipboard_clear")]
    pub clipboard_clear_seconds: u64,
    #[serde(default)]
    pub hide_codes: bool,
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_sort_mode")]
    pub sort_mode: String,
    #[serde(default = "default_true")]
    pub lock_on_minimize: bool,
    #[serde(default)]
    pub compact: bool,
}

fn default_auto_lock() -> u64 {
    300
}
fn default_clipboard_clear() -> u64 {
    30
}
fn default_theme() -> String {
    "system".to_string()
}
fn default_sort_mode() -> String {
    "custom".to_string()
}
fn default_true() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            auto_lock_seconds: default_auto_lock(),
            clipboard_clear_seconds: default_clipboard_clear(),
            hide_codes: false,
            theme: default_theme(),
            sort_mode: default_sort_mode(),
            lock_on_minimize: true,
            compact: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub settings: Settings,
}

impl VaultData {
    pub fn find(&self, id: &str) -> Result<&Account> {
        self.accounts
            .iter()
            .find(|a| a.id == id)
            .ok_or(AppError::NotFound)
    }

    pub fn find_mut(&mut self, id: &str) -> Result<&mut Account> {
        self.accounts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or(AppError::NotFound)
    }

    pub fn next_sort_index(&self) -> i32 {
        self.accounts
            .iter()
            .map(|a| a.sort_index)
            .max()
            .unwrap_or(-1)
            + 1
    }

    /// True when an entry with the same issuer/label/secret already exists.
    pub fn contains_duplicate(&self, candidate: &Account) -> bool {
        self.accounts.iter().any(|a| {
            a.secret.eq_ignore_ascii_case(&candidate.secret)
                && a.issuer.eq_ignore_ascii_case(&candidate.issuer)
                && a.label.eq_ignore_ascii_case(&candidate.label)
        })
    }
}

/// Associated data binds the ciphertext to its header so the KDF parameters
/// cannot be swapped out underneath us.
fn aad_for(header: &VaultHeader) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(header)?)
}

pub fn new_header(kdf_params: KdfParams) -> Result<VaultHeader> {
    Ok(VaultHeader {
        version: VAULT_VERSION,
        vault_id: uuid::Uuid::new_v4().to_string(),
        kdf: KDF_NAME.to_string(),
        kdf_params,
        salt: B64.encode(crypto::random_salt()?),
        cipher: CIPHER_NAME.to_string(),
        nonce: B64.encode(crypto::random_nonce()?),
    })
}

fn check_header(header: &VaultHeader) -> Result<()> {
    if header.version > VAULT_VERSION {
        return Err(AppError::invalid(format!(
            "이 볼트는 더 새로운 버전({})입니다. 앱을 업데이트하세요.",
            header.version
        )));
    }
    if header.kdf != KDF_NAME {
        return Err(AppError::invalid(format!(
            "지원하지 않는 KDF입니다: {}",
            header.kdf
        )));
    }
    if header.cipher != CIPHER_NAME {
        return Err(AppError::invalid(format!(
            "지원하지 않는 암호입니다: {}",
            header.cipher
        )));
    }
    Ok(())
}

pub fn derive_from_header(password: &str, header: &VaultHeader) -> Result<MasterKey> {
    check_header(header)?;
    let salt = B64
        .decode(&header.salt)
        .map_err(|_| AppError::invalid("볼트 헤더의 솔트가 손상되었습니다."))?;
    crypto::derive_key(password, &salt, &header.kdf_params)
}

/// Encrypt `data` under `key`, rotating the nonce. The header is returned
/// updated so callers always persist the nonce that was actually used.
pub fn seal(header: &VaultHeader, key: &MasterKey, data: &VaultData) -> Result<VaultFile> {
    let mut header = header.clone();
    header.nonce = B64.encode(crypto::random_nonce()?);

    let aad = aad_for(&header)?;
    let plaintext = serde_json::to_vec(data)?;
    let nonce = B64
        .decode(&header.nonce)
        .map_err(|_| AppError::msg("논스 인코딩 오류"))?;
    let ciphertext = crypto::encrypt(key, &nonce, &plaintext, &aad)?;

    Ok(VaultFile {
        header,
        ciphertext: B64.encode(ciphertext),
    })
}

pub fn open(file: &VaultFile, key: &MasterKey) -> Result<VaultData> {
    check_header(&file.header)?;
    let aad = aad_for(&file.header)?;
    let nonce = B64
        .decode(&file.header.nonce)
        .map_err(|_| AppError::invalid("볼트 헤더의 논스가 손상되었습니다."))?;
    let ciphertext = B64
        .decode(&file.ciphertext)
        .map_err(|_| AppError::invalid("볼트 본문이 손상되었습니다."))?;

    let plaintext = crypto::decrypt(key, &nonce, &ciphertext, &aad)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

pub fn read_file(path: &Path) -> Result<VaultFile> {
    if !path.exists() {
        return Err(AppError::NoVault);
    }
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Write atomically where the filesystem allows it, and keep one generation of
/// backup so a crash mid-write can never leave the user without a vault.
pub fn write_file(path: &Path, file: &VaultFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp: PathBuf = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(file)?;
    std::fs::write(&tmp, &json)?;

    if path.exists() {
        let backup = path.with_extension("json.bak");
        // A failed backup must not block the write itself.
        let _ = std::fs::copy(path, &backup);
    }

    // Rename is the atomic path, but it is not universally available: a
    // virtualised AppData (MSIX/App-V containers) or a redirected profile can
    // report ERROR_NOT_SAME_DEVICE for two files sitting in the same folder.
    // Falling back to a direct write costs atomicity, not the data — the .bak
    // written above is the recovery point.
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(rename_error) => {
            std::fs::write(path, &json).map_err(|write_error| {
                AppError::msg(format!(
                    "볼트를 저장하지 못했습니다. 이동 실패: {rename_error} / 직접 쓰기 실패: {write_error}"
                ))
            })?;
            let _ = std::fs::remove_file(&tmp);
            Ok(())
        }
    }
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

    fn sample_account() -> Account {
        Account {
            id: "id-1".into(),
            kind: OtpKind::Totp,
            issuer: "GitHub".into(),
            label: "me@example.com".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            counter: 0,
            group: None,
            notes: None,
            favorite: false,
            color: None,
            created_at: 0,
            updated_at: 0,
            sort_index: 0,
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let header = new_header(fast_params()).unwrap();
        let key = derive_from_header("hunter2", &header).unwrap();
        let mut data = VaultData::default();
        data.accounts.push(sample_account());

        let file = seal(&header, &key, &data).unwrap();
        let reopened = open(&file, &key).unwrap();
        assert_eq!(reopened.accounts.len(), 1);
        assert_eq!(reopened.accounts[0].issuer, "GitHub");
    }

    #[test]
    fn wrong_password_fails_to_open() {
        let header = new_header(fast_params()).unwrap();
        let key = derive_from_header("hunter2", &header).unwrap();
        let file = seal(&header, &key, &VaultData::default()).unwrap();

        let wrong = derive_from_header("hunter3", &file.header).unwrap();
        assert!(matches!(
            open(&file, &wrong).unwrap_err(),
            AppError::BadPassword
        ));
    }

    #[test]
    fn header_tampering_is_detected() {
        let header = new_header(fast_params()).unwrap();
        let key = derive_from_header("hunter2", &header).unwrap();
        let mut file = seal(&header, &key, &VaultData::default()).unwrap();

        // Same salt and nonce, weakened KDF: the AAD check must reject it.
        file.header.kdf_params.iterations = 2;
        assert!(open(&file, &key).is_err());
    }

    #[test]
    fn sealing_rotates_the_nonce() {
        let header = new_header(fast_params()).unwrap();
        let key = derive_from_header("pw", &header).unwrap();
        let a = seal(&header, &key, &VaultData::default()).unwrap();
        let b = seal(&header, &key, &VaultData::default()).unwrap();
        assert_ne!(a.header.nonce, b.header.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn sanitize_rejects_bad_input() {
        let mut a = sample_account();
        a.issuer = "  ".into();
        a.label = "".into();
        assert!(a.sanitize().is_err());

        let mut b = sample_account();
        b.secret = "not-base32-!!".into();
        assert!(b.sanitize().is_err());

        let mut c = sample_account();
        c.digits = 12;
        assert!(c.sanitize().is_err());
    }

    #[test]
    fn sanitize_strips_spaces_from_secret() {
        let mut a = sample_account();
        a.secret = "JBSW Y3DP EHPK 3PXP".into();
        a.sanitize().unwrap();
        assert_eq!(a.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn steam_entries_are_forced_to_canonical_parameters() {
        let mut a = sample_account();
        a.kind = OtpKind::Steam;
        a.digits = 8;
        a.period = 60;
        a.sanitize().unwrap();
        assert_eq!(a.digits, 5);
        assert_eq!(a.period, 30);
    }

    #[test]
    fn write_then_read_round_trips_and_keeps_a_backup() {
        let dir = std::env::temp_dir().join(format!("authom-vault-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.json");

        let header = new_header(fast_params()).unwrap();
        let key = derive_from_header("pw", &header).unwrap();

        let mut data = VaultData::default();
        data.accounts.push(sample_account());
        write_file(&path, &seal(&header, &key, &data).unwrap()).unwrap();

        let loaded = read_file(&path).unwrap();
        assert_eq!(open(&loaded, &key).unwrap().accounts.len(), 1);
        // No previous generation existed, so nothing to back up yet.
        assert!(!path.with_extension("json.bak").exists());

        // A second write must preserve the previous file as .bak.
        data.accounts.clear();
        write_file(&path, &seal(&loaded.header, &key, &data).unwrap()).unwrap();
        assert!(path.with_extension("json.bak").exists());
        assert!(open(&read_file(&path).unwrap(), &key).unwrap().accounts.is_empty());
        // The temp file must not be left behind.
        assert!(!path.with_extension("json.tmp").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_stale_temp_file_does_not_block_the_next_save() {
        let dir = std::env::temp_dir().join(format!("authom-stale-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.json");

        // Simulate the leftover of an interrupted write.
        std::fs::write(path.with_extension("json.tmp"), b"garbage").unwrap();

        let header = new_header(fast_params()).unwrap();
        let key = derive_from_header("pw", &header).unwrap();
        write_file(&path, &seal(&header, &key, &VaultData::default()).unwrap()).unwrap();

        assert!(path.exists());
        assert!(open(&read_file(&path).unwrap(), &key).is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_vault_reports_no_vault() {
        let path = std::env::temp_dir().join("authom-definitely-missing.json");
        assert!(matches!(read_file(&path).unwrap_err(), AppError::NoVault));
    }

    #[test]
    fn duplicate_detection_ignores_case() {
        let mut data = VaultData::default();
        data.accounts.push(sample_account());
        let mut candidate = sample_account();
        candidate.id = "id-2".into();
        candidate.issuer = "github".into();
        assert!(data.contains_duplicate(&candidate));
    }
}
