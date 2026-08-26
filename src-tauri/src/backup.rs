//! Encrypted backup export/import, plus a deliberately awkward plaintext export.

use crate::crypto::KdfParams;
use crate::error::{AppError, Result};
use crate::uri;
use crate::vault::{self, Account, VaultData, VaultFile};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportMode {
    /// Add entries that are not already present, keep everything else.
    Merge,
    /// Discard the current accounts and take the backup verbatim.
    Replace,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportSummary {
    pub added: usize,
    pub skipped_duplicates: usize,
    pub total_in_file: usize,
}

/// A backup is the same envelope as the live vault, re-keyed under whatever
/// password the user picks for it. That keeps one format to reason about.
pub fn export_encrypted(path: &Path, password: &str, data: &VaultData) -> Result<()> {
    if password.chars().count() < 8 {
        return Err(AppError::invalid("백업 비밀번호는 8자 이상이어야 합니다."));
    }
    let header = vault::new_header(KdfParams::default())?;
    let key = vault::derive_from_header(password, &header)?;
    let file = vault::seal(&header, &key, data)?;
    let json = serde_json::to_vec_pretty(&file)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn read_encrypted(path: &Path, password: &str) -> Result<VaultData> {
    let bytes = std::fs::read(path)?;
    let file: VaultFile = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::invalid("백업 파일 형식이 아닙니다."))?;
    let key = vault::derive_from_header(password, &file.header)?;
    vault::open(&file, &key)
}

/// Apply an imported account list to the live vault.
pub fn apply_import(
    target: &mut VaultData,
    incoming: Vec<Account>,
    mode: ImportMode,
    now: i64,
) -> ImportSummary {
    let total = incoming.len();

    if mode == ImportMode::Replace {
        target.accounts.clear();
    }

    let mut added = 0usize;
    let mut skipped = 0usize;

    for mut account in incoming {
        if target.contains_duplicate(&account) {
            skipped += 1;
            continue;
        }
        // Never trust ids from a file: a collision would silently shadow an
        // existing entry on the next edit.
        account.id = uuid::Uuid::new_v4().to_string();
        if account.created_at == 0 {
            account.created_at = now;
        }
        account.updated_at = now;
        account.sort_index = target.next_sort_index();
        target.accounts.push(account);
        added += 1;
    }

    ImportSummary {
        added,
        skipped_duplicates: skipped,
        total_in_file: total,
    }
}

/// Plaintext export. Every secret is readable by anyone who opens the file,
/// so the header says so in as many words.
pub fn export_plaintext_uris(path: &Path, data: &VaultData) -> Result<()> {
    let mut out = String::new();
    out.push_str("# Authom 평문 내보내기\n");
    out.push_str("# 경고: 이 파일에는 모든 2단계 인증 시크릿이 그대로 들어 있습니다.\n");
    out.push_str("# 가져오기가 끝나면 즉시 안전하게 삭제하세요.\n\n");

    for account in &data.accounts {
        out.push_str(&uri::build_otpauth(account));
        out.push('\n');
    }

    std::fs::write(path, out)?;
    Ok(())
}

/// Read a text file of `otpauth://` URIs, one per line. Blank lines and
/// comments are ignored; unparseable lines are reported rather than dropped.
pub fn read_plaintext_uris(path: &Path) -> Result<(Vec<Account>, Vec<String>)> {
    let text = std::fs::read_to_string(path)?;
    let mut accounts = Vec::new();
    let mut errors = Vec::new();

    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match uri::parse_otpauth(line) {
            Ok(account) => accounts.push(account),
            Err(e) => errors.push(format!("{}번째 줄: {}", line_no + 1, e)),
        }
    }

    if accounts.is_empty() && errors.is_empty() {
        return Err(AppError::invalid("가져올 URI가 없습니다."));
    }
    Ok((accounts, errors))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::{Algorithm, OtpKind};

    fn account(id: &str, issuer: &str, secret: &str) -> Account {
        Account {
            id: id.into(),
            kind: OtpKind::Totp,
            issuer: issuer.into(),
            label: "user".into(),
            secret: secret.into(),
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
    fn merge_skips_duplicates_and_reassigns_ids() {
        let mut target = VaultData::default();
        target.accounts.push(account("a", "GitHub", "JBSWY3DPEHPK3PXP"));

        let incoming = vec![
            account("a", "GitHub", "JBSWY3DPEHPK3PXP"), // duplicate
            account("b", "GitLab", "KRSXG5CTMVRXEZLU"),
        ];

        let summary = apply_import(&mut target, incoming, ImportMode::Merge, 100);
        assert_eq!(summary.added, 1);
        assert_eq!(summary.skipped_duplicates, 1);
        assert_eq!(target.accounts.len(), 2);
        assert_ne!(target.accounts[1].id, "b");
        assert_eq!(target.accounts[1].updated_at, 100);
    }

    #[test]
    fn replace_clears_existing_entries() {
        let mut target = VaultData::default();
        target.accounts.push(account("a", "GitHub", "JBSWY3DPEHPK3PXP"));

        let summary = apply_import(
            &mut target,
            vec![account("b", "GitLab", "KRSXG5CTMVRXEZLU")],
            ImportMode::Replace,
            100,
        );
        assert_eq!(summary.added, 1);
        assert_eq!(target.accounts.len(), 1);
        assert_eq!(target.accounts[0].issuer, "GitLab");
    }

    #[test]
    fn encrypted_backup_round_trips_and_rejects_wrong_password() {
        let dir = std::env::temp_dir().join(format!("authom-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.json");

        let mut data = VaultData::default();
        data.accounts.push(account("a", "GitHub", "JBSWY3DPEHPK3PXP"));

        export_encrypted(&path, "backup-password", &data).unwrap();

        let restored = read_encrypted(&path, "backup-password").unwrap();
        assert_eq!(restored.accounts.len(), 1);
        assert_eq!(restored.accounts[0].issuer, "GitHub");

        assert!(read_encrypted(&path, "wrong-password").is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn short_backup_passwords_are_refused() {
        let path = std::env::temp_dir().join("authom-never-written.json");
        assert!(export_encrypted(&path, "short", &VaultData::default()).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn plaintext_round_trip_reports_bad_lines() {
        let dir = std::env::temp_dir().join(format!("authom-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("export.txt");

        let mut data = VaultData::default();
        data.accounts.push(account("a", "GitHub", "JBSWY3DPEHPK3PXP"));
        export_plaintext_uris(&path, &data).unwrap();

        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("this line is not a uri\n");
        std::fs::write(&path, text).unwrap();

        let (accounts, errors) = read_plaintext_uris(&path).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].issuer, "GitHub");
        assert_eq!(errors.len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }
}
