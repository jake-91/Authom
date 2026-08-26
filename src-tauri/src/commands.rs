//! The command surface exposed to the UI.
//!
//! Rule of thumb enforced throughout: secrets never cross this boundary. The
//! only exceptions are the two commands whose entire purpose is to hand a
//! secret back (`account_uri`, `export_plaintext`), and both are behind an
//! explicit user action in the UI.

use crate::backup::{self, ImportMode, ImportSummary};
use crate::crypto::{self, KdfParams};
use crate::error::{AppError, Result};
use crate::keychain;
use crate::migration;
use crate::otp::{self, Algorithm, OtpKind, SecretKey};
use crate::qr;
use crate::state::{now_unix, AppState, Unlocked};
use crate::uri;
use crate::vault::{self, Account, Settings, VaultData};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::{Emitter, State};

// ---------------------------------------------------------------- DTOs

#[derive(Debug, Serialize)]
pub struct VaultStatus {
    pub exists: bool,
    pub unlocked: bool,
    pub has_remembered_key: bool,
    pub vault_path: String,
    pub account_count: usize,
}

#[derive(Debug, Serialize)]
pub struct AccountView {
    pub id: String,
    pub kind: OtpKind,
    pub issuer: String,
    pub label: String,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u32,
    pub counter: u64,
    pub group: Option<String>,
    pub notes: Option<String>,
    pub favorite: bool,
    pub color: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub sort_index: i32,
}

impl From<&Account> for AccountView {
    fn from(a: &Account) -> Self {
        AccountView {
            id: a.id.clone(),
            kind: a.kind,
            issuer: a.issuer.clone(),
            label: a.label.clone(),
            algorithm: a.algorithm,
            digits: a.digits,
            period: a.period,
            counter: a.counter,
            group: a.group.clone(),
            notes: a.notes.clone(),
            favorite: a.favorite,
            color: a.color.clone(),
            created_at: a.created_at,
            updated_at: a.updated_at,
            sort_index: a.sort_index,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CodeView {
    pub id: String,
    pub code: String,
    /// The code for the next time step, shown when a step is about to expire.
    pub next_code: Option<String>,
    pub remaining: u32,
    pub period: u32,
    pub counter: u64,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AccountInput {
    pub kind: OtpKind,
    pub issuer: String,
    pub label: String,
    /// Optional on update: `None` keeps the stored secret.
    pub secret: Option<String>,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u32,
    pub counter: Option<u64>,
    pub group: Option<String>,
    pub notes: Option<String>,
    pub favorite: Option<bool>,
    pub color: Option<String>,
}

/// A parsed-but-unsaved entry, safe to render: no secret, just its length.
#[derive(Debug, Serialize)]
pub struct AccountPreview {
    pub kind: OtpKind,
    pub issuer: String,
    pub label: String,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u32,
    pub counter: u64,
    pub secret_length: usize,
    pub duplicate: bool,
}

fn preview_of(account: &Account, data: Option<&VaultData>) -> AccountPreview {
    AccountPreview {
        kind: account.kind,
        issuer: account.issuer.clone(),
        label: account.label.clone(),
        algorithm: account.algorithm,
        digits: account.digits,
        period: account.period,
        counter: account.counter,
        secret_length: account.secret.len(),
        duplicate: data.map(|d| d.contains_duplicate(account)).unwrap_or(false),
    }
}

#[derive(Debug, Serialize)]
pub struct MigrationPreview {
    pub accounts: Vec<AccountPreview>,
    pub batch_size: i32,
    pub batch_index: i32,
    pub skipped: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub uris: Vec<String>,
    pub otpauth_count: usize,
    pub migration_count: usize,
}

// ---------------------------------------------------------------- helpers

fn classify(uris: Vec<String>) -> ScanResult {
    let otpauth_count = uris
        .iter()
        .filter(|u| u.to_ascii_lowercase().starts_with("otpauth://"))
        .count();
    let migration_count = uris
        .iter()
        .filter(|u| u.to_ascii_lowercase().starts_with("otpauth-migration://"))
        .count();
    ScanResult {
        uris,
        otpauth_count,
        migration_count,
    }
}

fn code_for(account: &Account, now: i64) -> CodeView {
    let build = || -> Result<(String, Option<String>, u32, u64)> {
        let key = SecretKey::from_base32(&account.secret)?;
        if !account.kind.is_time_based() {
            let code = otp::hotp(key.bytes(), account.counter, account.algorithm, account.digits)?;
            return Ok((code, None, 0, account.counter));
        }

        let code = otp::code_at(
            key.bytes(),
            now,
            account.period,
            account.algorithm,
            account.digits,
            account.kind,
        )?;
        let remaining = otp::seconds_remaining(now, account.period);
        let next = otp::code_at(
            key.bytes(),
            now + account.period as i64,
            account.period,
            account.algorithm,
            account.digits,
            account.kind,
        )
        .ok();
        Ok((
            code,
            next,
            remaining,
            otp::time_counter(now, account.period),
        ))
    };

    match build() {
        Ok((code, next_code, remaining, counter)) => CodeView {
            id: account.id.clone(),
            code,
            next_code,
            remaining,
            period: account.period,
            counter,
            error: None,
        },
        // A single broken entry must not blank the whole list.
        Err(e) => CodeView {
            id: account.id.clone(),
            code: String::new(),
            next_code: None,
            remaining: 0,
            period: account.period,
            counter: account.counter,
            error: Some(e.to_string()),
        },
    }
}

fn apply_input(account: &mut Account, input: AccountInput, now: i64) -> Result<()> {
    account.kind = input.kind;
    account.issuer = input.issuer;
    account.label = input.label;
    if let Some(secret) = input.secret {
        if !secret.trim().is_empty() {
            account.secret = secret;
        }
    }
    account.algorithm = input.algorithm;
    account.digits = input.digits;
    account.period = input.period;
    if let Some(counter) = input.counter {
        account.counter = counter;
    }
    account.group = input.group;
    account.notes = input.notes;
    if let Some(favorite) = input.favorite {
        account.favorite = favorite;
    }
    account.color = input.color;
    account.updated_at = now;
    account.sanitize()
}

// ---------------------------------------------------------------- vault lifecycle

#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> VaultStatus {
    let mut inner = state.lock_inner();
    if inner.header.is_none() && inner.vault_exists() {
        inner.refresh_header();
    }
    let has_remembered_key = inner
        .vault_id()
        .map(|id| keychain::has_key(&id))
        .unwrap_or(false);

    VaultStatus {
        exists: inner.vault_exists(),
        unlocked: inner.unlocked.is_some(),
        has_remembered_key,
        vault_path: inner.vault_path.display().to_string(),
        account_count: inner
            .unlocked
            .as_ref()
            .map(|u| u.data.accounts.len())
            .unwrap_or(0),
    }
}

#[tauri::command]
pub fn create_vault(
    state: State<'_, AppState>,
    password: String,
    remember: bool,
) -> Result<VaultStatus> {
    if password.chars().count() < 8 {
        return Err(AppError::invalid("마스터 비밀번호는 8자 이상이어야 합니다."));
    }

    let mut inner = state.lock_inner();
    if inner.vault_exists() {
        return Err(AppError::VaultExists);
    }

    let header = vault::new_header(KdfParams::default())?;
    let key = vault::derive_from_header(&password, &header)?;
    let data = VaultData::default();
    let file = vault::seal(&header, &key, &data)?;
    vault::write_file(&inner.vault_path, &file)?;

    if remember {
        keychain::store_key(&file.header.vault_id, &key)?;
    }

    inner.header = Some(file.header);
    inner.unlocked = Some(Unlocked { key, data });
    inner.touch();

    drop(inner);
    Ok(vault_status(state))
}

#[tauri::command]
pub fn unlock_vault(
    state: State<'_, AppState>,
    password: String,
    remember: bool,
) -> Result<VaultStatus> {
    let mut inner = state.lock_inner();
    if !inner.vault_exists() {
        return Err(AppError::NoVault);
    }

    let file = vault::read_file(&inner.vault_path)?;
    let key = vault::derive_from_header(&password, &file.header)?;
    let data = vault::open(&file, &key)?;

    if remember {
        keychain::store_key(&file.header.vault_id, &key)?;
    } else {
        // Unchecking the box on a later unlock should actually forget it.
        let _ = keychain::clear_key(&file.header.vault_id);
    }

    inner.header = Some(file.header);
    inner.unlocked = Some(Unlocked { key, data });
    inner.touch();

    drop(inner);
    Ok(vault_status(state))
}

#[tauri::command]
pub fn unlock_with_saved_key(state: State<'_, AppState>) -> Result<VaultStatus> {
    let mut inner = state.lock_inner();
    if !inner.vault_exists() {
        return Err(AppError::NoVault);
    }

    let file = vault::read_file(&inner.vault_path)?;
    let key = keychain::load_key(&file.header.vault_id)?
        .ok_or_else(|| AppError::msg("이 기기에 저장된 키가 없습니다."))?;
    let data = vault::open(&file, &key)?;

    inner.header = Some(file.header);
    inner.unlocked = Some(Unlocked { key, data });
    inner.touch();

    drop(inner);
    Ok(vault_status(state))
}

#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>) -> VaultStatus {
    {
        let mut inner = state.lock_inner();
        inner.lock();
    }
    vault_status(state)
}

#[tauri::command]
pub fn forget_saved_key(state: State<'_, AppState>) -> Result<VaultStatus> {
    {
        let inner = state.lock_inner();
        if let Some(id) = inner.vault_id() {
            keychain::clear_key(&id)?;
        }
    }
    Ok(vault_status(state))
}

#[tauri::command]
pub fn change_master_password(
    state: State<'_, AppState>,
    current: String,
    new_password: String,
) -> Result<()> {
    if new_password.chars().count() < 8 {
        return Err(AppError::invalid("새 비밀번호는 8자 이상이어야 합니다."));
    }

    let mut inner = state.lock_inner();
    let file = vault::read_file(&inner.vault_path)?;

    // Verify the current password against the file rather than the cached key,
    // so a keychain-unlocked session still has to prove knowledge of it.
    let current_key = vault::derive_from_header(&current, &file.header)?;
    let data = vault::open(&file, &current_key)?;

    let header = vault::new_header(KdfParams::default())?;
    let new_key = vault::derive_from_header(&new_password, &header)?;
    let new_file = vault::seal(&header, &new_key, &data)?;
    vault::write_file(&inner.vault_path, &new_file)?;

    // The remembered key is now stale in every case; refresh or drop it.
    let had_remembered = keychain::has_key(&file.header.vault_id);
    let _ = keychain::clear_key(&file.header.vault_id);
    if had_remembered {
        keychain::store_key(&new_file.header.vault_id, &new_key)?;
    }

    inner.header = Some(new_file.header);
    inner.unlocked = Some(Unlocked {
        key: new_key,
        data,
    });
    inner.touch();
    Ok(())
}

#[tauri::command]
pub fn password_strength(password: String) -> u8 {
    crypto::password_strength(&password)
}

#[tauri::command]
pub fn touch_activity(state: State<'_, AppState>) {
    state.lock_inner().touch();
}

// ---------------------------------------------------------------- accounts

#[tauri::command]
pub fn list_accounts(state: State<'_, AppState>) -> Result<Vec<AccountView>> {
    let mut inner = state.lock_inner();
    inner.touch();
    let unlocked = inner.unlocked_ref()?;
    Ok(unlocked.data.accounts.iter().map(AccountView::from).collect())
}

#[tauri::command]
pub fn generate_codes(state: State<'_, AppState>) -> Result<Vec<CodeView>> {
    let inner = state.lock_inner();
    let unlocked = inner.unlocked_ref()?;
    let now = now_unix();
    Ok(unlocked
        .data
        .accounts
        .iter()
        .map(|a| code_for(a, now))
        .collect())
}

#[tauri::command]
pub fn add_account(state: State<'_, AppState>, input: AccountInput) -> Result<AccountView> {
    let mut inner = state.lock_inner();
    inner.touch();
    let now = now_unix();

    let mut account = Account {
        id: uuid::Uuid::new_v4().to_string(),
        kind: OtpKind::Totp,
        issuer: String::new(),
        label: String::new(),
        secret: String::new(),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
        counter: 0,
        group: None,
        notes: None,
        favorite: false,
        color: None,
        created_at: now,
        updated_at: now,
        sort_index: 0,
    };

    if input.secret.as_deref().unwrap_or("").trim().is_empty() {
        return Err(AppError::invalid("시크릿을 입력하세요."));
    }
    apply_input(&mut account, input, now)?;

    {
        let unlocked = inner.unlocked_mut()?;
        account.sort_index = unlocked.data.next_sort_index();
        unlocked.data.accounts.push(account.clone());
    }
    inner.persist()?;
    Ok(AccountView::from(&account))
}

#[tauri::command]
pub fn update_account(
    state: State<'_, AppState>,
    id: String,
    input: AccountInput,
) -> Result<AccountView> {
    let mut inner = state.lock_inner();
    inner.touch();
    let now = now_unix();

    let updated = {
        let unlocked = inner.unlocked_mut()?;
        let account = unlocked.data.find_mut(&id)?;
        apply_input(account, input, now)?;
        account.clone()
    };
    inner.persist()?;
    Ok(AccountView::from(&updated))
}

#[tauri::command]
pub fn delete_account(state: State<'_, AppState>, id: String) -> Result<()> {
    let mut inner = state.lock_inner();
    inner.touch();
    {
        let unlocked = inner.unlocked_mut()?;
        let before = unlocked.data.accounts.len();
        unlocked.data.accounts.retain(|a| a.id != id);
        if unlocked.data.accounts.len() == before {
            return Err(AppError::NotFound);
        }
    }
    inner.persist()
}

#[tauri::command]
pub fn reorder_accounts(state: State<'_, AppState>, ids: Vec<String>) -> Result<()> {
    let mut inner = state.lock_inner();
    inner.touch();
    {
        let unlocked = inner.unlocked_mut()?;
        for (index, id) in ids.iter().enumerate() {
            if let Ok(account) = unlocked.data.find_mut(id) {
                account.sort_index = index as i32;
            }
        }
    }
    inner.persist()
}

#[tauri::command]
pub fn set_favorite(state: State<'_, AppState>, id: String, favorite: bool) -> Result<()> {
    let mut inner = state.lock_inner();
    inner.touch();
    {
        let unlocked = inner.unlocked_mut()?;
        unlocked.data.find_mut(&id)?.favorite = favorite;
    }
    inner.persist()
}

/// HOTP entries only: burn the current counter and return the new code.
#[tauri::command]
pub fn advance_counter(state: State<'_, AppState>, id: String) -> Result<CodeView> {
    let mut inner = state.lock_inner();
    inner.touch();

    let account = {
        let unlocked = inner.unlocked_mut()?;
        let account = unlocked.data.find_mut(&id)?;
        if account.kind != OtpKind::Hotp {
            return Err(AppError::invalid("HOTP 항목이 아닙니다."));
        }
        account.counter = account.counter.saturating_add(1);
        account.updated_at = now_unix();
        account.clone()
    };
    inner.persist()?;
    Ok(code_for(&account, now_unix()))
}

/// Reveals a secret. Only ever called from the explicit "show secret / export
/// this entry" action in the UI.
#[tauri::command]
pub fn account_uri(state: State<'_, AppState>, id: String) -> Result<String> {
    let mut inner = state.lock_inner();
    inner.touch();
    let unlocked = inner.unlocked_ref()?;
    Ok(uri::build_otpauth(unlocked.data.find(&id)?))
}

// ---------------------------------------------------------------- import

#[tauri::command]
pub fn preview_uri(state: State<'_, AppState>, input: String) -> Result<AccountPreview> {
    let account = uri::parse_otpauth(&input)?;
    let inner = state.lock_inner();
    let data = inner.unlocked.as_ref().map(|u| &u.data);
    Ok(preview_of(&account, data))
}

#[tauri::command]
pub fn import_uris(
    state: State<'_, AppState>,
    uris: Vec<String>,
    mode: ImportMode,
) -> Result<ImportSummary> {
    let mut accounts = Vec::new();
    let mut errors = Vec::new();
    for item in &uris {
        match uri::parse_otpauth(item) {
            Ok(a) => accounts.push(a),
            Err(e) => errors.push(e.to_string()),
        }
    }
    if accounts.is_empty() {
        return Err(AppError::invalid(format!(
            "가져올 수 있는 항목이 없습니다. {}",
            errors.join(" / ")
        )));
    }

    let mut inner = state.lock_inner();
    inner.touch();
    let now = now_unix();
    let summary = {
        let unlocked = inner.unlocked_mut()?;
        backup::apply_import(&mut unlocked.data, accounts, mode, now)
    };
    inner.persist()?;
    Ok(summary)
}

#[tauri::command]
pub fn preview_migration(
    state: State<'_, AppState>,
    input: String,
) -> Result<MigrationPreview> {
    let result = migration::parse_migration(&input)?;
    let inner = state.lock_inner();
    let data = inner.unlocked.as_ref().map(|u| &u.data);

    Ok(MigrationPreview {
        accounts: result
            .accounts
            .iter()
            .map(|a| preview_of(a, data))
            .collect(),
        batch_size: result.batch.size,
        batch_index: result.batch.index,
        skipped: result.skipped,
    })
}

#[tauri::command]
pub fn import_migration(
    state: State<'_, AppState>,
    input: String,
    mode: ImportMode,
) -> Result<ImportSummary> {
    let result = migration::parse_migration(&input)?;
    if result.accounts.is_empty() {
        return Err(AppError::invalid("가져올 수 있는 항목이 없습니다."));
    }

    let mut inner = state.lock_inner();
    inner.touch();
    let now = now_unix();
    let summary = {
        let unlocked = inner.unlocked_mut()?;
        backup::apply_import(&mut unlocked.data, result.accounts, mode, now)
    };
    inner.persist()?;
    Ok(summary)
}

// ---------------------------------------------------------------- QR scanning

#[tauri::command]
pub fn scan_qr_file(state: State<'_, AppState>, path: String) -> Result<ScanResult> {
    state.lock_inner().touch();
    Ok(classify(qr::decode_image_file(&PathBuf::from(path))?))
}

#[tauri::command]
pub fn scan_qr_bytes(state: State<'_, AppState>, bytes: Vec<u8>) -> Result<ScanResult> {
    state.lock_inner().touch();
    Ok(classify(qr::decode_image_bytes(&bytes)?))
}

#[tauri::command]
pub fn scan_qr_rgba(
    state: State<'_, AppState>,
    width: u32,
    height: u32,
    bytes: Vec<u8>,
) -> Result<ScanResult> {
    state.lock_inner().touch();
    Ok(classify(qr::decode_rgba(width, height, &bytes)?))
}

#[tauri::command]
pub fn scan_qr_screen(state: State<'_, AppState>) -> Result<ScanResult> {
    state.lock_inner().touch();
    Ok(classify(qr::scan_screens()?))
}

// ---------------------------------------------------------------- backup

#[tauri::command]
pub fn export_backup(state: State<'_, AppState>, path: String, password: String) -> Result<()> {
    let mut inner = state.lock_inner();
    inner.touch();
    let unlocked = inner.unlocked_ref()?;
    backup::export_encrypted(&PathBuf::from(path), &password, &unlocked.data)
}

#[tauri::command]
pub fn import_backup(
    state: State<'_, AppState>,
    path: String,
    password: String,
    mode: ImportMode,
) -> Result<ImportSummary> {
    let imported = backup::read_encrypted(&PathBuf::from(path), &password)?;

    let mut inner = state.lock_inner();
    inner.touch();
    let now = now_unix();
    let summary = {
        let unlocked = inner.unlocked_mut()?;
        backup::apply_import(&mut unlocked.data, imported.accounts, mode, now)
    };
    inner.persist()?;
    Ok(summary)
}

/// Writes every secret in the clear. The UI gates this behind a warning.
#[tauri::command]
pub fn export_plaintext(state: State<'_, AppState>, path: String) -> Result<()> {
    let mut inner = state.lock_inner();
    inner.touch();
    let unlocked = inner.unlocked_ref()?;
    backup::export_plaintext_uris(&PathBuf::from(path), &unlocked.data)
}

#[tauri::command]
pub fn import_plaintext(
    state: State<'_, AppState>,
    path: String,
    mode: ImportMode,
) -> Result<ImportSummary> {
    let (accounts, errors) = backup::read_plaintext_uris(&PathBuf::from(path))?;
    if accounts.is_empty() {
        return Err(AppError::invalid(format!(
            "가져올 수 있는 항목이 없습니다. {}",
            errors.join(" / ")
        )));
    }

    let mut inner = state.lock_inner();
    inner.touch();
    let now = now_unix();
    let summary = {
        let unlocked = inner.unlocked_mut()?;
        backup::apply_import(&mut unlocked.data, accounts, mode, now)
    };
    inner.persist()?;
    Ok(summary)
}

// ---------------------------------------------------------------- settings

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Result<Settings> {
    let inner = state.lock_inner();
    Ok(inner.unlocked_ref()?.data.settings.clone())
}

#[tauri::command]
pub fn update_settings(state: State<'_, AppState>, settings: Settings) -> Result<Settings> {
    let mut inner = state.lock_inner();
    inner.touch();
    let stored = {
        let unlocked = inner.unlocked_mut()?;
        unlocked.data.settings = settings;
        unlocked.data.settings.clone()
    };
    inner.persist()?;
    Ok(stored)
}

/// Difference between this machine's clock and the code the UI is showing.
/// Purely informational, but a drifting clock is the single most common cause
/// of "the app gives wrong codes".
#[tauri::command]
pub fn clock_info() -> serde_json::Value {
    let now = now_unix();
    serde_json::json!({
        "unix": now,
        "step_remaining_30s": otp::seconds_remaining(now, 30),
    })
}

/// Called by the auto-lock watchdog and by window events.
pub fn lock_and_notify(app: &tauri::AppHandle, state: &AppState) {
    let mut inner = state.lock_inner();
    if inner.unlocked.is_some() {
        inner.lock();
        drop(inner);
        let _ = app.emit("vault-locked", ());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::base32_encode;

    fn account(kind: OtpKind, secret: &str, digits: u8) -> Account {
        Account {
            id: "test".into(),
            kind,
            issuer: "Example".into(),
            label: "user".into(),
            secret: secret.into(),
            algorithm: Algorithm::Sha1,
            digits,
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

    /// The row the UI renders must match the RFC 6238 vector exactly.
    #[test]
    fn totp_row_matches_rfc_vector() {
        let secret = base32_encode(b"12345678901234567890");
        let view = code_for(&account(OtpKind::Totp, &secret, 8), 59);
        assert_eq!(view.code, "94287082");
        assert_eq!(view.remaining, 1); // 59 % 30 == 29, so one second left
        assert!(view.error.is_none());
        assert!(view.next_code.is_some());
    }

    #[test]
    fn hotp_row_has_no_countdown() {
        let secret = base32_encode(b"12345678901234567890");
        let view = code_for(&account(OtpKind::Hotp, &secret, 6), 1_000_000);
        assert_eq!(view.code, "755224"); // counter 0, RFC 4226
        assert_eq!(view.remaining, 0);
        assert!(view.next_code.is_none());
    }

    #[test]
    fn broken_secret_becomes_a_row_error_not_a_panic() {
        let view = code_for(&account(OtpKind::Totp, "!!!not-base32!!!", 6), 0);
        assert!(view.code.is_empty());
        assert!(view.error.is_some());
    }

    #[test]
    fn blank_secret_on_update_keeps_the_stored_one() {
        let secret = base32_encode(b"12345678901234567890");
        let mut existing = account(OtpKind::Totp, &secret, 6);

        let input = AccountInput {
            kind: OtpKind::Totp,
            issuer: "Example".into(),
            label: "user".into(),
            secret: Some("   ".into()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            counter: None,
            group: None,
            notes: None,
            favorite: None,
            color: None,
        };
        apply_input(&mut existing, input, 42).unwrap();
        assert_eq!(existing.secret, secret);
        assert_eq!(existing.updated_at, 42);
    }

    #[test]
    fn scan_results_are_classified_by_scheme() {
        let result = classify(vec![
            "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP".into(),
            "otpauth-migration://offline?data=xx".into(),
            "https://example.com".into(),
        ]);
        assert_eq!(result.otpauth_count, 1);
        assert_eq!(result.migration_count, 1);
        assert_eq!(result.uris.len(), 3);
    }
}
