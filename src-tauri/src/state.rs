//! Process-wide vault state. Secrets live here and nowhere else.

use crate::crypto::MasterKey;
use crate::error::{AppError, Result};
use crate::vault::{self, VaultData, VaultFile, VaultHeader};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct Unlocked {
    pub key: MasterKey,
    pub data: VaultData,
}

pub struct Inner {
    pub vault_path: PathBuf,
    /// Cached header of the vault on disk, so the unlock screen knows the
    /// vault id (for the keychain lookup) before any password is entered.
    pub header: Option<VaultHeader>,
    pub unlocked: Option<Unlocked>,
    pub last_activity: Instant,
}

impl Inner {
    pub fn unlocked_mut(&mut self) -> Result<&mut Unlocked> {
        self.unlocked.as_mut().ok_or(AppError::Locked)
    }

    pub fn unlocked_ref(&self) -> Result<&Unlocked> {
        self.unlocked.as_ref().ok_or(AppError::Locked)
    }

    pub fn vault_exists(&self) -> bool {
        self.vault_path.exists()
    }

    pub fn vault_id(&self) -> Option<String> {
        self.header.as_ref().map(|h| h.vault_id.clone())
    }

    /// Re-read the header from disk. Missing or unreadable files simply leave
    /// the cache empty; the caller decides whether that is an error.
    pub fn refresh_header(&mut self) {
        self.header = vault::read_file(&self.vault_path).ok().map(|f| f.header);
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn idle_seconds(&self) -> u64 {
        self.last_activity.elapsed().as_secs()
    }

    /// Encrypt the in-memory vault and write it out. No-op guard: callers that
    /// hit this while locked have a bug, so it surfaces as an error.
    pub fn persist(&mut self) -> Result<()> {
        let header = self
            .header
            .clone()
            .ok_or_else(|| AppError::msg("볼트 헤더가 없습니다."))?;
        let unlocked = self.unlocked_ref()?;
        let file: VaultFile = vault::seal(&header, &unlocked.key, &unlocked.data)?;
        vault::write_file(&self.vault_path, &file)?;
        self.header = Some(file.header);
        Ok(())
    }

    pub fn lock(&mut self) {
        // Dropping `Unlocked` zeroizes the key; the decrypted accounts go with it.
        self.unlocked = None;
    }
}

pub struct AppState(pub Mutex<Inner>);

impl AppState {
    pub fn new(vault_path: PathBuf) -> Self {
        let header = vault::read_file(&vault_path).ok().map(|f| f.header);
        AppState(Mutex::new(Inner {
            vault_path,
            header,
            unlocked: None,
            last_activity: Instant::now(),
        }))
    }

    /// A poisoned mutex means another command panicked while holding vault
    /// state. Recovering the guard is preferable to bricking the app, and the
    /// only invariant at risk is "is it unlocked", which we re-check anyway.
    pub fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}
