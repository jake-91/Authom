//! Optional "remember this device" support backed by the OS credential store
//! (Windows Credential Manager / macOS Keychain).
//!
//! What is stored is the derived vault key, not the master password. The vault
//! file itself stays password-derived, so it remains portable to another
//! machine even when this cache is present.

use crate::crypto::{MasterKey, KEY_LEN};
use crate::error::{AppError, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use keyring::Entry;
use zeroize::{Zeroize, Zeroizing};

const SERVICE: &str = "Authom";

fn entry_for(vault_id: &str) -> Result<Entry> {
    Entry::new(SERVICE, &format!("vault-key:{vault_id}"))
        .map_err(|e| AppError::msg(format!("OS 키체인에 접근할 수 없습니다: {e}")))
}

pub fn store_key(vault_id: &str, key: &MasterKey) -> Result<()> {
    let entry = entry_for(vault_id)?;
    let mut encoded = B64.encode(key.as_ref());
    let result = entry
        .set_password(&encoded)
        .map_err(|e| AppError::msg(format!("키체인 저장에 실패했습니다: {e}")));
    encoded.zeroize();
    result
}

/// `Ok(None)` means "nothing remembered", which is a normal state rather than
/// an error the UI should surface.
pub fn load_key(vault_id: &str) -> Result<Option<MasterKey>> {
    let entry = entry_for(vault_id)?;
    let encoded = match entry.get_password() {
        Ok(value) => Zeroizing::new(value),
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(e) => return Err(AppError::msg(format!("키체인 조회에 실패했습니다: {e}"))),
    };

    let decoded = Zeroizing::new(
        B64.decode(encoded.as_bytes())
            .map_err(|_| AppError::msg("키체인에 저장된 키가 손상되었습니다."))?,
    );

    if decoded.len() != KEY_LEN {
        // A stale or corrupt entry is worse than none; drop it.
        let _ = clear_key(vault_id);
        return Ok(None);
    }

    let mut key: MasterKey = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&decoded);
    Ok(Some(key))
}

pub fn clear_key(vault_id: &str) -> Result<()> {
    let entry = entry_for(vault_id)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(AppError::msg(format!("키체인 삭제에 실패했습니다: {e}"))),
    }
}

pub fn has_key(vault_id: &str) -> bool {
    matches!(load_key(vault_id), Ok(Some(_)))
}
