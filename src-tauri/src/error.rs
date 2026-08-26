use serde::{Serialize, Serializer};

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Message(String),

    #[error("볼트가 잠겨 있습니다.")]
    Locked,

    #[error("볼트가 아직 만들어지지 않았습니다.")]
    NoVault,

    #[error("이미 볼트가 존재합니다.")]
    VaultExists,

    #[error("마스터 비밀번호가 올바르지 않습니다.")]
    BadPassword,

    #[error("항목을 찾을 수 없습니다.")]
    NotFound,

    #[error("잘못된 형식입니다: {0}")]
    Invalid(String),

    #[error("파일 오류: {0}")]
    Io(#[from] std::io::Error),

    #[error("데이터 오류: {0}")]
    Json(#[from] serde_json::Error),
}

impl AppError {
    pub fn msg(m: impl Into<String>) -> Self {
        AppError::Message(m.into())
    }

    pub fn invalid(m: impl Into<String>) -> Self {
        AppError::Invalid(m.into())
    }
}

/// Tauri commands must return something serializable; the UI only ever needs
/// the human-readable message, never the internal variant.
impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
