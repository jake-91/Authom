//! Import of Google Authenticator export QR codes
//! (`otpauth-migration://offline?data=...`).
//!
//! The payload is a protobuf message. Rather than pull in a code generator and
//! a `protoc` build dependency for five fields, this decodes the wire format
//! directly — the schema is tiny and frozen.

use crate::error::{AppError, Result};
use crate::otp::{base32_encode, Algorithm, OtpKind};
use crate::vault::Account;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use url::Url;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn byte(&mut self) -> Result<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| AppError::invalid("마이그레이션 데이터가 잘렸습니다."))?;
        self.pos += 1;
        Ok(b)
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            value |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(AppError::invalid("varint가 너무 깁니다."))
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| AppError::invalid("길이 값이 잘못되었습니다."))?;
        if end > self.data.len() {
            return Err(AppError::invalid("마이그레이션 데이터가 잘렸습니다."));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Skip a field we do not care about, given its wire type.
    fn skip(&mut self, wire_type: u8) -> Result<()> {
        match wire_type {
            0 => {
                self.varint()?;
            }
            1 => {
                self.bytes(8)?;
            }
            2 => {
                let len = self.varint()? as usize;
                self.bytes(len)?;
            }
            5 => {
                self.bytes(4)?;
            }
            other => {
                return Err(AppError::invalid(format!(
                    "알 수 없는 protobuf 와이어 타입: {other}"
                )))
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct OtpParameters {
    secret: Vec<u8>,
    name: String,
    issuer: String,
    algorithm: u64,
    digits: u64,
    kind: u64,
    counter: u64,
}

fn parse_otp_parameters(data: &[u8]) -> Result<OtpParameters> {
    let mut r = Reader::new(data);
    let mut out = OtpParameters::default();

    while !r.done() {
        let tag = r.varint()?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;

        match (field, wire) {
            (1, 2) => {
                let len = r.varint()? as usize;
                out.secret = r.bytes(len)?.to_vec();
            }
            (2, 2) => {
                let len = r.varint()? as usize;
                out.name = String::from_utf8_lossy(r.bytes(len)?).to_string();
            }
            (3, 2) => {
                let len = r.varint()? as usize;
                out.issuer = String::from_utf8_lossy(r.bytes(len)?).to_string();
            }
            (4, 0) => out.algorithm = r.varint()?,
            (5, 0) => out.digits = r.varint()?,
            (6, 0) => out.kind = r.varint()?,
            (7, 0) => out.counter = r.varint()?,
            (_, w) => r.skip(w)?,
        }
    }
    Ok(out)
}

/// How many entries the exporting device split the vault into. Google emits
/// several QR codes when the account list is long.
#[derive(Debug, Clone, Copy)]
pub struct BatchInfo {
    pub size: i32,
    pub index: i32,
    pub id: i32,
}

pub struct MigrationResult {
    pub accounts: Vec<Account>,
    pub batch: BatchInfo,
    /// Entries that were present but could not be converted, with a reason.
    pub skipped: Vec<String>,
}

fn base64_decode_loose(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    B64.decode(trimmed)
        .or_else(|_| B64URL.decode(trimmed.trim_end_matches('=')))
        .map_err(|_| AppError::invalid("마이그레이션 데이터의 base64 디코딩에 실패했습니다."))
}

pub fn parse_migration(input: &str) -> Result<MigrationResult> {
    let trimmed = input.trim();
    if !trimmed
        .to_ascii_lowercase()
        .starts_with("otpauth-migration://")
    {
        return Err(AppError::invalid(
            "Google Authenticator 내보내기 QR(otpauth-migration://)이 아닙니다.",
        ));
    }

    let url =
        Url::parse(trimmed).map_err(|e| AppError::invalid(format!("URI 파싱 실패: {e}")))?;
    let data = url
        .query_pairs()
        .find(|(k, _)| k == "data")
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| AppError::invalid("data 파라미터가 없습니다."))?;

    let payload = base64_decode_loose(&data)?;

    let mut r = Reader::new(&payload);
    let mut accounts = Vec::new();
    let mut skipped = Vec::new();
    let mut batch = BatchInfo {
        size: 1,
        index: 0,
        id: 0,
    };

    while !r.done() {
        let tag = r.varint()?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;

        match (field, wire) {
            (1, 2) => {
                let len = r.varint()? as usize;
                let raw = r.bytes(len)?;
                let params = parse_otp_parameters(raw)?;
                match convert(params) {
                    Ok(account) => accounts.push(account),
                    Err(e) => skipped.push(e.to_string()),
                }
            }
            (3, 0) => batch.size = r.varint()? as i32,
            (4, 0) => batch.index = r.varint()? as i32,
            (5, 0) => batch.id = r.varint()? as i32,
            (_, w) => r.skip(w)?,
        }
    }

    if accounts.is_empty() && skipped.is_empty() {
        return Err(AppError::invalid("가져올 항목이 없습니다."));
    }

    Ok(MigrationResult {
        accounts,
        batch,
        skipped,
    })
}

fn convert(p: OtpParameters) -> Result<Account> {
    let name = if p.name.is_empty() && p.issuer.is_empty() {
        "(이름 없음)".to_string()
    } else {
        p.name.clone()
    };

    // Google sometimes stores the issuer only as a "Issuer:name" label prefix.
    let (issuer, label) = if !p.issuer.is_empty() {
        (p.issuer.clone(), name)
    } else if let Some((i, a)) = name.split_once(':') {
        (i.trim().to_string(), a.trim().to_string())
    } else {
        (String::new(), name)
    };

    let algorithm = match p.algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        4 => {
            return Err(AppError::invalid(format!(
                "{issuer} {label}: MD5는 지원하지 않습니다."
            )))
        }
        other => {
            return Err(AppError::invalid(format!(
                "{issuer} {label}: 알 수 없는 알고리즘({other})"
            )))
        }
    };

    let digits = match p.digits {
        0 | 1 => 6u8,
        2 => 8u8,
        other => {
            return Err(AppError::invalid(format!(
                "{issuer} {label}: 알 수 없는 자릿수({other})"
            )))
        }
    };

    let kind = match p.kind {
        1 => OtpKind::Hotp,
        0 | 2 => OtpKind::Totp,
        other => {
            return Err(AppError::invalid(format!(
                "{issuer} {label}: 알 수 없는 종류({other})"
            )))
        }
    };

    if p.secret.is_empty() {
        return Err(AppError::invalid(format!("{issuer} {label}: 시크릿이 비어 있습니다.")));
    }

    let mut account = Account {
        id: uuid::Uuid::new_v4().to_string(),
        kind,
        issuer,
        label,
        secret: base32_encode(&p.secret),
        algorithm,
        digits,
        period: 30,
        counter: p.counter,
        group: None,
        notes: None,
        favorite: false,
        color: None,
        created_at: 0,
        updated_at: 0,
        sort_index: 0,
    };
    account.sanitize()?;
    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-encode a MigrationPayload so the test does not depend on a fixture.
    fn encode_varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let mut byte = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
    }

    fn field(out: &mut Vec<u8>, number: u64, wire: u64) {
        encode_varint(out, (number << 3) | wire);
    }

    fn len_delimited(out: &mut Vec<u8>, number: u64, payload: &[u8]) {
        field(out, number, 2);
        encode_varint(out, payload.len() as u64);
        out.extend_from_slice(payload);
    }

    fn sample_payload() -> String {
        let mut params = Vec::new();
        len_delimited(&mut params, 1, b"\x0b\x16\xbe\x81\xa5\x5f\x9c\xbd\x8f\xef"); // secret
        len_delimited(&mut params, 2, b"me@example.com");
        len_delimited(&mut params, 3, b"GitHub");
        field(&mut params, 4, 0);
        encode_varint(&mut params, 1); // SHA1
        field(&mut params, 5, 0);
        encode_varint(&mut params, 1); // six digits
        field(&mut params, 6, 0);
        encode_varint(&mut params, 2); // TOTP

        let mut payload = Vec::new();
        len_delimited(&mut payload, 1, &params);
        field(&mut payload, 2, 0);
        encode_varint(&mut payload, 1); // version
        field(&mut payload, 3, 0);
        encode_varint(&mut payload, 1); // batch size
        field(&mut payload, 4, 0);
        encode_varint(&mut payload, 0); // batch index

        format!(
            "otpauth-migration://offline?data={}",
            urlencode(&B64.encode(payload))
        )
    }

    fn urlencode(s: &str) -> String {
        s.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
    }

    #[test]
    fn parses_a_single_entry_export() {
        let result = parse_migration(&sample_payload()).unwrap();
        assert_eq!(result.accounts.len(), 1);
        assert!(result.skipped.is_empty());

        let a = &result.accounts[0];
        assert_eq!(a.issuer, "GitHub");
        assert_eq!(a.label, "me@example.com");
        assert_eq!(a.kind, OtpKind::Totp);
        assert_eq!(a.digits, 6);
        assert_eq!(a.algorithm, Algorithm::Sha1);
        // The secret is re-encoded as base32 for storage.
        assert_eq!(a.secret, base32_encode(b"\x0b\x16\xbe\x81\xa5\x5f\x9c\xbd\x8f\xef"));

        assert_eq!(result.batch.size, 1);
        assert_eq!(result.batch.index, 0);
    }

    #[test]
    fn rejects_non_migration_uris() {
        assert!(parse_migration("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(parse_migration("otpauth-migration://offline").is_err());
    }

    #[test]
    fn rejects_corrupt_base64() {
        assert!(parse_migration("otpauth-migration://offline?data=!!!!").is_err());
    }

    #[test]
    fn truncated_payload_errors_instead_of_panicking() {
        let mut params = Vec::new();
        len_delimited(&mut params, 1, b"secret");
        let mut payload = Vec::new();
        len_delimited(&mut payload, 1, &params);
        payload.truncate(payload.len() - 2);

        let uri = format!(
            "otpauth-migration://offline?data={}",
            urlencode(&B64.encode(payload))
        );
        assert!(parse_migration(&uri).is_err());
    }
}
