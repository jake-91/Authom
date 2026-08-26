//! Parsing and generation of `otpauth://` URIs (the Key URI Format).

use crate::error::{AppError, Result};
use crate::otp::{Algorithm, OtpKind};
use crate::vault::Account;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use url::Url;

/// Everything outside the unreserved set gets encoded, which keeps the output
/// compatible with the strictest authenticator apps.
const URI_ESCAPE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'/')
    .add(b':')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

fn decode(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().to_string()
}

/// Parse one `otpauth://` URI into an unsaved account. `id`, timestamps and
/// sort order are left for the caller to assign.
pub fn parse_otpauth(input: &str) -> Result<Account> {
    let trimmed = input.trim();
    if !trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        return Err(AppError::invalid("otpauth:// URI가 아닙니다."));
    }

    let url = Url::parse(trimmed).map_err(|e| AppError::invalid(format!("URI 파싱 실패: {e}")))?;

    let kind = OtpKind::parse(url.host_str().unwrap_or_default())?;

    // Path is "/Issuer:Account" or just "/Account"; the separator may be a
    // literal or percent-encoded colon, and some issuers pad it with a space.
    let raw_label = decode(url.path().trim_start_matches('/'));
    let (label_issuer, account_name) = match raw_label.split_once(':') {
        Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
        None => (String::new(), raw_label.trim().to_string()),
    };

    let mut secret = String::new();
    let mut issuer = String::new();
    let mut algorithm = Algorithm::Sha1;
    let mut digits: u8 = 6;
    let mut period: u32 = 30;
    let mut counter: u64 = 0;

    for (key, value) in url.query_pairs() {
        match key.as_ref().to_ascii_lowercase().as_str() {
            "secret" => secret = value.split_whitespace().collect::<String>(),
            "issuer" => issuer = value.trim().to_string(),
            "algorithm" => algorithm = Algorithm::parse(&value)?,
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| AppError::invalid("digits 값이 숫자가 아닙니다."))?
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| AppError::invalid("period 값이 숫자가 아닙니다."))?
            }
            "counter" => {
                counter = value
                    .parse()
                    .map_err(|_| AppError::invalid("counter 값이 숫자가 아닙니다."))?
            }
            _ => {}
        }
    }

    if secret.is_empty() {
        return Err(AppError::invalid("URI에 secret 파라미터가 없습니다."));
    }

    // The query issuer wins when both are present, per the spec's guidance.
    let issuer = if issuer.is_empty() { label_issuer } else { issuer };

    let mut account = Account {
        id: uuid::Uuid::new_v4().to_string(),
        kind,
        issuer,
        label: account_name,
        secret,
        algorithm,
        digits,
        period,
        counter,
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

/// Render an account back to a Key URI. Steam entries are emitted as
/// `otpauth://steam/...`, which round-trips through this parser.
pub fn build_otpauth(account: &Account) -> String {
    let label = if account.issuer.is_empty() {
        utf8_percent_encode(&account.label, URI_ESCAPE).to_string()
    } else {
        format!(
            "{}:{}",
            utf8_percent_encode(&account.issuer, URI_ESCAPE),
            utf8_percent_encode(&account.label, URI_ESCAPE)
        )
    };

    let mut uri = format!(
        "otpauth://{}/{}?secret={}",
        account.kind.as_str(),
        label,
        account.secret
    );

    if !account.issuer.is_empty() {
        uri.push_str(&format!(
            "&issuer={}",
            utf8_percent_encode(&account.issuer, URI_ESCAPE)
        ));
    }

    if account.kind != OtpKind::Steam {
        uri.push_str(&format!("&algorithm={}", account.algorithm.as_str()));
        uri.push_str(&format!("&digits={}", account.digits));
        match account.kind {
            OtpKind::Hotp => uri.push_str(&format!("&counter={}", account.counter)),
            _ => uri.push_str(&format!("&period={}", account.period)),
        }
    }

    uri
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_google_uri() {
        let a = parse_otpauth(
            "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        )
        .unwrap();
        assert_eq!(a.kind, OtpKind::Totp);
        assert_eq!(a.issuer, "GitHub");
        assert_eq!(a.label, "me@example.com");
        assert_eq!(a.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(a.digits, 6);
        assert_eq!(a.period, 30);
    }

    #[test]
    fn honours_explicit_parameters() {
        let a = parse_otpauth(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(a.algorithm, Algorithm::Sha256);
        assert_eq!(a.digits, 8);
        assert_eq!(a.period, 60);
    }

    #[test]
    fn parses_hotp_counter() {
        let a = parse_otpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=42").unwrap();
        assert_eq!(a.kind, OtpKind::Hotp);
        assert_eq!(a.counter, 42);
    }

    #[test]
    fn decodes_percent_encoded_labels() {
        let a =
            parse_otpauth("otpauth://totp/ACME%20Co%3Ajohn%40acme.com?secret=JBSWY3DPEHPK3PXP")
                .unwrap();
        assert_eq!(a.issuer, "ACME Co");
        assert_eq!(a.label, "john@acme.com");
    }

    #[test]
    fn query_issuer_wins_over_label_issuer() {
        let a = parse_otpauth("otpauth://totp/Old:me?secret=JBSWY3DPEHPK3PXP&issuer=New").unwrap();
        assert_eq!(a.issuer, "New");
    }

    #[test]
    fn rejects_missing_secret_and_foreign_schemes() {
        assert!(parse_otpauth("otpauth://totp/x?issuer=y").is_err());
        assert!(parse_otpauth("https://example.com").is_err());
        assert!(parse_otpauth("otpauth://nope/x?secret=JBSWY3DPEHPK3PXP").is_err());
    }

    #[test]
    fn build_then_parse_round_trips() {
        let original = parse_otpauth(
            "otpauth://totp/ACME%20Co:john@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA512&digits=8&period=45",
        )
        .unwrap();

        let round_tripped = parse_otpauth(&build_otpauth(&original)).unwrap();
        assert_eq!(round_tripped.issuer, original.issuer);
        assert_eq!(round_tripped.label, original.label);
        assert_eq!(round_tripped.secret, original.secret);
        assert_eq!(round_tripped.algorithm, original.algorithm);
        assert_eq!(round_tripped.digits, original.digits);
        assert_eq!(round_tripped.period, original.period);
    }

    #[test]
    fn steam_round_trips() {
        let a = parse_otpauth("otpauth://steam/Steam:player?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(a.kind, OtpKind::Steam);
        assert_eq!(a.digits, 5);
        let back = parse_otpauth(&build_otpauth(&a)).unwrap();
        assert_eq!(back.kind, OtpKind::Steam);
    }
}
