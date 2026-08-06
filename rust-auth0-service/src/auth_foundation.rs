use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

pub(crate) const SERVICE_ID_MAX_BYTES: usize = 64;
pub(crate) const SERVICE_STATE_MAX_BYTES: usize = 256;
const REFERENCE_VALUE_ENCODED_BYTES: usize = 43;

pub(crate) const OAUTH_STATE_BYTES: usize = REFERENCE_VALUE_ENCODED_BYTES;
pub(crate) const OAUTH_CODE_MAX_BYTES: usize = 4_096;
pub(crate) const HANDOFF_CODE_BYTES: usize = REFERENCE_VALUE_ENCODED_BYTES;
pub(crate) const PKCE_VERIFIER_MIN_BYTES: usize = 43;
pub(crate) const PKCE_VERIFIER_MAX_BYTES: usize = 128;
pub(crate) const PKCE_CHALLENGE_BYTES: usize = REFERENCE_VALUE_ENCODED_BYTES;
pub(crate) const PROVIDER_MAX_BYTES: usize = 16;
pub(crate) const SUBJECT_MAX_BYTES: usize = 255;
pub(crate) const POST_LOGIN_PATH_MAX_BYTES: usize = 2_048;
pub(crate) const CSRF_VALUE_BYTES: usize = REFERENCE_VALUE_ENCODED_BYTES;
pub(crate) const AUTHORIZATION_HEADER_MAX_BYTES: usize = 8_192;
pub(crate) const CALLBACK_URI_MAX_BYTES: usize = 2_048;
pub(crate) const LOGOUT_RETURN_URI_MAX_BYTES: usize = 2_048;
pub(crate) const HTTP_BODY_MAX_BYTES: usize = 16_384;

const REFERENCE_VALUE_RANDOM_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputBoundaryError {
    InvalidLength,
    InvalidAsciiFormat,
}

pub(crate) fn generate_reference_value() -> Result<String, rand::Error> {
    let mut bytes = [0_u8; REFERENCE_VALUE_RANDOM_BYTES];
    OsRng.try_fill_bytes(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn reference_value_lookup(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{digest:x}")
}

pub(crate) fn validate_max_bytes(value: &str, max: usize) -> Result<(), InputBoundaryError> {
    if value.len() <= max {
        Ok(())
    } else {
        Err(InputBoundaryError::InvalidLength)
    }
}

pub(crate) fn validate_ascii_byte_range(
    value: &str,
    min: usize,
    max: usize,
) -> Result<(), InputBoundaryError> {
    if !(min..=max).contains(&value.len()) {
        return Err(InputBoundaryError::InvalidLength);
    }

    if value.is_ascii() {
        Ok(())
    } else {
        Err(InputBoundaryError::InvalidAsciiFormat)
    }
}

pub(crate) fn validate_fixed_reference_value(value: &str) -> Result<(), InputBoundaryError> {
    if value.len() != OAUTH_STATE_BYTES {
        return Err(InputBoundaryError::InvalidLength);
    }

    if value.bytes().all(is_base64url_no_pad_byte) {
        Ok(())
    } else {
        Err(InputBoundaryError::InvalidAsciiFormat)
    }
}

pub(crate) fn validate_service_id(value: &str) -> Result<(), InputBoundaryError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > SERVICE_ID_MAX_BYTES {
        return Err(InputBoundaryError::InvalidLength);
    }

    if !matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
        || !bytes[1..].iter().copied().all(is_service_id_rest_byte)
    {
        return Err(InputBoundaryError::InvalidAsciiFormat);
    }

    Ok(())
}

fn is_base64url_no_pad_byte(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

fn is_service_id_rest_byte(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-')
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn reference_values_are_base64url_without_padding_and_not_reused() {
        let values: Vec<String> = (0..8)
            .map(|_| generate_reference_value().expect("OS random source must be available"))
            .collect();

        assert!(values.iter().all(|value| value.len() == OAUTH_STATE_BYTES));
        assert!(values
            .iter()
            .all(|value| validate_fixed_reference_value(value).is_ok()));
        assert!(values.iter().all(|value| !value.contains('=')));
        assert_eq!(values.iter().collect::<HashSet<_>>().len(), values.len());
    }

    #[test]
    fn lookup_is_lowercase_sha256_hex() {
        let lookup = reference_value_lookup("abc");
        assert_eq!(lookup.len(), 64);
        assert!(lookup
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));
        assert_eq!(
            lookup,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn maximum_length_uses_utf8_bytes() {
        assert!(validate_max_bytes("abcd", 4).is_ok());
        assert_eq!(
            validate_max_bytes("abcde", 4),
            Err(InputBoundaryError::InvalidLength)
        );
        assert!(validate_max_bytes("あ", 3).is_ok());
        assert_eq!(
            validate_max_bytes("あ", 2),
            Err(InputBoundaryError::InvalidLength)
        );
    }

    #[test]
    fn pkce_verifier_length_range_is_inclusive() {
        for (length, expected) in [(42, false), (43, true), (128, true), (129, false)] {
            assert_eq!(
                validate_ascii_byte_range(
                    &"a".repeat(length),
                    PKCE_VERIFIER_MIN_BYTES,
                    PKCE_VERIFIER_MAX_BYTES
                )
                .is_ok(),
                expected
            );
        }

        let unicode = "あ".repeat(15);
        assert_eq!(
            validate_ascii_byte_range(&unicode, PKCE_VERIFIER_MIN_BYTES, PKCE_VERIFIER_MAX_BYTES,),
            Err(InputBoundaryError::InvalidAsciiFormat)
        );
    }

    #[test]
    fn fixed_reference_value_requires_43_base64url_characters() {
        assert!(validate_fixed_reference_value(&"A".repeat(43)).is_ok());
        assert!(matches!(
            validate_fixed_reference_value(&"A".repeat(42)),
            Err(InputBoundaryError::InvalidLength)
        ));
        assert!(matches!(
            validate_fixed_reference_value(&"A".repeat(44)),
            Err(InputBoundaryError::InvalidLength)
        ));
        for invalid in ['=', '+', '/', ' '] {
            let value = format!("{}{}", "A".repeat(42), invalid);
            assert_eq!(
                validate_fixed_reference_value(&value),
                Err(InputBoundaryError::InvalidAsciiFormat)
            );
        }
        assert_eq!(
            validate_fixed_reference_value(&format!("{}あ", "A".repeat(40))),
            Err(InputBoundaryError::InvalidAsciiFormat)
        );
    }

    #[test]
    fn service_id_accepts_specified_ascii_format() {
        let valid = [
            "a",
            "0",
            "portal-prod",
            "portal_dev",
            "a0_b-c",
            "a_______________________________________________________________",
        ];
        assert!(valid.iter().all(|value| validate_service_id(value).is_ok()));
    }

    #[test]
    fn service_id_rejects_invalid_values() {
        let invalid = [
            "",
            "a________________________________________________________________",
            "Portal",
            "_portal",
            "-portal",
            "portal:prod",
            "portal prod",
            "portal.prod",
            "portalあ",
            "portal\nprod",
        ];
        assert!(invalid
            .iter()
            .all(|value| validate_service_id(value).is_err()));
    }
}
