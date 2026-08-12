use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeBoundaryError {
    BeforeUnixEpoch,
    Overflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EmailVerification {
    Verified,
    Unverified,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedExternalIdentity {
    pub(crate) provider: String,
    pub(crate) subject: String,
    pub(crate) email: Option<String>,
    pub(crate) email_verification: EmailVerification,
    pub(crate) display_name: Option<String>,
    pub(crate) picture_url: Option<String>,
}

impl NormalizedExternalIdentity {
    pub(crate) fn validate(&self) -> Result<(), InputBoundaryError> {
        validate_nonempty_max_bytes(&self.provider, PROVIDER_MAX_BYTES)?;
        validate_nonempty_max_bytes(&self.subject, SUBJECT_MAX_BYTES)
    }
}

pub(crate) fn generate_reference_value() -> Result<String, rand::Error> {
    let mut bytes = [0_u8; REFERENCE_VALUE_RANDOM_BYTES];
    OsRng.try_fill_bytes(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn reference_value_lookup(value: &str) -> String {
    sha256_digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn sha256_digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

pub(crate) fn sha256_digest_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.ct_eq(right).into()
}

pub(crate) fn pkce_s256_challenge(verifier: &str) -> Result<String, InputBoundaryError> {
    validate_ascii_byte_range(verifier, PKCE_VERIFIER_MIN_BYTES, PKCE_VERIFIER_MAX_BYTES)?;

    Ok(URL_SAFE_NO_PAD.encode(sha256_digest(verifier.as_bytes())))
}

pub(crate) fn unix_seconds(time: SystemTime) -> Result<u64, TimeBoundaryError> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| TimeBoundaryError::BeforeUnixEpoch)
}

pub(crate) fn checked_expires_at(now: u64, ttl_seconds: u64) -> Result<u64, TimeBoundaryError> {
    now.checked_add(ttl_seconds)
        .ok_or(TimeBoundaryError::Overflow)
}

pub(crate) fn is_unexpired(now: u64, expires_at: u64) -> bool {
    now < expires_at
}

pub(crate) fn validate_max_bytes(value: &str, max: usize) -> Result<(), InputBoundaryError> {
    if value.len() <= max {
        Ok(())
    } else {
        Err(InputBoundaryError::InvalidLength)
    }
}

fn validate_nonempty_max_bytes(value: &str, max: usize) -> Result<(), InputBoundaryError> {
    if value.is_empty() || value.len() > max {
        Err(InputBoundaryError::InvalidLength)
    } else {
        Ok(())
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
    fn normalized_external_identity_validates_provider_and_subject_boundaries() {
        let identity = NormalizedExternalIdentity {
            provider: "google".to_owned(),
            subject: "subject".to_owned(),
            email: Some("person@example.test".to_owned()),
            email_verification: EmailVerification::Verified,
            display_name: None,
            picture_url: None,
        };
        assert!(identity.validate().is_ok());

        for (provider, subject) in [
            ("", "subject"),
            (&"p".repeat(PROVIDER_MAX_BYTES + 1), "subject"),
            ("google", ""),
            ("google", &"s".repeat(SUBJECT_MAX_BYTES + 1)),
        ] {
            let identity = NormalizedExternalIdentity {
                provider: provider.to_owned(),
                subject: subject.to_owned(),
                email: None,
                email_verification: EmailVerification::Unknown,
                display_name: None,
                picture_url: None,
            };
            assert_eq!(identity.validate(), Err(InputBoundaryError::InvalidLength));
        }
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

    #[test]
    fn sha256_digest_matches_known_value_and_is_stable() {
        let abc_digest = sha256_digest(b"abc");

        assert_eq!(
            abc_digest,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert_eq!(abc_digest, sha256_digest(b"abc"));
        assert_ne!(abc_digest, sha256_digest(b"abd"));
    }

    #[test]
    fn sha256_digest_comparison_handles_equal_and_different_positions() {
        let digest = sha256_digest(b"abc");
        let mut first_byte_differs = digest;
        first_byte_differs[0] ^= 1;
        let mut last_byte_differs = digest;
        last_byte_differs[31] ^= 1;

        assert!(sha256_digest_eq(&digest, &digest));
        assert!(!sha256_digest_eq(&digest, &sha256_digest(b"abd")));
        assert!(!sha256_digest_eq(&digest, &first_byte_differs));
        assert!(!sha256_digest_eq(&digest, &last_byte_differs));
    }

    #[test]
    fn pkce_s256_challenge_matches_rfc_7636_and_validates_boundaries() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_s256_challenge(verifier).expect("RFC verifier is valid");

        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert_eq!(challenge.len(), PKCE_CHALLENGE_BYTES);
        assert!(!challenge.contains('='));
        assert_eq!(
            pkce_s256_challenge(&"a".repeat(42)),
            Err(InputBoundaryError::InvalidLength)
        );
        assert_eq!(
            pkce_s256_challenge(&"a".repeat(129)),
            Err(InputBoundaryError::InvalidLength)
        );
        assert_eq!(
            pkce_s256_challenge(&"あ".repeat(15)),
            Err(InputBoundaryError::InvalidAsciiFormat)
        );
    }

    #[test]
    fn unix_seconds_converts_epoch_seconds_and_rejects_before_epoch() {
        use std::time::Duration;

        assert_eq!(unix_seconds(UNIX_EPOCH), Ok(0));
        assert_eq!(unix_seconds(UNIX_EPOCH + Duration::from_secs(1)), Ok(1));
        assert_eq!(
            unix_seconds(UNIX_EPOCH + Duration::from_millis(1_999)),
            Ok(1)
        );
        assert_eq!(
            unix_seconds(UNIX_EPOCH - Duration::from_secs(1)),
            Err(TimeBoundaryError::BeforeUnixEpoch)
        );
    }

    #[test]
    fn checked_expires_at_rejects_overflow() {
        assert_eq!(checked_expires_at(100, 60), Ok(160));
        assert_eq!(checked_expires_at(100, 0), Ok(100));
        assert_eq!(checked_expires_at(u64::MAX - 1, 1), Ok(u64::MAX));
        assert_eq!(
            checked_expires_at(u64::MAX, 1),
            Err(TimeBoundaryError::Overflow)
        );
    }

    #[test]
    fn unexpired_requires_now_to_be_strictly_before_expiry() {
        assert!(is_unexpired(9, 10));
        assert!(!is_unexpired(10, 10));
        assert!(!is_unexpired(11, 10));
    }
}
