use crate::auth_foundation::{is_unexpired, reference_value_lookup};
use redis::aio::MultiplexedConnection;
use std::collections::BTreeMap;

pub(crate) const EXTERNAL_AUTH_TRANSACTION_TTL_SECONDS: u64 = 600;
pub(crate) const COMMON_SESSION_TTL_SECONDS: u64 = 28_800;
pub(crate) const AUTHENTICATION_HANDOFF_TTL_SECONDS: u64 = 120;
pub(crate) const COMMON_LOGOUT_TRANSACTION_TTL_SECONDS: u64 = 600;

const EXTERNAL_FIELDS: [&str; 8] = [
    "service_id",
    "service_state",
    "handoff_code_challenge",
    "provider",
    "provider_verification_data",
    "created_at",
    "expires_at",
    "status",
];
const SESSION_FIELDS: [&str; 4] = [
    "internal_user_id",
    "authenticated_at",
    "created_at",
    "expires_at",
];
const HANDOFF_FIELDS: [&str; 8] = [
    "service_id",
    "internal_user_id",
    "common_session_lookup",
    "code_challenge",
    "authenticated_at",
    "issued_at",
    "expires_at",
    "status",
];
const LOGOUT_FIELDS: [&str; 6] = [
    "service_id",
    "logout_return_uri",
    "csrf_lookup",
    "created_at",
    "expires_at",
    "status",
];

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ExternalAuthTransaction {
    pub(crate) service_id: String,
    pub(crate) service_state: String,
    pub(crate) handoff_code_challenge: String,
    pub(crate) provider: String,
    pub(crate) provider_verification_data: String,
    pub(crate) created_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) status: ExternalStatus,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CommonSession {
    pub(crate) internal_user_id: i32,
    pub(crate) authenticated_at: u64,
    pub(crate) created_at: u64,
    pub(crate) expires_at: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuthenticationHandoff {
    pub(crate) service_id: String,
    pub(crate) internal_user_id: i32,
    pub(crate) common_session_lookup: String,
    pub(crate) code_challenge: String,
    pub(crate) authenticated_at: u64,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) status: UsageStatus,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CommonLogoutTransaction {
    pub(crate) service_id: String,
    pub(crate) logout_return_uri: String,
    pub(crate) csrf_lookup: String,
    pub(crate) created_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) status: UsageStatus,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExternalStatus {
    Waiting,
    Processing,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UsageStatus {
    Unused,
    Used,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RedisStateError {
    NotFound,
    Expired,
    RedisFailure,
    InvalidStoredState,
}

pub(crate) fn external_key(reference: &str) -> String {
    format!("auth:external:{}", reference_value_lookup(reference))
}

pub(crate) fn session_key(reference: &str) -> String {
    format!("auth:session:{}", reference_value_lookup(reference))
}

pub(crate) fn handoff_key(reference: &str) -> String {
    format!("auth:handoff:{}", reference_value_lookup(reference))
}

pub(crate) fn logout_key(reference: &str) -> String {
    format!("auth:logout:{}", reference_value_lookup(reference))
}

pub(crate) async fn write_external(
    connection: &mut MultiplexedConnection,
    reference: &str,
    state: &ExternalAuthTransaction,
    now: u64,
) -> Result<(), RedisStateError> {
    write_state(
        connection,
        external_key(reference),
        encode_external(state),
        state.expires_at,
        now,
    )
    .await
}

pub(crate) async fn write_session(
    connection: &mut MultiplexedConnection,
    reference: &str,
    state: &CommonSession,
    now: u64,
) -> Result<(), RedisStateError> {
    write_state(
        connection,
        session_key(reference),
        encode_session(state),
        state.expires_at,
        now,
    )
    .await
}

pub(crate) async fn write_handoff(
    connection: &mut MultiplexedConnection,
    reference: &str,
    state: &AuthenticationHandoff,
    now: u64,
) -> Result<(), RedisStateError> {
    write_state(
        connection,
        handoff_key(reference),
        encode_handoff(state),
        state.expires_at,
        now,
    )
    .await
}

pub(crate) async fn write_logout(
    connection: &mut MultiplexedConnection,
    reference: &str,
    state: &CommonLogoutTransaction,
    now: u64,
) -> Result<(), RedisStateError> {
    write_state(
        connection,
        logout_key(reference),
        encode_logout(state),
        state.expires_at,
        now,
    )
    .await
}

pub(crate) async fn read_external(
    connection: &mut MultiplexedConnection,
    reference: &str,
    now: u64,
) -> Result<ExternalAuthTransaction, RedisStateError> {
    let key = external_key(reference);
    let fields = read_fields(connection, &key).await?;
    let state = decode_external(&fields)?;
    expire_if_needed(connection, &key, state.expires_at, now).await?;
    Ok(state)
}

pub(crate) async fn read_session(
    connection: &mut MultiplexedConnection,
    reference: &str,
    now: u64,
) -> Result<CommonSession, RedisStateError> {
    let key = session_key(reference);
    let fields = read_fields(connection, &key).await?;
    let state = decode_session(&fields)?;
    expire_if_needed(connection, &key, state.expires_at, now).await?;
    Ok(state)
}

pub(crate) async fn read_handoff(
    connection: &mut MultiplexedConnection,
    reference: &str,
    now: u64,
) -> Result<AuthenticationHandoff, RedisStateError> {
    let key = handoff_key(reference);
    let fields = read_fields(connection, &key).await?;
    let state = decode_handoff(&fields)?;
    expire_if_needed(connection, &key, state.expires_at, now).await?;
    Ok(state)
}

pub(crate) async fn read_logout(
    connection: &mut MultiplexedConnection,
    reference: &str,
    now: u64,
) -> Result<CommonLogoutTransaction, RedisStateError> {
    let key = logout_key(reference);
    let fields = read_fields(connection, &key).await?;
    let state = decode_logout(&fields)?;
    expire_if_needed(connection, &key, state.expires_at, now).await?;
    Ok(state)
}

async fn write_state(
    connection: &mut MultiplexedConnection,
    key: String,
    fields: Vec<(&'static str, String)>,
    expires_at: u64,
    now: u64,
) -> Result<(), RedisStateError> {
    if !is_unexpired(now, expires_at) {
        return Err(RedisStateError::Expired);
    }

    let mut hset = redis::cmd("HSET");
    hset.arg(&key);
    for (field, value) in fields {
        hset.arg(field).arg(value);
    }
    hset.query_async::<()>(connection)
        .await
        .map_err(|_| RedisStateError::RedisFailure)?;

    redis::cmd("EXPIREAT")
        .arg(&key)
        .arg(expires_at)
        .query_async::<()>(connection)
        .await
        .map_err(|_| RedisStateError::RedisFailure)
}

async fn read_fields(
    connection: &mut MultiplexedConnection,
    key: &str,
) -> Result<BTreeMap<String, String>, RedisStateError> {
    let pairs: Vec<(String, String)> = redis::cmd("HGETALL")
        .arg(key)
        .query_async(connection)
        .await
        .map_err(|_| RedisStateError::RedisFailure)?;
    if pairs.is_empty() {
        return Err(RedisStateError::NotFound);
    }
    Ok(pairs.into_iter().collect())
}

async fn expire_if_needed(
    connection: &mut MultiplexedConnection,
    key: &str,
    expires_at: u64,
    now: u64,
) -> Result<(), RedisStateError> {
    if is_unexpired(now, expires_at) {
        return Ok(());
    }

    redis::cmd("DEL")
        .arg(key)
        .query_async::<()>(connection)
        .await
        .map_err(|_| RedisStateError::RedisFailure)?;
    Err(RedisStateError::Expired)
}

fn encode_external(state: &ExternalAuthTransaction) -> Vec<(&'static str, String)> {
    vec![
        ("service_id", state.service_id.clone()),
        ("service_state", state.service_state.clone()),
        (
            "handoff_code_challenge",
            state.handoff_code_challenge.clone(),
        ),
        ("provider", state.provider.clone()),
        (
            "provider_verification_data",
            state.provider_verification_data.clone(),
        ),
        ("created_at", state.created_at.to_string()),
        ("expires_at", state.expires_at.to_string()),
        ("status", external_status_value(&state.status).to_owned()),
    ]
}

fn encode_session(state: &CommonSession) -> Vec<(&'static str, String)> {
    vec![
        ("internal_user_id", state.internal_user_id.to_string()),
        ("authenticated_at", state.authenticated_at.to_string()),
        ("created_at", state.created_at.to_string()),
        ("expires_at", state.expires_at.to_string()),
    ]
}

fn encode_handoff(state: &AuthenticationHandoff) -> Vec<(&'static str, String)> {
    vec![
        ("service_id", state.service_id.clone()),
        ("internal_user_id", state.internal_user_id.to_string()),
        ("common_session_lookup", state.common_session_lookup.clone()),
        ("code_challenge", state.code_challenge.clone()),
        ("authenticated_at", state.authenticated_at.to_string()),
        ("issued_at", state.issued_at.to_string()),
        ("expires_at", state.expires_at.to_string()),
        ("status", usage_status_value(&state.status).to_owned()),
    ]
}

fn encode_logout(state: &CommonLogoutTransaction) -> Vec<(&'static str, String)> {
    vec![
        ("service_id", state.service_id.clone()),
        ("logout_return_uri", state.logout_return_uri.clone()),
        ("csrf_lookup", state.csrf_lookup.clone()),
        ("created_at", state.created_at.to_string()),
        ("expires_at", state.expires_at.to_string()),
        ("status", usage_status_value(&state.status).to_owned()),
    ]
}

fn decode_external(
    fields: &BTreeMap<String, String>,
) -> Result<ExternalAuthTransaction, RedisStateError> {
    validate_field_names(fields, &EXTERNAL_FIELDS)?;
    Ok(ExternalAuthTransaction {
        service_id: required_string(fields, "service_id")?.to_owned(),
        service_state: required_string(fields, "service_state")?.to_owned(),
        handoff_code_challenge: required_string(fields, "handoff_code_challenge")?.to_owned(),
        provider: required_string(fields, "provider")?.to_owned(),
        provider_verification_data: required_string(fields, "provider_verification_data")?
            .to_owned(),
        created_at: parse_u64(fields, "created_at")?,
        expires_at: parse_u64(fields, "expires_at")?,
        status: decode_external_status(required_string(fields, "status")?)?,
    })
}

fn decode_session(fields: &BTreeMap<String, String>) -> Result<CommonSession, RedisStateError> {
    validate_field_names(fields, &SESSION_FIELDS)?;
    Ok(CommonSession {
        internal_user_id: parse_i32(fields, "internal_user_id")?,
        authenticated_at: parse_u64(fields, "authenticated_at")?,
        created_at: parse_u64(fields, "created_at")?,
        expires_at: parse_u64(fields, "expires_at")?,
    })
}

fn decode_handoff(
    fields: &BTreeMap<String, String>,
) -> Result<AuthenticationHandoff, RedisStateError> {
    validate_field_names(fields, &HANDOFF_FIELDS)?;
    let common_session_lookup = required_string(fields, "common_session_lookup")?;
    if !is_lookup(common_session_lookup) {
        return Err(RedisStateError::InvalidStoredState);
    }
    Ok(AuthenticationHandoff {
        service_id: required_string(fields, "service_id")?.to_owned(),
        internal_user_id: parse_i32(fields, "internal_user_id")?,
        common_session_lookup: common_session_lookup.to_owned(),
        code_challenge: required_string(fields, "code_challenge")?.to_owned(),
        authenticated_at: parse_u64(fields, "authenticated_at")?,
        issued_at: parse_u64(fields, "issued_at")?,
        expires_at: parse_u64(fields, "expires_at")?,
        status: decode_usage_status(required_string(fields, "status")?)?,
    })
}

fn decode_logout(
    fields: &BTreeMap<String, String>,
) -> Result<CommonLogoutTransaction, RedisStateError> {
    validate_field_names(fields, &LOGOUT_FIELDS)?;
    let csrf_lookup = required_string(fields, "csrf_lookup")?;
    if !is_lookup(csrf_lookup) {
        return Err(RedisStateError::InvalidStoredState);
    }
    Ok(CommonLogoutTransaction {
        service_id: required_string(fields, "service_id")?.to_owned(),
        logout_return_uri: required_string(fields, "logout_return_uri")?.to_owned(),
        csrf_lookup: csrf_lookup.to_owned(),
        created_at: parse_u64(fields, "created_at")?,
        expires_at: parse_u64(fields, "expires_at")?,
        status: decode_usage_status(required_string(fields, "status")?)?,
    })
}

fn validate_field_names(
    fields: &BTreeMap<String, String>,
    expected: &[&str],
) -> Result<(), RedisStateError> {
    if fields.len() != expected.len() || expected.iter().any(|field| !fields.contains_key(*field)) {
        return Err(RedisStateError::InvalidStoredState);
    }
    Ok(())
}

fn required_string<'a>(
    fields: &'a BTreeMap<String, String>,
    field: &str,
) -> Result<&'a str, RedisStateError> {
    fields
        .get(field)
        .map(String::as_str)
        .ok_or(RedisStateError::InvalidStoredState)
}

fn parse_u64(fields: &BTreeMap<String, String>, field: &str) -> Result<u64, RedisStateError> {
    required_string(fields, field)?
        .parse()
        .map_err(|_| RedisStateError::InvalidStoredState)
}

fn parse_i32(fields: &BTreeMap<String, String>, field: &str) -> Result<i32, RedisStateError> {
    required_string(fields, field)?
        .parse()
        .map_err(|_| RedisStateError::InvalidStoredState)
}

fn external_status_value(status: &ExternalStatus) -> &'static str {
    match status {
        ExternalStatus::Waiting => "waiting",
        ExternalStatus::Processing => "processing",
    }
}

fn decode_external_status(value: &str) -> Result<ExternalStatus, RedisStateError> {
    match value {
        "waiting" => Ok(ExternalStatus::Waiting),
        "processing" => Ok(ExternalStatus::Processing),
        _ => Err(RedisStateError::InvalidStoredState),
    }
}

fn usage_status_value(status: &UsageStatus) -> &'static str {
    match status {
        UsageStatus::Unused => "unused",
        UsageStatus::Used => "used",
    }
}

fn decode_usage_status(value: &str) -> Result<UsageStatus, RedisStateError> {
    match value {
        "unused" => Ok(UsageStatus::Unused),
        "used" => Ok(UsageStatus::Used),
        _ => Err(RedisStateError::InvalidStoredState),
    }
}

fn is_lookup(value: &str) -> bool {
    value.len() == 64
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn lookup() -> String {
        reference_value_lookup("common-session-reference")
    }

    fn external() -> ExternalAuthTransaction {
        ExternalAuthTransaction {
            service_id: "service".to_owned(),
            service_state: "state".to_owned(),
            handoff_code_challenge: "challenge".to_owned(),
            provider: "google".to_owned(),
            provider_verification_data: "verification".to_owned(),
            created_at: 100,
            expires_at: 700,
            status: ExternalStatus::Waiting,
        }
    }

    fn session() -> CommonSession {
        CommonSession {
            internal_user_id: 42,
            authenticated_at: 101,
            created_at: 100,
            expires_at: 28_900,
        }
    }

    fn handoff(status: UsageStatus) -> AuthenticationHandoff {
        AuthenticationHandoff {
            service_id: "service".to_owned(),
            internal_user_id: 42,
            common_session_lookup: lookup(),
            code_challenge: "challenge".to_owned(),
            authenticated_at: 101,
            issued_at: 102,
            expires_at: 222,
            status,
        }
    }

    fn logout() -> CommonLogoutTransaction {
        CommonLogoutTransaction {
            service_id: "service".to_owned(),
            logout_return_uri: "https://service.example/logout".to_owned(),
            csrf_lookup: reference_value_lookup("csrf-token"),
            created_at: 100,
            expires_at: 700,
            status: UsageStatus::Unused,
        }
    }

    fn fields(values: Vec<(&'static str, String)>) -> BTreeMap<String, String> {
        values
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect()
    }

    #[test]
    fn keys_use_only_the_four_hashed_key_families() {
        let reference = "plain-reference-must-not-appear";
        for (prefix, key) in [
            ("auth:external:", external_key(reference)),
            ("auth:session:", session_key(reference)),
            ("auth:handoff:", handoff_key(reference)),
            ("auth:logout:", logout_key(reference)),
        ] {
            assert!(key.starts_with(prefix));
            assert!(!key.contains(reference));
            let lookup = key.strip_prefix(prefix).unwrap();
            assert_eq!(lookup.len(), 64);
            assert!(is_lookup(lookup));
        }
    }

    #[test]
    fn all_states_encode_decode_with_exact_fields() {
        let external_state = external();
        let session_state = session();
        let handoff_state = handoff(UsageStatus::Used);
        let logout_state = logout();

        assert_eq!(
            decode_external(&fields(encode_external(&external_state))),
            Ok(external_state)
        );
        assert_eq!(
            decode_session(&fields(encode_session(&session_state))),
            Ok(session_state)
        );
        assert_eq!(
            decode_handoff(&fields(encode_handoff(&handoff_state))),
            Ok(handoff_state)
        );
        assert_eq!(
            decode_logout(&fields(encode_logout(&logout_state))),
            Ok(logout_state)
        );

        assert_eq!(encode_external(&external()).len(), EXTERNAL_FIELDS.len());
        assert_eq!(encode_session(&session()).len(), SESSION_FIELDS.len());
        assert_eq!(
            encode_handoff(&handoff(UsageStatus::Unused)).len(),
            HANDOFF_FIELDS.len()
        );
        assert_eq!(encode_logout(&logout()).len(), LOGOUT_FIELDS.len());
    }

    #[test]
    fn decode_rejects_missing_unknown_and_invalid_numeric_fields() {
        let mut missing = fields(encode_external(&external()));
        missing.remove("provider");
        assert_eq!(
            decode_external(&missing),
            Err(RedisStateError::InvalidStoredState)
        );

        let mut unknown = fields(encode_session(&session()));
        unknown.insert("unexpected".to_owned(), "value".to_owned());
        assert_eq!(
            decode_session(&unknown),
            Err(RedisStateError::InvalidStoredState)
        );

        let mut invalid_numeric = fields(encode_session(&session()));
        invalid_numeric.insert("internal_user_id".to_owned(), "not-a-number".to_owned());
        assert_eq!(
            decode_session(&invalid_numeric),
            Err(RedisStateError::InvalidStoredState)
        );
    }

    #[test]
    fn decode_rejects_unknown_status_and_invalid_lookups() {
        let mut external_unknown_status = fields(encode_external(&external()));
        external_unknown_status.insert("status".to_owned(), "other".to_owned());
        assert_eq!(
            decode_external(&external_unknown_status),
            Err(RedisStateError::InvalidStoredState)
        );

        let mut handoff_unknown_status = fields(encode_handoff(&handoff(UsageStatus::Unused)));
        handoff_unknown_status.insert("status".to_owned(), "other".to_owned());
        assert_eq!(
            decode_handoff(&handoff_unknown_status),
            Err(RedisStateError::InvalidStoredState)
        );

        let mut logout_unknown_status = fields(encode_logout(&logout()));
        logout_unknown_status.insert("status".to_owned(), "other".to_owned());
        assert_eq!(
            decode_logout(&logout_unknown_status),
            Err(RedisStateError::InvalidStoredState)
        );

        let mut invalid_session_lookup = fields(encode_handoff(&handoff(UsageStatus::Unused)));
        invalid_session_lookup.insert("common_session_lookup".to_owned(), "ABC".to_owned());
        assert_eq!(
            decode_handoff(&invalid_session_lookup),
            Err(RedisStateError::InvalidStoredState)
        );

        let mut invalid_csrf_lookup = fields(encode_logout(&logout()));
        invalid_csrf_lookup.insert("csrf_lookup".to_owned(), "g".repeat(64));
        assert_eq!(
            decode_logout(&invalid_csrf_lookup),
            Err(RedisStateError::InvalidStoredState)
        );
    }

    #[test]
    fn expiry_requires_now_to_be_strictly_before_expires_at() {
        assert!(is_unexpired(9, 10));
        assert!(!is_unexpired(10, 10));
        assert!(!is_unexpired(11, 10));
    }

    #[test]
    fn ttl_constants_match_the_storage_contract() {
        assert_eq!(EXTERNAL_AUTH_TRANSACTION_TTL_SECONDS, 600);
        assert_eq!(COMMON_SESSION_TTL_SECONDS, 28_800);
        assert_eq!(AUTHENTICATION_HANDOFF_TTL_SECONDS, 120);
        assert_eq!(COMMON_LOGOUT_TRANSACTION_TTL_SECONDS, 600);
    }

    #[actix_web::test]
    #[ignore = "requires AUTH_FOUNDATION_TEST_REDIS_URL and a disposable Redis 7 instance"]
    async fn redis_hash_state_integration() {
        let redis_url = std::env::var("AUTH_FOUNDATION_TEST_REDIS_URL")
            .expect("AUTH_FOUNDATION_TEST_REDIS_URL must be set for this ignored test");
        let client = redis::Client::open(redis_url).expect("test Redis URL must be valid");
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("test Redis must be reachable");
        let now = 2_000_000_000;
        let external_reference = "t07-integration-external";
        let session_reference = "t07-integration-session";
        let handoff_reference = "t07-integration-handoff";
        let logout_reference = "t07-integration-logout";
        let keys = [
            external_key(external_reference),
            session_key(session_reference),
            handoff_key(handoff_reference),
            logout_key(logout_reference),
        ];
        for key in &keys {
            let _: () = redis::cmd("DEL")
                .arg(key)
                .query_async(&mut connection)
                .await
                .unwrap();
        }

        let mut external_state = external();
        external_state.expires_at = now + EXTERNAL_AUTH_TRANSACTION_TTL_SECONDS;
        let mut session_state = session();
        session_state.expires_at = now + COMMON_SESSION_TTL_SECONDS;
        let mut handoff_state = handoff(UsageStatus::Used);
        handoff_state.expires_at = now + AUTHENTICATION_HANDOFF_TTL_SECONDS;
        let mut logout_state = logout();
        logout_state.expires_at = now + COMMON_LOGOUT_TRANSACTION_TTL_SECONDS;

        write_external(&mut connection, external_reference, &external_state, now)
            .await
            .unwrap();
        write_session(&mut connection, session_reference, &session_state, now)
            .await
            .unwrap();
        write_handoff(&mut connection, handoff_reference, &handoff_state, now)
            .await
            .unwrap();
        write_logout(&mut connection, logout_reference, &logout_state, now)
            .await
            .unwrap();

        let expected_field_sets = [
            EXTERNAL_FIELDS.as_slice(),
            SESSION_FIELDS.as_slice(),
            HANDOFF_FIELDS.as_slice(),
            LOGOUT_FIELDS.as_slice(),
        ];
        for (key, expected_fields) in keys.iter().zip(expected_field_sets) {
            let key_type: String = redis::cmd("TYPE")
                .arg(key)
                .query_async(&mut connection)
                .await
                .unwrap();
            assert_eq!(key_type, "hash");
            let mut actual_fields: Vec<String> = redis::cmd("HKEYS")
                .arg(key)
                .query_async(&mut connection)
                .await
                .unwrap();
            actual_fields.sort();
            let mut expected_fields: Vec<String> = expected_fields
                .iter()
                .map(|field| (*field).to_owned())
                .collect();
            expected_fields.sort();
            assert_eq!(actual_fields, expected_fields);
            let expires_at: u64 = redis::cmd("HGET")
                .arg(key)
                .arg("expires_at")
                .query_async(&mut connection)
                .await
                .unwrap();
            let expiretime: i64 = redis::cmd("EXPIRETIME")
                .arg(key)
                .query_async(&mut connection)
                .await
                .unwrap();
            assert_eq!(expiretime, expires_at as i64);
        }

        assert_eq!(
            read_external(&mut connection, external_reference, now).await,
            Ok(external_state)
        );
        assert_eq!(
            read_session(&mut connection, session_reference, now).await,
            Ok(session_state)
        );
        assert_eq!(
            read_handoff(&mut connection, handoff_reference, now).await,
            Ok(handoff_state)
        );
        assert_eq!(
            read_logout(&mut connection, logout_reference, now).await,
            Ok(logout_state)
        );
        assert_eq!(
            read_session(&mut connection, "missing", now).await,
            Err(RedisStateError::NotFound)
        );

        let expired_reference = "t07-integration-expired";
        let expired_key = external_key(expired_reference);
        let mut expired = external();
        expired.expires_at = now - 1;
        let _: () = redis::cmd("HSET")
            .arg(&expired_key)
            .arg("service_id")
            .arg(&expired.service_id)
            .arg("service_state")
            .arg(&expired.service_state)
            .arg("handoff_code_challenge")
            .arg(&expired.handoff_code_challenge)
            .arg("provider")
            .arg(&expired.provider)
            .arg("provider_verification_data")
            .arg(&expired.provider_verification_data)
            .arg("created_at")
            .arg(expired.created_at)
            .arg("expires_at")
            .arg(expired.expires_at)
            .arg("status")
            .arg("waiting")
            .query_async(&mut connection)
            .await
            .unwrap();
        redis::cmd("EXPIREAT")
            .arg(&expired_key)
            .arg(now + 60)
            .query_async::<()>(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            read_external(&mut connection, expired_reference, now).await,
            Err(RedisStateError::Expired)
        );
        let exists: bool = redis::cmd("EXISTS")
            .arg(&expired_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(!exists);

        let failure_key = session_key("t07-integration-wrong-type");
        let _: () = redis::cmd("SET")
            .arg(&failure_key)
            .arg("string")
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            read_session(&mut connection, "t07-integration-wrong-type", now).await,
            Err(RedisStateError::RedisFailure)
        );

        for key in keys.iter().chain([expired_key, failure_key].iter()) {
            let _: () = redis::cmd("DEL")
                .arg(key)
                .query_async(&mut connection)
                .await
                .unwrap();
        }
    }
}
