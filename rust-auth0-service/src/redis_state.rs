use crate::auth_foundation::{is_unexpired, reference_value_lookup};
use redis::{aio::MultiplexedConnection, Script, Value};
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

const CALLBACK_CLAIM_SCRIPT: &str = r#"
local function invalid() return {3} end
local function uint(value)
  if value == false or string.match(value, "^[+]?[0-9]+$") == nil then return false end
  local number = tonumber(value)
  return number ~= nil and number >= 0 and number <= 9007199254740991 and number == math.floor(number)
end
if redis.call("EXISTS", KEYS[1]) == 0 then return {1} end
if redis.call("TYPE", KEYS[1]).ok ~= "hash" then return invalid() end
if redis.call("HLEN", KEYS[1]) ~= 8 then return invalid() end
local service_id = redis.call("HGET", KEYS[1], "service_id")
local service_state = redis.call("HGET", KEYS[1], "service_state")
local challenge = redis.call("HGET", KEYS[1], "handoff_code_challenge")
local provider = redis.call("HGET", KEYS[1], "provider")
local verification = redis.call("HGET", KEYS[1], "provider_verification_data")
local created_at = redis.call("HGET", KEYS[1], "created_at")
local expires_at = redis.call("HGET", KEYS[1], "expires_at")
local status = redis.call("HGET", KEYS[1], "status")
if service_id == false or service_state == false or challenge == false or provider == false or verification == false
  or not uint(created_at) or not uint(expires_at) or status == false then return invalid() end
local now = tonumber(redis.call("TIME")[1])
local expiry = tonumber(expires_at)
if now >= expiry then redis.call("DEL", KEYS[1]); return {2} end
if redis.call("EXPIRETIME", KEYS[1]) ~= expiry then return invalid() end
if status == "processing" then return {4} end
if status ~= "waiting" then return invalid() end
redis.call("HSET", KEYS[1], "status", "processing")
return {0, service_id, service_state, challenge, provider, verification, created_at, expires_at, "processing"}
"#;

const ISSUE_SSO_HANDOFF_SCRIPT: &str = r#"
local function invalid() return {3} end
local function uint(value)
  if value == false or string.match(value, "^[+]?[0-9]+$") == nil then return false end
  local number = tonumber(value)
  return number ~= nil and number >= 0 and number <= 9007199254740991 and number == math.floor(number)
end
local function int(value)
  if value == false or string.match(value, "^[+-]?[0-9]+$") == nil then return false end
  local number = tonumber(value)
  return number ~= nil and number >= -2147483648 and number <= 2147483647 and number == math.floor(number)
end
local function lookup(value)
  return value ~= false and string.match(value, "^[0-9a-f][0-9a-f]*$") ~= nil and string.len(value) == 64
end
if redis.call("EXISTS", KEYS[1]) == 0 then return {1} end
if redis.call("TYPE", KEYS[1]).ok ~= "hash" then return invalid() end
if redis.call("HLEN", KEYS[1]) ~= 4 then return invalid() end
local session_user = redis.call("HGET", KEYS[1], "internal_user_id")
local session_authenticated = redis.call("HGET", KEYS[1], "authenticated_at")
local session_created = redis.call("HGET", KEYS[1], "created_at")
local session_expires = redis.call("HGET", KEYS[1], "expires_at")
if not int(session_user) or not uint(session_authenticated) or not uint(session_created) or not uint(session_expires) then return invalid() end
local now = tonumber(redis.call("TIME")[1])
if now >= tonumber(session_expires) then redis.call("DEL", KEYS[1]); return {2} end
if redis.call("EXPIRETIME", KEYS[1]) ~= tonumber(session_expires) then return invalid() end
if redis.call("EXISTS", KEYS[2]) ~= 0 then return {9} end
if not lookup(ARGV[1]) or KEYS[1] ~= "auth:session:" .. ARGV[1] then return invalid() end
if ARGV[9] ~= "unused" or not int(ARGV[3]) or not lookup(ARGV[4]) or not uint(ARGV[6])
  or not uint(ARGV[7]) or not uint(ARGV[8]) then return invalid() end
if ARGV[4] ~= ARGV[1] or tonumber(ARGV[3]) ~= tonumber(session_user) or tonumber(ARGV[6]) ~= tonumber(session_authenticated) then return invalid() end
if tonumber(ARGV[8]) <= now then return {2} end
redis.call("HSET", KEYS[2],
  "service_id", ARGV[2], "internal_user_id", ARGV[3], "common_session_lookup", ARGV[4],
  "code_challenge", ARGV[5], "authenticated_at", ARGV[6], "issued_at", ARGV[7],
  "expires_at", ARGV[8], "status", ARGV[9])
redis.call("EXPIREAT", KEYS[2], ARGV[8])
return {0}
"#;

const CREATE_SESSION_AND_HANDOFF_SCRIPT: &str = r#"
local function invalid() return {3} end
local function uint(value)
  if value == false or string.match(value, "^[+]?[0-9]+$") == nil then return false end
  local number = tonumber(value)
  return number ~= nil and number >= 0 and number <= 9007199254740991 and number == math.floor(number)
end
local function int(value)
  if value == false or string.match(value, "^[+-]?[0-9]+$") == nil then return false end
  local number = tonumber(value)
  return number ~= nil and number >= -2147483648 and number <= 2147483647 and number == math.floor(number)
end
local function lookup(value)
  return value ~= false and string.match(value, "^[0-9a-f][0-9a-f]*$") ~= nil and string.len(value) == 64
end
if redis.call("EXISTS", KEYS[1]) ~= 0 or redis.call("EXISTS", KEYS[2]) ~= 0 then return {9} end
if not int(ARGV[1]) or not uint(ARGV[2]) or not uint(ARGV[3]) or not uint(ARGV[4])
  or not lookup(ARGV[5]) or KEYS[1] ~= "auth:session:" .. ARGV[5] then return invalid() end
if ARGV[13] ~= "unused" or not int(ARGV[7]) or not lookup(ARGV[8]) or not uint(ARGV[10])
  or not uint(ARGV[11]) or not uint(ARGV[12]) then return invalid() end
if ARGV[8] ~= ARGV[5] or tonumber(ARGV[7]) ~= tonumber(ARGV[1]) or tonumber(ARGV[10]) ~= tonumber(ARGV[2]) then return invalid() end
local now = tonumber(redis.call("TIME")[1])
if tonumber(ARGV[4]) <= now or tonumber(ARGV[12]) <= now then return {2} end
redis.call("HSET", KEYS[1], "internal_user_id", ARGV[1], "authenticated_at", ARGV[2],
  "created_at", ARGV[3], "expires_at", ARGV[4])
redis.call("EXPIREAT", KEYS[1], ARGV[4])
redis.call("HSET", KEYS[2], "service_id", ARGV[6], "internal_user_id", ARGV[7],
  "common_session_lookup", ARGV[8], "code_challenge", ARGV[9], "authenticated_at", ARGV[10],
  "issued_at", ARGV[11], "expires_at", ARGV[12], "status", ARGV[13])
redis.call("EXPIREAT", KEYS[2], ARGV[12])
return {0}
"#;

const EXCHANGE_HANDOFF_SCRIPT: &str = r#"
local function invalid() return {3} end
local function uint(value)
  if value == false or string.match(value, "^[+]?[0-9]+$") == nil then return false end
  local number = tonumber(value)
  return number ~= nil and number >= 0 and number <= 9007199254740991 and number == math.floor(number)
end
local function int(value)
  if value == false or string.match(value, "^[+-]?[0-9]+$") == nil then return false end
  local number = tonumber(value)
  return number ~= nil and number >= -2147483648 and number <= 2147483647 and number == math.floor(number)
end
local function lookup(value)
  return value ~= false and string.match(value, "^[0-9a-f][0-9a-f]*$") ~= nil and string.len(value) == 64
end
if redis.call("EXISTS", KEYS[1]) == 0 then return {1} end
if redis.call("TYPE", KEYS[1]).ok ~= "hash" then return invalid() end
if redis.call("HLEN", KEYS[1]) ~= 8 then return invalid() end
local handoff_service = redis.call("HGET", KEYS[1], "service_id")
local handoff_user = redis.call("HGET", KEYS[1], "internal_user_id")
local handoff_lookup = redis.call("HGET", KEYS[1], "common_session_lookup")
local handoff_challenge = redis.call("HGET", KEYS[1], "code_challenge")
local handoff_authenticated = redis.call("HGET", KEYS[1], "authenticated_at")
local handoff_issued = redis.call("HGET", KEYS[1], "issued_at")
local handoff_expires = redis.call("HGET", KEYS[1], "expires_at")
local handoff_status = redis.call("HGET", KEYS[1], "status")
if handoff_service == false or not int(handoff_user) or not lookup(handoff_lookup) or handoff_challenge == false
  or not uint(handoff_authenticated) or not uint(handoff_issued) or not uint(handoff_expires) or handoff_status == false then return invalid() end
local now = tonumber(redis.call("TIME")[1])
if now >= tonumber(handoff_expires) then redis.call("DEL", KEYS[1]); return {2} end
if redis.call("EXPIRETIME", KEYS[1]) ~= tonumber(handoff_expires) then return invalid() end
if handoff_status == "used" then return {5} end
if handoff_status ~= "unused" then return invalid() end
if handoff_service ~= ARGV[1] then return {6} end
if handoff_challenge ~= ARGV[2] then return {7} end
if not lookup(ARGV[3]) or handoff_lookup ~= ARGV[3] or KEYS[2] ~= "auth:session:" .. ARGV[3] then return invalid() end
if redis.call("EXISTS", KEYS[2]) == 0 then return {1} end
if redis.call("TYPE", KEYS[2]).ok ~= "hash" then return invalid() end
if redis.call("HLEN", KEYS[2]) ~= 4 then return invalid() end
local session_user = redis.call("HGET", KEYS[2], "internal_user_id")
local session_authenticated = redis.call("HGET", KEYS[2], "authenticated_at")
local session_created = redis.call("HGET", KEYS[2], "created_at")
local session_expires = redis.call("HGET", KEYS[2], "expires_at")
if not int(session_user) or not uint(session_authenticated) or not uint(session_created) or not uint(session_expires) then return invalid() end
if now >= tonumber(session_expires) then redis.call("DEL", KEYS[2]); return {2} end
if redis.call("EXPIRETIME", KEYS[2]) ~= tonumber(session_expires) then return invalid() end
if tonumber(handoff_user) ~= tonumber(session_user) or tonumber(handoff_authenticated) ~= tonumber(session_authenticated) then return invalid() end
redis.call("HSET", KEYS[1], "status", "used")
return {0, tonumber(handoff_user), tonumber(handoff_authenticated)}
"#;

const COMPLETE_COMMON_LOGOUT_SCRIPT: &str = r#"
local function invalid() return {3} end
local function uint(value)
  if value == false or string.match(value, "^[+]?[0-9]+$") == nil then return false end
  local number = tonumber(value)
  return number ~= nil and number >= 0 and number <= 9007199254740991 and number == math.floor(number)
end
local function lookup(value)
  return value ~= false and string.match(value, "^[0-9a-f][0-9a-f]*$") ~= nil and string.len(value) == 64
end
local function fixed_work_equal_lookup(a, b)
  if not lookup(a) or not lookup(b) then return false end
  local diff = 0
  for i = 1, 64 do
    diff = bit.bor(diff, bit.bxor(string.byte(a, i), string.byte(b, i)))
  end
  return diff == 0
end
if redis.call("EXISTS", KEYS[1]) == 0 then return {1} end
if redis.call("TYPE", KEYS[1]).ok ~= "hash" then return invalid() end
if redis.call("HLEN", KEYS[1]) ~= 6 then return invalid() end
local service_id = redis.call("HGET", KEYS[1], "service_id")
local return_uri = redis.call("HGET", KEYS[1], "logout_return_uri")
local csrf_lookup = redis.call("HGET", KEYS[1], "csrf_lookup")
local created_at = redis.call("HGET", KEYS[1], "created_at")
local expires_at = redis.call("HGET", KEYS[1], "expires_at")
local status = redis.call("HGET", KEYS[1], "status")
if service_id == false or return_uri == false or not lookup(csrf_lookup) or not uint(created_at)
  or not uint(expires_at) or status == false then return invalid() end
local now = tonumber(redis.call("TIME")[1])
if now >= tonumber(expires_at) then redis.call("DEL", KEYS[1]); return {2} end
if redis.call("EXPIRETIME", KEYS[1]) ~= tonumber(expires_at) then return invalid() end
if status == "used" then return {5} end
if status ~= "unused" then return invalid() end
if not lookup(ARGV[1]) then return {8} end
if not fixed_work_equal_lookup(csrf_lookup, ARGV[1]) then return {8} end
redis.call("HSET", KEYS[1], "status", "used")
redis.call("DEL", KEYS[2])
return {0, return_uri}
"#;

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
    AlreadyClaimed,
    AlreadyUsed,
    ServiceMismatch,
    ChallengeMismatch,
    CsrfMismatch,
    KeyConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandoffExchangeResult {
    pub(crate) internal_user_id: i32,
    pub(crate) authenticated_at: u64,
}

pub(crate) fn external_key(reference: &str) -> String {
    format!("auth:external:{}", reference_value_lookup(reference))
}

pub(crate) fn session_key(reference: &str) -> String {
    format!("auth:session:{}", reference_value_lookup(reference))
}

fn session_key_from_lookup(lookup: &str) -> Result<String, RedisStateError> {
    if !is_lookup(lookup) {
        return Err(RedisStateError::InvalidStoredState);
    }
    Ok(format!("auth:session:{lookup}"))
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

pub(crate) async fn claim_external_callback(
    connection: &mut MultiplexedConnection,
    external_reference: &str,
) -> Result<ExternalAuthTransaction, RedisStateError> {
    let script = Script::new(CALLBACK_CLAIM_SCRIPT);
    let mut invocation = script.prepare_invoke();
    invocation.key(external_key(external_reference));
    let reply: Vec<Value> = invocation
        .invoke_async(connection)
        .await
        .map_err(|_| RedisStateError::RedisFailure)?;

    match reply.as_slice() {
        [Value::Int(0), service_id, service_state, challenge, provider, verification, created_at, expires_at, status] =>
        {
            let mut fields = BTreeMap::new();
            fields.insert("service_id".to_owned(), reply_string(service_id)?);
            fields.insert("service_state".to_owned(), reply_string(service_state)?);
            fields.insert(
                "handoff_code_challenge".to_owned(),
                reply_string(challenge)?,
            );
            fields.insert("provider".to_owned(), reply_string(provider)?);
            fields.insert(
                "provider_verification_data".to_owned(),
                reply_string(verification)?,
            );
            fields.insert("created_at".to_owned(), reply_string(created_at)?);
            fields.insert("expires_at".to_owned(), reply_string(expires_at)?);
            fields.insert("status".to_owned(), reply_string(status)?);
            let state = decode_external(&fields)?;
            if state.status != ExternalStatus::Processing {
                return Err(RedisStateError::InvalidStoredState);
            }
            Ok(state)
        }
        [Value::Int(code)] => script_error(*code),
        _ => Err(RedisStateError::InvalidStoredState),
    }
}

pub(crate) async fn issue_sso_handoff(
    connection: &mut MultiplexedConnection,
    common_session_reference: &str,
    handoff_reference: &str,
    handoff: &AuthenticationHandoff,
) -> Result<(), RedisStateError> {
    let session_lookup = reference_value_lookup(common_session_reference);
    let script = Script::new(ISSUE_SSO_HANDOFF_SCRIPT);
    let mut invocation = script.prepare_invoke();
    invocation
        .key(session_key(common_session_reference))
        .key(handoff_key(handoff_reference))
        .arg(session_lookup)
        .arg(&handoff.service_id)
        .arg(handoff.internal_user_id.to_string())
        .arg(&handoff.common_session_lookup)
        .arg(&handoff.code_challenge)
        .arg(handoff.authenticated_at.to_string())
        .arg(handoff.issued_at.to_string())
        .arg(handoff.expires_at.to_string())
        .arg(usage_status_value(&handoff.status));
    let reply: Vec<Value> = invocation
        .invoke_async(connection)
        .await
        .map_err(|_| RedisStateError::RedisFailure)?;
    match reply.as_slice() {
        [Value::Int(0)] => Ok(()),
        [Value::Int(code)] => script_error(*code),
        _ => Err(RedisStateError::InvalidStoredState),
    }
}

pub(crate) async fn create_session_and_handoff(
    connection: &mut MultiplexedConnection,
    common_session_reference: &str,
    session: &CommonSession,
    handoff_reference: &str,
    handoff: &AuthenticationHandoff,
) -> Result<(), RedisStateError> {
    let session_lookup = reference_value_lookup(common_session_reference);
    let script = Script::new(CREATE_SESSION_AND_HANDOFF_SCRIPT);
    let mut invocation = script.prepare_invoke();
    invocation
        .key(session_key(common_session_reference))
        .key(handoff_key(handoff_reference))
        .arg(session.internal_user_id.to_string())
        .arg(session.authenticated_at.to_string())
        .arg(session.created_at.to_string())
        .arg(session.expires_at.to_string())
        .arg(session_lookup)
        .arg(&handoff.service_id)
        .arg(handoff.internal_user_id.to_string())
        .arg(&handoff.common_session_lookup)
        .arg(&handoff.code_challenge)
        .arg(handoff.authenticated_at.to_string())
        .arg(handoff.issued_at.to_string())
        .arg(handoff.expires_at.to_string())
        .arg(usage_status_value(&handoff.status));
    let reply: Vec<Value> = invocation
        .invoke_async(connection)
        .await
        .map_err(|_| RedisStateError::RedisFailure)?;
    match reply.as_slice() {
        [Value::Int(0)] => Ok(()),
        [Value::Int(code)] => script_error(*code),
        _ => Err(RedisStateError::InvalidStoredState),
    }
}

pub(crate) async fn exchange_handoff(
    connection: &mut MultiplexedConnection,
    handoff_reference: &str,
    service_id: &str,
    candidate_code_challenge: &str,
) -> Result<HandoffExchangeResult, RedisStateError> {
    let common_session_lookup =
        resolve_handoff_session_lookup(connection, handoff_reference).await?;
    let session_key = session_key_from_lookup(&common_session_lookup)?;
    let script = Script::new(EXCHANGE_HANDOFF_SCRIPT);
    let mut invocation = script.prepare_invoke();
    invocation
        .key(handoff_key(handoff_reference))
        .key(session_key)
        .arg(service_id)
        .arg(candidate_code_challenge)
        .arg(common_session_lookup);
    let reply: Vec<Value> = invocation
        .invoke_async(connection)
        .await
        .map_err(|_| RedisStateError::RedisFailure)?;
    match reply.as_slice() {
        [Value::Int(0), Value::Int(internal_user_id), Value::Int(authenticated_at)] => {
            let internal_user_id = i32::try_from(*internal_user_id)
                .map_err(|_| RedisStateError::InvalidStoredState)?;
            let authenticated_at = u64::try_from(*authenticated_at)
                .map_err(|_| RedisStateError::InvalidStoredState)?;
            Ok(HandoffExchangeResult {
                internal_user_id,
                authenticated_at,
            })
        }
        [Value::Int(code)] => script_error(*code),
        _ => Err(RedisStateError::InvalidStoredState),
    }
}

pub(crate) async fn complete_common_logout(
    connection: &mut MultiplexedConnection,
    logout_reference: &str,
    common_session_reference: &str,
    csrf_lookup: &str,
) -> Result<String, RedisStateError> {
    let script = Script::new(COMPLETE_COMMON_LOGOUT_SCRIPT);
    let mut invocation = script.prepare_invoke();
    invocation
        .key(logout_key(logout_reference))
        .key(session_key(common_session_reference))
        .arg(csrf_lookup);
    let reply: Vec<Value> = invocation
        .invoke_async(connection)
        .await
        .map_err(|_| RedisStateError::RedisFailure)?;
    match reply.as_slice() {
        [Value::Int(0), return_uri] => reply_string(return_uri),
        [Value::Int(code)] => script_error(*code),
        _ => Err(RedisStateError::InvalidStoredState),
    }
}

async fn resolve_handoff_session_lookup(
    connection: &mut MultiplexedConnection,
    handoff_reference: &str,
) -> Result<String, RedisStateError> {
    let key = handoff_key(handoff_reference);
    let key_type: String = redis::cmd("TYPE")
        .arg(&key)
        .query_async(connection)
        .await
        .map_err(|_| RedisStateError::RedisFailure)?;
    match key_type.as_str() {
        "none" => return Err(RedisStateError::NotFound),
        "hash" => {}
        _ => return Err(RedisStateError::InvalidStoredState),
    }

    let lookup: Option<String> = redis::cmd("HGET")
        .arg(&key)
        .arg("common_session_lookup")
        .query_async(connection)
        .await
        .map_err(|_| RedisStateError::RedisFailure)?;
    let lookup = lookup.ok_or(RedisStateError::InvalidStoredState)?;
    if !is_lookup(&lookup) {
        return Err(RedisStateError::InvalidStoredState);
    }
    Ok(lookup)
}

fn reply_string(value: &Value) -> Result<String, RedisStateError> {
    match value {
        Value::BulkString(value) => {
            String::from_utf8(value.clone()).map_err(|_| RedisStateError::InvalidStoredState)
        }
        _ => Err(RedisStateError::InvalidStoredState),
    }
}

fn script_error<T>(code: i64) -> Result<T, RedisStateError> {
    match code {
        1 => Err(RedisStateError::NotFound),
        2 => Err(RedisStateError::Expired),
        3 => Err(RedisStateError::InvalidStoredState),
        4 => Err(RedisStateError::AlreadyClaimed),
        5 => Err(RedisStateError::AlreadyUsed),
        6 => Err(RedisStateError::ServiceMismatch),
        7 => Err(RedisStateError::ChallengeMismatch),
        8 => Err(RedisStateError::CsrfMismatch),
        9 => Err(RedisStateError::KeyConflict),
        _ => Err(RedisStateError::InvalidStoredState),
    }
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

    async fn redis_exists(connection: &mut MultiplexedConnection, key: &str) -> bool {
        redis::cmd("EXISTS")
            .arg(key)
            .query_async(connection)
            .await
            .unwrap()
    }

    async fn redis_status(connection: &mut MultiplexedConnection, key: &str) -> String {
        redis::cmd("HGET")
            .arg(key)
            .arg("status")
            .query_async(connection)
            .await
            .unwrap()
    }

    async fn redis_expiretime(connection: &mut MultiplexedConnection, key: &str) -> i64 {
        redis::cmd("EXPIRETIME")
            .arg(key)
            .query_async(connection)
            .await
            .unwrap()
    }

    async fn set_hash_field(
        connection: &mut MultiplexedConnection,
        key: &str,
        field: &str,
        value: impl redis::ToRedisArgs,
    ) {
        redis::cmd("HSET")
            .arg(key)
            .arg(field)
            .arg(value)
            .query_async::<()>(connection)
            .await
            .unwrap();
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

    #[actix_web::test]
    #[ignore = "requires AUTH_FOUNDATION_TEST_REDIS_URL and a disposable Redis 7 instance"]
    async fn t08_redis_lua_atomic_operations() {
        let redis_url = std::env::var("AUTH_FOUNDATION_TEST_REDIS_URL")
            .expect("AUTH_FOUNDATION_TEST_REDIS_URL must be set for this ignored test");
        let client = redis::Client::open(redis_url.clone()).unwrap();
        let mut connection = client.get_multiplexed_async_connection().await.unwrap();
        let now: u64 = redis::cmd("TIME")
            .query_async::<(u64, u64)>(&mut connection)
            .await
            .unwrap()
            .0;
        let external_reference = "t08-external";
        let session_reference = "t08-session";
        let handoff_reference = "t08-handoff";
        let issued_handoff_reference = "t08-issued-handoff";
        let concurrent_exchange_reference = "t08-concurrent-exchange";
        let logout_reference = "t08-logout";
        let logout_session_reference = "t08-logout-session";
        let concurrent_logout_reference = "t08-concurrent-logout";
        let concurrent_logout_session_reference = "t08-concurrent-logout-session";
        let keys = [
            external_key(external_reference),
            session_key(session_reference),
            handoff_key(handoff_reference),
            handoff_key(issued_handoff_reference),
            handoff_key(concurrent_exchange_reference),
            logout_key(logout_reference),
            session_key(logout_session_reference),
            logout_key(concurrent_logout_reference),
            session_key(concurrent_logout_session_reference),
        ];
        for key in &keys {
            redis::cmd("DEL")
                .arg(key)
                .query_async::<()>(&mut connection)
                .await
                .unwrap();
        }

        let mut callback = external();
        callback.expires_at = now + 120;
        write_external(&mut connection, external_reference, &callback, now)
            .await
            .unwrap();
        let claimed = claim_external_callback(&mut connection, external_reference)
            .await
            .unwrap();
        assert_eq!(claimed.status, ExternalStatus::Processing);
        assert_eq!(
            claim_external_callback(&mut connection, external_reference).await,
            Err(RedisStateError::AlreadyClaimed)
        );
        assert_eq!(
            claim_external_callback(&mut connection, "t08-missing").await,
            Err(RedisStateError::NotFound)
        );

        let concurrent_reference = "t08-concurrent-claim";
        let concurrent_key = external_key(concurrent_reference);
        let mut concurrent = external();
        concurrent.expires_at = now + 120;
        write_external(&mut connection, concurrent_reference, &concurrent, now)
            .await
            .unwrap();
        let first_url = redis_url.clone();
        let second_url = redis_url.clone();
        let first = actix_web::rt::spawn(async move {
            let client = redis::Client::open(first_url).unwrap();
            let mut connection = client.get_multiplexed_async_connection().await.unwrap();
            claim_external_callback(&mut connection, concurrent_reference).await
        });
        let second = actix_web::rt::spawn(async move {
            let client = redis::Client::open(second_url).unwrap();
            let mut connection = client.get_multiplexed_async_connection().await.unwrap();
            claim_external_callback(&mut connection, concurrent_reference).await
        });
        let outcomes = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Err(RedisStateError::AlreadyClaimed))
                .count(),
            1
        );

        let mut session_state = session();
        session_state.expires_at = now + 300;
        let mut initial_handoff = handoff(UsageStatus::Unused);
        initial_handoff.common_session_lookup = reference_value_lookup(session_reference);
        initial_handoff.expires_at = now + 120;
        create_session_and_handoff(
            &mut connection,
            session_reference,
            &session_state,
            handoff_reference,
            &initial_handoff,
        )
        .await
        .unwrap();
        for (key, expires_at) in [
            (session_key(session_reference), session_state.expires_at),
            (handoff_key(handoff_reference), initial_handoff.expires_at),
        ] {
            let expiretime: i64 = redis::cmd("EXPIRETIME")
                .arg(key)
                .query_async(&mut connection)
                .await
                .unwrap();
            assert_eq!(expiretime, expires_at as i64);
        }
        assert_eq!(
            create_session_and_handoff(
                &mut connection,
                session_reference,
                &session_state,
                "t08-conflicting-handoff",
                &initial_handoff,
            )
            .await,
            Err(RedisStateError::KeyConflict)
        );
        assert!(!redis::cmd("EXISTS")
            .arg(handoff_key("t08-conflicting-handoff"))
            .query_async::<bool>(&mut connection)
            .await
            .unwrap());

        let session_expiretime_before: i64 = redis::cmd("EXPIRETIME")
            .arg(session_key(session_reference))
            .query_async(&mut connection)
            .await
            .unwrap();
        let mut issued_handoff = handoff(UsageStatus::Unused);
        issued_handoff.common_session_lookup = reference_value_lookup(session_reference);
        issued_handoff.expires_at = now + 110;
        issue_sso_handoff(
            &mut connection,
            session_reference,
            issued_handoff_reference,
            &issued_handoff,
        )
        .await
        .unwrap();
        assert_eq!(
            redis::cmd("EXPIRETIME")
                .arg(session_key(session_reference))
                .query_async::<i64>(&mut connection)
                .await
                .unwrap(),
            session_expiretime_before
        );
        assert_eq!(
            issue_sso_handoff(
                &mut connection,
                session_reference,
                issued_handoff_reference,
                &issued_handoff,
            )
            .await,
            Err(RedisStateError::KeyConflict)
        );
        let handoff_expiretime_before: i64 = redis::cmd("EXPIRETIME")
            .arg(handoff_key(issued_handoff_reference))
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            exchange_handoff(
                &mut connection,
                issued_handoff_reference,
                "service",
                "challenge",
            )
            .await,
            Ok(HandoffExchangeResult {
                internal_user_id: 42,
                authenticated_at: 101,
            })
        );
        assert_eq!(
            redis::cmd("EXPIRETIME")
                .arg(handoff_key(issued_handoff_reference))
                .query_async::<i64>(&mut connection)
                .await
                .unwrap(),
            handoff_expiretime_before
        );
        assert_eq!(
            exchange_handoff(
                &mut connection,
                issued_handoff_reference,
                "service",
                "challenge",
            )
            .await,
            Err(RedisStateError::AlreadyUsed)
        );

        let mut concurrent_exchange = handoff(UsageStatus::Unused);
        concurrent_exchange.common_session_lookup = reference_value_lookup(session_reference);
        concurrent_exchange.expires_at = now + 100;
        issue_sso_handoff(
            &mut connection,
            session_reference,
            concurrent_exchange_reference,
            &concurrent_exchange,
        )
        .await
        .unwrap();
        let first_url = redis_url.clone();
        let second_url = redis_url.clone();
        let first = actix_web::rt::spawn(async move {
            let client = redis::Client::open(first_url).unwrap();
            let mut connection = client.get_multiplexed_async_connection().await.unwrap();
            exchange_handoff(
                &mut connection,
                concurrent_exchange_reference,
                "service",
                "challenge",
            )
            .await
        });
        let second = actix_web::rt::spawn(async move {
            let client = redis::Client::open(second_url).unwrap();
            let mut connection = client.get_multiplexed_async_connection().await.unwrap();
            exchange_handoff(
                &mut connection,
                concurrent_exchange_reference,
                "service",
                "challenge",
            )
            .await
        });
        let outcomes = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Err(RedisStateError::AlreadyUsed))
                .count(),
            1
        );

        let mut logout_state = logout();
        logout_state.expires_at = now + 120;
        let mut logout_session = session();
        logout_session.expires_at = now + 120;
        write_logout(&mut connection, logout_reference, &logout_state, now)
            .await
            .unwrap();
        write_session(
            &mut connection,
            logout_session_reference,
            &logout_session,
            now,
        )
        .await
        .unwrap();
        let logout_expiretime_before: i64 = redis::cmd("EXPIRETIME")
            .arg(logout_key(logout_reference))
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            complete_common_logout(
                &mut connection,
                logout_reference,
                logout_session_reference,
                &logout_state.csrf_lookup,
            )
            .await,
            Ok(logout_state.logout_return_uri.clone())
        );
        assert_eq!(
            redis::cmd("EXPIRETIME")
                .arg(logout_key(logout_reference))
                .query_async::<i64>(&mut connection)
                .await
                .unwrap(),
            logout_expiretime_before
        );
        assert!(redis::cmd("EXISTS")
            .arg(logout_key(logout_reference))
            .query_async::<bool>(&mut connection)
            .await
            .unwrap());
        assert!(!redis::cmd("EXISTS")
            .arg(session_key(logout_session_reference))
            .query_async::<bool>(&mut connection)
            .await
            .unwrap());
        assert_eq!(
            complete_common_logout(
                &mut connection,
                logout_reference,
                logout_session_reference,
                &logout_state.csrf_lookup,
            )
            .await,
            Err(RedisStateError::AlreadyUsed)
        );

        let mut concurrent_logout = logout();
        concurrent_logout.expires_at = now + 100;
        let mut concurrent_logout_session = session();
        concurrent_logout_session.expires_at = now + 100;
        write_logout(
            &mut connection,
            concurrent_logout_reference,
            &concurrent_logout,
            now,
        )
        .await
        .unwrap();
        write_session(
            &mut connection,
            concurrent_logout_session_reference,
            &concurrent_logout_session,
            now,
        )
        .await
        .unwrap();
        let first_url = redis_url.clone();
        let second_url = redis_url.clone();
        let csrf_lookup = concurrent_logout.csrf_lookup.clone();
        let first = actix_web::rt::spawn(async move {
            let client = redis::Client::open(first_url).unwrap();
            let mut connection = client.get_multiplexed_async_connection().await.unwrap();
            complete_common_logout(
                &mut connection,
                concurrent_logout_reference,
                concurrent_logout_session_reference,
                &csrf_lookup,
            )
            .await
        });
        let csrf_lookup = concurrent_logout.csrf_lookup.clone();
        let second = actix_web::rt::spawn(async move {
            let client = redis::Client::open(second_url).unwrap();
            let mut connection = client.get_multiplexed_async_connection().await.unwrap();
            complete_common_logout(
                &mut connection,
                concurrent_logout_reference,
                concurrent_logout_session_reference,
                &csrf_lookup,
            )
            .await
        });
        let outcomes = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Err(RedisStateError::AlreadyUsed))
                .count(),
            1
        );

        let expired_reference = "t08-logical-expired";
        let expired_key = external_key(expired_reference);
        let mut future_ttl = external();
        future_ttl.expires_at = now + 60;
        write_external(&mut connection, expired_reference, &future_ttl, now)
            .await
            .unwrap();
        redis::cmd("HSET")
            .arg(&expired_key)
            .arg("expires_at")
            .arg(now - 1)
            .query_async::<()>(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            claim_external_callback(&mut connection, expired_reference).await,
            Err(RedisStateError::Expired)
        );
        assert!(!redis::cmd("EXISTS")
            .arg(&expired_key)
            .query_async::<bool>(&mut connection)
            .await
            .unwrap());

        for key in keys.iter().chain([concurrent_key, expired_key].iter()) {
            redis::cmd("DEL")
                .arg(key)
                .query_async::<()>(&mut connection)
                .await
                .unwrap();
        }
    }

    #[actix_web::test]
    #[ignore = "requires AUTH_FOUNDATION_TEST_REDIS_URL and a disposable Redis 7 instance"]
    async fn t08_redis_lua_rejects_invalid_states_without_mutation() {
        let redis_url = std::env::var("AUTH_FOUNDATION_TEST_REDIS_URL")
            .expect("AUTH_FOUNDATION_TEST_REDIS_URL must be set for this ignored test");
        let client = redis::Client::open(redis_url).unwrap();
        let mut connection = client.get_multiplexed_async_connection().await.unwrap();
        let now: u64 = redis::cmd("TIME")
            .query_async::<(u64, u64)>(&mut connection)
            .await
            .unwrap()
            .0;
        let prefix = format!("t08-review-{now}");
        let callback_malformed = format!("{prefix}-callback-malformed");
        let callback_range = format!("{prefix}-callback-range");
        let missing_session = format!("{prefix}-missing-session");
        let missing_handoff = format!("{prefix}-missing-handoff");
        let expired_session = format!("{prefix}-expired-session");
        let expired_handoff = format!("{prefix}-expired-handoff");
        let conflict_session = format!("{prefix}-conflict-session");
        let conflict_handoff = format!("{prefix}-conflict-handoff");
        let initial_new_session = format!("{prefix}-initial-new-session");
        let initial_new_handoff = format!("{prefix}-initial-new-handoff");
        let initial_handoff_session = format!("{prefix}-initial-handoff-session");
        let exchange_session = format!("{prefix}-exchange-session");
        let exchange_handoff_reference = format!("{prefix}-exchange-handoff");
        let missing_exchange_handoff = format!("{prefix}-missing-exchange-handoff");
        let expired_exchange_session = format!("{prefix}-expired-exchange-session");
        let expired_exchange_handoff = format!("{prefix}-expired-exchange-handoff");
        let mismatch_user_handoff = format!("{prefix}-mismatch-user-handoff");
        let mismatch_auth_handoff = format!("{prefix}-mismatch-auth-handoff");
        let malformed_handoff = format!("{prefix}-malformed-handoff");
        let range_handoff = format!("{prefix}-range-handoff");
        let ttl_handoff = format!("{prefix}-ttl-handoff");
        let logout_csrf = format!("{prefix}-logout-csrf");
        let logout_csrf_session = format!("{prefix}-logout-csrf-session");
        let logout_expired = format!("{prefix}-logout-expired");
        let logout_absent_session = format!("{prefix}-logout-absent-session");
        let cleanup_references = [
            &callback_malformed,
            &callback_range,
            &missing_session,
            &missing_handoff,
            &expired_session,
            &expired_handoff,
            &conflict_session,
            &conflict_handoff,
            &initial_new_session,
            &initial_new_handoff,
            &initial_handoff_session,
            &exchange_session,
            &exchange_handoff_reference,
            &missing_exchange_handoff,
            &expired_exchange_session,
            &expired_exchange_handoff,
            &mismatch_user_handoff,
            &mismatch_auth_handoff,
            &malformed_handoff,
            &range_handoff,
            &ttl_handoff,
            &logout_csrf,
            &logout_csrf_session,
            &logout_expired,
            &logout_absent_session,
        ];
        for reference in cleanup_references {
            for key in [
                external_key(reference),
                session_key(reference),
                handoff_key(reference),
                logout_key(reference),
            ] {
                redis::cmd("DEL")
                    .arg(key)
                    .query_async::<()>(&mut connection)
                    .await
                    .unwrap();
            }
        }

        let mut external_state = external();
        external_state.expires_at = now + 120;
        write_external(&mut connection, &callback_malformed, &external_state, now)
            .await
            .unwrap();
        let callback_malformed_key = external_key(&callback_malformed);
        set_hash_field(
            &mut connection,
            &callback_malformed_key,
            "unexpected",
            "value",
        )
        .await;
        assert_eq!(
            claim_external_callback(&mut connection, &callback_malformed).await,
            Err(RedisStateError::InvalidStoredState)
        );
        assert_eq!(
            redis_status(&mut connection, &callback_malformed_key).await,
            "waiting"
        );

        write_external(&mut connection, &callback_range, &external_state, now)
            .await
            .unwrap();
        let callback_range_key = external_key(&callback_range);
        set_hash_field(
            &mut connection,
            &callback_range_key,
            "created_at",
            "9007199254740992",
        )
        .await;
        assert_eq!(
            claim_external_callback(&mut connection, &callback_range).await,
            Err(RedisStateError::InvalidStoredState)
        );
        assert_eq!(
            redis_status(&mut connection, &callback_range_key).await,
            "waiting"
        );

        let mut handoff_state = handoff(UsageStatus::Unused);
        handoff_state.common_session_lookup = reference_value_lookup(&missing_session);
        handoff_state.expires_at = now + 120;
        assert_eq!(
            issue_sso_handoff(
                &mut connection,
                &missing_session,
                &missing_handoff,
                &handoff_state,
            )
            .await,
            Err(RedisStateError::NotFound)
        );
        assert!(!redis_exists(&mut connection, &handoff_key(&missing_handoff)).await);

        let mut expired_session_state = session();
        expired_session_state.expires_at = now + 120;
        write_session(
            &mut connection,
            &expired_session,
            &expired_session_state,
            now,
        )
        .await
        .unwrap();
        set_hash_field(
            &mut connection,
            &session_key(&expired_session),
            "expires_at",
            (now - 1).to_string(),
        )
        .await;
        let mut expired_handoff_state = handoff(UsageStatus::Unused);
        expired_handoff_state.common_session_lookup = reference_value_lookup(&expired_session);
        expired_handoff_state.expires_at = now + 100;
        assert_eq!(
            issue_sso_handoff(
                &mut connection,
                &expired_session,
                &expired_handoff,
                &expired_handoff_state,
            )
            .await,
            Err(RedisStateError::Expired)
        );
        assert!(!redis_exists(&mut connection, &handoff_key(&expired_handoff)).await);

        let mut conflict_session_state = session();
        conflict_session_state.expires_at = now + 120;
        write_session(
            &mut connection,
            &conflict_session,
            &conflict_session_state,
            now,
        )
        .await
        .unwrap();
        let mut conflict_handoff_state = handoff(UsageStatus::Unused);
        conflict_handoff_state.common_session_lookup = reference_value_lookup(&conflict_session);
        conflict_handoff_state.expires_at = now + 100;
        write_handoff(
            &mut connection,
            &conflict_handoff,
            &conflict_handoff_state,
            now,
        )
        .await
        .unwrap();
        assert_eq!(
            issue_sso_handoff(
                &mut connection,
                &conflict_session,
                &conflict_handoff,
                &conflict_handoff_state,
            )
            .await,
            Err(RedisStateError::KeyConflict)
        );

        let mut initial_session = session();
        initial_session.expires_at = now + 120;
        let mut initial_handoff = handoff(UsageStatus::Unused);
        initial_handoff.common_session_lookup = reference_value_lookup(&initial_new_session);
        initial_handoff.expires_at = now + 100;
        write_session(&mut connection, &initial_new_session, &initial_session, now)
            .await
            .unwrap();
        assert_eq!(
            create_session_and_handoff(
                &mut connection,
                &initial_new_session,
                &initial_session,
                &initial_new_handoff,
                &initial_handoff,
            )
            .await,
            Err(RedisStateError::KeyConflict)
        );
        assert!(!redis_exists(&mut connection, &handoff_key(&initial_new_handoff)).await);

        initial_handoff.common_session_lookup = reference_value_lookup(&initial_handoff_session);
        write_handoff(&mut connection, &initial_new_handoff, &initial_handoff, now)
            .await
            .unwrap();
        assert_eq!(
            create_session_and_handoff(
                &mut connection,
                &initial_handoff_session,
                &initial_session,
                &initial_new_handoff,
                &initial_handoff,
            )
            .await,
            Err(RedisStateError::KeyConflict)
        );
        assert!(!redis_exists(&mut connection, &session_key(&initial_handoff_session)).await);

        let mut exchange_session_state = session();
        exchange_session_state.expires_at = now + 120;
        write_session(
            &mut connection,
            &exchange_session,
            &exchange_session_state,
            now,
        )
        .await
        .unwrap();
        let mut exchange_handoff_state = handoff(UsageStatus::Unused);
        exchange_handoff_state.common_session_lookup = reference_value_lookup(&exchange_session);
        exchange_handoff_state.expires_at = now + 100;
        write_handoff(
            &mut connection,
            &exchange_handoff_reference,
            &exchange_handoff_state,
            now,
        )
        .await
        .unwrap();
        let exchange_key = handoff_key(&exchange_handoff_reference);
        let exchange_session_key = session_key(&exchange_session);
        assert_eq!(
            exchange_handoff(
                &mut connection,
                &exchange_handoff_reference,
                "other-service",
                "challenge",
            )
            .await,
            Err(RedisStateError::ServiceMismatch)
        );
        assert_eq!(redis_status(&mut connection, &exchange_key).await, "unused");
        assert_eq!(
            exchange_handoff(
                &mut connection,
                &exchange_handoff_reference,
                "service",
                "other-challenge",
            )
            .await,
            Err(RedisStateError::ChallengeMismatch)
        );
        assert_eq!(redis_status(&mut connection, &exchange_key).await, "unused");

        let mut missing_exchange_state = handoff(UsageStatus::Unused);
        missing_exchange_state.common_session_lookup = reference_value_lookup(&missing_session);
        missing_exchange_state.expires_at = now + 100;
        write_handoff(
            &mut connection,
            &missing_exchange_handoff,
            &missing_exchange_state,
            now,
        )
        .await
        .unwrap();
        let missing_exchange_key = handoff_key(&missing_exchange_handoff);
        assert_eq!(
            exchange_handoff(
                &mut connection,
                &missing_exchange_handoff,
                "service",
                "challenge",
            )
            .await,
            Err(RedisStateError::NotFound)
        );
        assert_eq!(
            redis_status(&mut connection, &missing_exchange_key).await,
            "unused"
        );

        let mut expired_exchange_session_state = session();
        expired_exchange_session_state.expires_at = now + 120;
        write_session(
            &mut connection,
            &expired_exchange_session,
            &expired_exchange_session_state,
            now,
        )
        .await
        .unwrap();
        set_hash_field(
            &mut connection,
            &session_key(&expired_exchange_session),
            "expires_at",
            (now - 1).to_string(),
        )
        .await;
        let mut expired_exchange_handoff_state = handoff(UsageStatus::Unused);
        expired_exchange_handoff_state.common_session_lookup =
            reference_value_lookup(&expired_exchange_session);
        expired_exchange_handoff_state.expires_at = now + 100;
        write_handoff(
            &mut connection,
            &expired_exchange_handoff,
            &expired_exchange_handoff_state,
            now,
        )
        .await
        .unwrap();
        let expired_exchange_key = handoff_key(&expired_exchange_handoff);
        assert_eq!(
            exchange_handoff(
                &mut connection,
                &expired_exchange_handoff,
                "service",
                "challenge",
            )
            .await,
            Err(RedisStateError::Expired)
        );
        assert_eq!(
            redis_status(&mut connection, &expired_exchange_key).await,
            "unused"
        );

        for (reference, field, value) in [
            (&mismatch_user_handoff, "internal_user_id", "43"),
            (&mismatch_auth_handoff, "authenticated_at", "102"),
        ] {
            write_handoff(&mut connection, reference, &exchange_handoff_state, now)
                .await
                .unwrap();
            let key = handoff_key(reference);
            set_hash_field(&mut connection, &key, field, value).await;
            assert_eq!(
                exchange_handoff(&mut connection, reference, "service", "challenge").await,
                Err(RedisStateError::InvalidStoredState)
            );
            assert_eq!(redis_status(&mut connection, &key).await, "unused");
        }

        for (reference, field, value) in [
            (&malformed_handoff, "unexpected", "value"),
            (&range_handoff, "internal_user_id", "2147483648"),
        ] {
            write_handoff(&mut connection, reference, &exchange_handoff_state, now)
                .await
                .unwrap();
            let key = handoff_key(reference);
            let handoff_ttl = redis_expiretime(&mut connection, &key).await;
            let session_ttl = redis_expiretime(&mut connection, &exchange_session_key).await;
            set_hash_field(&mut connection, &key, field, value).await;
            assert_eq!(
                exchange_handoff(&mut connection, reference, "service", "challenge").await,
                Err(RedisStateError::InvalidStoredState)
            );
            assert_eq!(redis_status(&mut connection, &key).await, "unused");
            assert_eq!(redis_expiretime(&mut connection, &key).await, handoff_ttl);
            assert_eq!(
                redis_expiretime(&mut connection, &exchange_session_key).await,
                session_ttl
            );
        }

        write_handoff(&mut connection, &ttl_handoff, &exchange_handoff_state, now)
            .await
            .unwrap();
        let ttl_handoff_key = handoff_key(&ttl_handoff);
        redis::cmd("EXPIREAT")
            .arg(&ttl_handoff_key)
            .arg(now + 30)
            .query_async::<()>(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            exchange_handoff(&mut connection, &ttl_handoff, "service", "challenge").await,
            Err(RedisStateError::InvalidStoredState)
        );
        assert_eq!(
            redis_status(&mut connection, &ttl_handoff_key).await,
            "unused"
        );

        let mut logout_state = logout();
        logout_state.expires_at = now + 120;
        let mut logout_session_state = session();
        logout_session_state.expires_at = now + 120;
        write_logout(&mut connection, &logout_csrf, &logout_state, now)
            .await
            .unwrap();
        write_session(
            &mut connection,
            &logout_csrf_session,
            &logout_session_state,
            now,
        )
        .await
        .unwrap();
        assert_eq!(
            complete_common_logout(
                &mut connection,
                &logout_csrf,
                &logout_csrf_session,
                "0".repeat(64).as_str(),
            )
            .await,
            Err(RedisStateError::CsrfMismatch)
        );
        assert_eq!(
            redis_status(&mut connection, &logout_key(&logout_csrf)).await,
            "unused"
        );
        assert!(redis_exists(&mut connection, &session_key(&logout_csrf_session)).await);

        write_logout(&mut connection, &logout_expired, &logout_state, now)
            .await
            .unwrap();
        let logout_expired_key = logout_key(&logout_expired);
        set_hash_field(
            &mut connection,
            &logout_expired_key,
            "expires_at",
            (now - 1).to_string(),
        )
        .await;
        assert_eq!(
            complete_common_logout(
                &mut connection,
                &logout_expired,
                &logout_csrf_session,
                &logout_state.csrf_lookup,
            )
            .await,
            Err(RedisStateError::Expired)
        );
        assert!(!redis_exists(&mut connection, &logout_expired_key).await);

        write_logout(&mut connection, &logout_absent_session, &logout_state, now)
            .await
            .unwrap();
        assert_eq!(
            complete_common_logout(
                &mut connection,
                &logout_absent_session,
                &missing_session,
                &logout_state.csrf_lookup,
            )
            .await,
            Ok(logout_state.logout_return_uri.clone())
        );
        let logout_absent_key = logout_key(&logout_absent_session);
        assert!(redis_exists(&mut connection, &logout_absent_key).await);
        assert_eq!(
            redis_status(&mut connection, &logout_absent_key).await,
            "used"
        );

        for reference in cleanup_references {
            for key in [
                external_key(reference),
                session_key(reference),
                handoff_key(reference),
                logout_key(reference),
            ] {
                redis::cmd("DEL")
                    .arg(key)
                    .query_async::<()>(&mut connection)
                    .await
                    .unwrap();
            }
        }
    }

    #[actix_web::test]
    #[ignore = "requires AUTH_FOUNDATION_TEST_REDIS_URL and a disposable Redis 7 instance"]
    async fn t12_common_logout_csrf_full_length_regression() {
        let redis_url = std::env::var("AUTH_FOUNDATION_TEST_REDIS_URL")
            .expect("AUTH_FOUNDATION_TEST_REDIS_URL must be set");
        let client = redis::Client::open(redis_url).expect("test Redis URL must be valid");
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("connect disposable Redis");
        let now: u64 = redis::cmd("TIME")
            .query_async::<(u64, u64)>(&mut connection)
            .await
            .expect("read Redis time")
            .0;
        let suffix = now.to_string();
        let session_reference = format!("t12-csrf-session-{suffix}");
        let logout_reference = format!("t12-csrf-logout-{suffix}");
        let session = CommonSession {
            internal_user_id: 42,
            authenticated_at: now - 1,
            created_at: now - 2,
            expires_at: now + 120,
        };
        let csrf_lookup = "a".repeat(64);
        let logout = CommonLogoutTransaction {
            service_id: "service".to_owned(),
            logout_return_uri: "https://service.example/logout".to_owned(),
            csrf_lookup: csrf_lookup.clone(),
            created_at: now,
            expires_at: now + 120,
            status: UsageStatus::Unused,
        };
        let session_key = session_key(&session_reference);
        let logout_state_key = logout_key(&logout_reference);
        let _: () = redis::cmd("DEL")
            .arg(&session_key)
            .arg(&logout_state_key)
            .query_async(&mut connection)
            .await
            .expect("clear test state");
        write_session(&mut connection, &session_reference, &session, now)
            .await
            .expect("write CommonSession");
        write_logout(&mut connection, &logout_reference, &logout, now)
            .await
            .expect("write logout transaction");

        for mismatch in [
            format!("b{}", "a".repeat(63)),
            format!("{}b{}", "a".repeat(31), "a".repeat(32)),
            format!("{}b", "a".repeat(63)),
        ] {
            assert_eq!(
                complete_common_logout(
                    &mut connection,
                    &logout_reference,
                    &session_reference,
                    &mismatch,
                )
                .await,
                Err(RedisStateError::CsrfMismatch)
            );
            assert_eq!(
                redis_status(&mut connection, &logout_state_key).await,
                "unused"
            );
            assert!(redis_exists(&mut connection, &session_key).await);
        }
        assert_eq!(
            complete_common_logout(
                &mut connection,
                &logout_reference,
                &session_reference,
                &csrf_lookup,
            )
            .await,
            Ok(logout.logout_return_uri.clone())
        );

        let invalid_reference = format!("t12-csrf-invalid-{suffix}");
        let invalid_key = logout_key(&invalid_reference);
        write_logout(&mut connection, &invalid_reference, &logout, now)
            .await
            .expect("write invalid logout transaction");
        redis::cmd("HSET")
            .arg(&invalid_key)
            .arg("csrf_lookup")
            .arg("a".repeat(63))
            .query_async::<()>(&mut connection)
            .await
            .expect("corrupt csrf lookup");
        assert_eq!(
            complete_common_logout(
                &mut connection,
                &invalid_reference,
                &session_reference,
                &csrf_lookup,
            )
            .await,
            Err(RedisStateError::InvalidStoredState)
        );
        assert_eq!(redis_status(&mut connection, &invalid_key).await, "unused");

        let _: () = redis::cmd("DEL")
            .arg(&session_key)
            .arg(&logout_state_key)
            .arg(&invalid_key)
            .query_async(&mut connection)
            .await
            .expect("clean test state");
    }
}
