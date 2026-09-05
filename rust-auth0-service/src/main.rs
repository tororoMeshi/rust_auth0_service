// src/main.rs for rust-auth0-service

// 必要なクレートのインポート
// T02で定義し、後続の認証タスクから順次接続する。
#[allow(dead_code)]
mod auth_foundation;
// These modules expose helpers used by the integration-style tests in this binary.
#[allow(unused_imports)]
mod postgres;
#[allow(dead_code)]
mod redis_state;

use actix_web::http::header;

use actix_web::cookie::{time::Duration, Cookie, SameSite};
use actix_web::middleware::DefaultHeaders;
use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use dotenv::dotenv;
use log::{error, info};
use oauth2::reqwest::async_http_client;
use oauth2::TokenResponse;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    Scope, TokenUrl,
};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::{env, io, time::SystemTime};

use crate::auth_foundation::{
    checked_expires_at, generate_reference_value, pkce_s256_challenge, reference_value_lookup,
    unix_seconds, validate_fixed_reference_value, validate_max_bytes, validate_service_id,
    EmailVerification, NormalizedExternalIdentity, OAUTH_CODE_MAX_BYTES, SERVICE_STATE_MAX_BYTES,
};
use crate::postgres::{
    authenticate_service, lookup_login_callback_uri, lookup_logout_return_uri,
    read_internal_user_enabled, resolve_external_identity, PostgresAuthError,
};
use crate::redis_state::{
    claim_external_callback, complete_common_logout, create_session_and_handoff, exchange_handoff,
    issue_sso_handoff, read_session, write_external, write_logout, AuthenticationHandoff,
    CommonLogoutTransaction, CommonSession, ExternalAuthTransaction, ExternalStatus,
    RedisStateError, UsageStatus, AUTHENTICATION_HANDOFF_TTL_SECONDS,
    COMMON_LOGOUT_TRANSACTION_TTL_SECONDS, COMMON_SESSION_TTL_SECONDS,
    EXTERNAL_AUTH_TRANSACTION_TTL_SECONDS,
};

const AUTH_SESSION_COOKIE_NAME: &str = "__Host-auth_session";
const GOOGLE_AUTHORIZATION_URL: &str = "https://accounts.google.com/o/oauth2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";
const HTTP_BODY_MAX_BYTES: usize = 16_384;

#[derive(Clone)]
struct GoogleAuthorizationConfig {
    client_id: String,
    redirect_uri: RedirectUrl,
}

struct GoogleCallbackConfig {
    oauth_client: BasicClient,
    userinfo_url: reqwest::Url,
}

struct AuthFoundationConfig {
    google_client_id: String,
    google_client_secret: String,
    google_redirect_uri: String,
    redis_url: String,
    pg_host: String,
    pg_port: u16,
    pg_database: String,
    pg_user: String,
    pg_password: String,
}

impl AuthFoundationConfig {
    fn from_env() -> io::Result<Self> {
        let pg_port = required_nonempty_env("PGPORT")?
            .parse::<u16>()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "PGPORT environment variable must be a valid u16",
                )
            })?;

        Ok(Self {
            google_client_id: required_nonempty_env("GOOGLE_CLIENT_ID")?,
            google_client_secret: required_nonempty_env("GOOGLE_CLIENT_SECRET")?,
            google_redirect_uri: required_nonempty_env("GOOGLE_REDIRECT_URI")?,
            redis_url: required_nonempty_env("REDIS_URL")?,
            pg_host: required_nonempty_env("PGHOST")?,
            pg_port,
            pg_database: required_nonempty_env("PGDATABASE")?,
            pg_user: required_nonempty_env("PGUSER")?,
            pg_password: required_nonempty_env("PGPASSWORD")?,
        })
    }
}

fn required_nonempty_env(name: &str) -> io::Result<String> {
    let value = env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} environment variable is required"),
        )
    })?;

    if value.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} environment variable is required"),
        ));
    }

    Ok(value)
}

#[derive(Deserialize)]
struct LoginQuery {
    service_id: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
}

fn login_input_is_valid(query: &LoginQuery) -> bool {
    validate_service_id(&query.service_id).is_ok()
        && !query.state.is_empty()
        && validate_max_bytes(&query.state, SERVICE_STATE_MAX_BYTES).is_ok()
        && validate_fixed_reference_value(&query.code_challenge).is_ok()
        && query.code_challenge_method == "S256"
}

fn valid_callback_url(callback_uri: &str) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(callback_uri).ok()?;
    (matches!(url.scheme(), "http" | "https") && url.host_str().is_some()).then_some(url)
}

fn auth_security_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add((header::CACHE_CONTROL, "no-store"))
        .add((header::REFERRER_POLICY, "no-referrer"))
}

fn build_deleted_common_auth_cookie() -> Cookie<'static> {
    Cookie::build(AUTH_SESSION_COOKIE_NAME, "")
        .path("/")
        .max_age(Duration::seconds(0))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .finish()
}

fn basic_credentials(request: &HttpRequest) -> Option<(String, String)> {
    let values: Vec<_> = request.headers().get_all(header::AUTHORIZATION).collect();
    if values.len() != 1 {
        return None;
    }
    let value = values[0].to_str().ok()?;
    if value.len() > 8192 {
        return None;
    }
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (service_id, service_secret) = decoded.split_once(':')?;
    (!service_id.is_empty()).then(|| (service_id.to_owned(), service_secret.to_owned()))
}

#[derive(Deserialize)]
struct HandoffExchangeRequest {
    code: String,
    code_verifier: String,
}

#[derive(Serialize)]
struct HandoffExchangeResponse {
    internal_user_id: i32,
    authenticated_at: u64,
}

#[derive(Deserialize)]
struct LogoutQuery {
    service_id: String,
}

#[derive(Deserialize)]
struct LogoutForm {
    logout_reference: String,
    csrf_token: String,
}

async fn start_google_login(
    query: &LoginQuery,
    google_config: &GoogleAuthorizationConfig,
    redis_connection: &web::Data<redis::aio::MultiplexedConnection>,
    now: u64,
) -> HttpResponse {
    let oauth_state = match generate_reference_value() {
        Ok(value) => value,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let authorization_url = BasicClient::new(
        ClientId::new(google_config.client_id.clone()),
        None,
        AuthUrl::new(GOOGLE_AUTHORIZATION_URL.to_owned()).expect("valid URL"),
        None,
    )
    .set_redirect_uri(google_config.redirect_uri.clone())
    .authorize_url(|| CsrfToken::new(oauth_state.clone()))
    .add_scope(Scope::new("email".to_owned()))
    .add_scope(Scope::new("profile".to_owned()))
    .url()
    .0
    .to_string();
    let expires_at = match checked_expires_at(now, EXTERNAL_AUTH_TRANSACTION_TTL_SECONDS) {
        Ok(value) => value,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let transaction = ExternalAuthTransaction {
        service_id: query.service_id.clone(),
        service_state: query.state.clone(),
        handoff_code_challenge: query.code_challenge.clone(),
        provider: "google".to_owned(),
        provider_verification_data: String::new(),
        created_at: now,
        expires_at,
        status: ExternalStatus::Waiting,
    };
    let mut connection = redis_connection.get_ref().clone();
    if write_external(&mut connection, &oauth_state, &transaction, now)
        .await
        .is_err()
    {
        error!("authentication storage unavailable");
        return HttpResponse::ServiceUnavailable().finish();
    }
    HttpResponse::Found()
        .append_header((header::LOCATION, authorization_url))
        .finish()
}

#[get("/auth/login")]
async fn login(
    request: HttpRequest,
    query: web::Query<LoginQuery>,
    postgres_pool: web::Data<PgPool>,
    redis_connection: web::Data<redis::aio::MultiplexedConnection>,
    google_config: web::Data<GoogleAuthorizationConfig>,
) -> HttpResponse {
    let query = query.into_inner();
    if !login_input_is_valid(&query) {
        error!("authentication login input rejected");
        return HttpResponse::BadRequest().finish();
    }
    let callback_uri =
        match lookup_login_callback_uri(postgres_pool.get_ref(), &query.service_id).await {
            Ok(value) => value,
            Err(PostgresAuthError::ServiceNotFound | PostgresAuthError::ServiceDisabled) => {
                return HttpResponse::Forbidden().finish()
            }
            Err(_) => {
                error!("registered login service unavailable");
                return HttpResponse::ServiceUnavailable().finish();
            }
        };
    let now = match unix_seconds(SystemTime::now()) {
        Ok(value) => value,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let Some(cookie) = request.cookie(AUTH_SESSION_COOKIE_NAME) else {
        return start_google_login(&query, google_config.get_ref(), &redis_connection, now).await;
    };
    let common_session_reference = cookie.value();
    if validate_fixed_reference_value(common_session_reference).is_err() {
        return start_google_login(&query, google_config.get_ref(), &redis_connection, now).await;
    }
    let callback_url = match valid_callback_url(&callback_uri) {
        Some(value) => value,
        None => {
            error!("registered login service unavailable");
            return HttpResponse::ServiceUnavailable().finish();
        }
    };
    let mut connection = redis_connection.get_ref().clone();
    let session = match read_session(&mut connection, common_session_reference, now).await {
        Ok(value) => value,
        Err(RedisStateError::NotFound | RedisStateError::Expired) => {
            return start_google_login(&query, google_config.get_ref(), &redis_connection, now)
                .await
        }
        Err(_) => {
            error!("authentication storage unavailable");
            return HttpResponse::ServiceUnavailable().finish();
        }
    };
    match read_internal_user_enabled(postgres_pool.get_ref(), session.internal_user_id).await {
        Ok(Some(true)) => {}
        Ok(Some(false) | None) => {
            error!("SSO session user is not eligible");
            return HttpResponse::Forbidden().finish();
        }
        Err(_) => {
            error!("authentication storage unavailable");
            return HttpResponse::ServiceUnavailable().finish();
        }
    }
    let handoff_reference = match generate_reference_value() {
        Ok(value) => value,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let expires_at = match checked_expires_at(now, AUTHENTICATION_HANDOFF_TTL_SECONDS) {
        Ok(value) => value,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let handoff = AuthenticationHandoff {
        service_id: query.service_id.clone(),
        internal_user_id: session.internal_user_id,
        common_session_lookup: reference_value_lookup(common_session_reference),
        code_challenge: query.code_challenge.clone(),
        authenticated_at: session.authenticated_at,
        issued_at: now,
        expires_at,
        status: UsageStatus::Unused,
    };
    match issue_sso_handoff(
        &mut connection,
        common_session_reference,
        &handoff_reference,
        &handoff,
    )
    .await
    {
        Ok(()) => {}
        Err(RedisStateError::NotFound | RedisStateError::Expired) => {
            return start_google_login(&query, google_config.get_ref(), &redis_connection, now)
                .await
        }
        Err(_) => {
            error!("authentication storage unavailable");
            return HttpResponse::ServiceUnavailable().finish();
        }
    }
    let mut callback_url = callback_url;
    callback_url
        .query_pairs_mut()
        .append_pair("code", &handoff_reference)
        .append_pair("state", &query.state);
    HttpResponse::Found()
        .append_header((header::LOCATION, callback_url.to_string()))
        .finish()
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    id: String,
    email: Option<String>,
    verified_email: Option<bool>,
    name: Option<String>,
    picture: Option<String>,
}

fn normalize_google_user_info(user_info: GoogleUserInfo) -> Result<NormalizedExternalIdentity, ()> {
    let identity = NormalizedExternalIdentity {
        provider: "google".to_owned(),
        subject: user_info.id,
        email: user_info.email.filter(|value| !value.is_empty()),
        email_verification: match user_info.verified_email {
            Some(true) => EmailVerification::Verified,
            Some(false) => EmailVerification::Unverified,
            None => EmailVerification::Unknown,
        },
        display_name: user_info.name.filter(|value| !value.trim().is_empty()),
        picture_url: user_info.picture.filter(|value| !value.is_empty()),
    };
    identity.validate().map_err(|_| ())?;
    Ok(identity)
}

#[get("/auth/google/callback")]
async fn google_auth_callback(
    query: web::Query<CallbackQuery>,
    postgres_pool: web::Data<PgPool>,
    redis_connection: web::Data<redis::aio::MultiplexedConnection>,
    google_config: web::Data<GoogleCallbackConfig>,
) -> HttpResponse {
    let query = query.into_inner();
    if query.code.is_empty()
        || validate_max_bytes(&query.code, OAUTH_CODE_MAX_BYTES).is_err()
        || validate_fixed_reference_value(&query.state).is_err()
    {
        error!("authentication callback input rejected");
        return HttpResponse::BadRequest().finish();
    }

    let mut connection = redis_connection.get_ref().clone();
    let transaction = match claim_external_callback(&mut connection, &query.state).await {
        Ok(value) => value,
        Err(
            RedisStateError::NotFound | RedisStateError::Expired | RedisStateError::AlreadyClaimed,
        ) => {
            error!("authentication callback state unavailable");
            return HttpResponse::BadRequest().finish();
        }
        Err(_) => {
            error!("authentication Redis state unavailable");
            return HttpResponse::ServiceUnavailable().finish();
        }
    };

    let callback_uri =
        match lookup_login_callback_uri(postgres_pool.get_ref(), &transaction.service_id).await {
            Ok(value) => value,
            Err(PostgresAuthError::ServiceNotFound | PostgresAuthError::ServiceDisabled) => {
                return HttpResponse::Forbidden().finish();
            }
            Err(_) => {
                error!("authentication database unavailable");
                return HttpResponse::ServiceUnavailable().finish();
            }
        };
    let callback_url = match valid_callback_url(&callback_uri) {
        Some(value) => value,
        None => {
            error!("registered login callback URI is invalid");
            return HttpResponse::InternalServerError().finish();
        }
    };

    let token = match google_config
        .oauth_client
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(async_http_client)
        .await
    {
        Ok(value) => value,
        Err(_) => {
            error!("Google token exchange failed");
            return HttpResponse::BadGateway().finish();
        }
    };
    let response = match reqwest::Client::new()
        .get(google_config.userinfo_url.clone())
        .bearer_auth(token.access_token().secret())
        .send()
        .await
    {
        Ok(value) if value.status().is_success() => value,
        _ => {
            error!("Google user info request failed");
            return HttpResponse::BadGateway().finish();
        }
    };
    let user_info = match response.json::<GoogleUserInfo>().await {
        Ok(value) => value,
        Err(_) => {
            error!("Google user info response invalid");
            return HttpResponse::BadGateway().finish();
        }
    };
    let identity = match normalize_google_user_info(user_info) {
        Ok(value) => value,
        Err(()) => {
            error!("Google identity response invalid");
            return HttpResponse::BadGateway().finish();
        }
    };
    let now = match unix_seconds(SystemTime::now()) {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let internal_user_id = match resolve_external_identity(
        postgres_pool.get_ref(),
        &identity.provider,
        &identity.subject,
    )
    .await
    {
        Ok(value) => value,
        Err(PostgresAuthError::UserDisabled) => return HttpResponse::Forbidden().finish(),
        Err(PostgresAuthError::IdentityInconsistent) => {
            return HttpResponse::InternalServerError().finish()
        }
        Err(_) => {
            error!("authentication database unavailable");
            return HttpResponse::ServiceUnavailable().finish();
        }
    };
    let common_session_reference = match generate_reference_value() {
        Ok(value) => value,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let handoff_reference = match generate_reference_value() {
        Ok(value) => value,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let session_expires_at = match checked_expires_at(now, COMMON_SESSION_TTL_SECONDS) {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let handoff_expires_at = match checked_expires_at(now, AUTHENTICATION_HANDOFF_TTL_SECONDS) {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let session = CommonSession {
        internal_user_id,
        authenticated_at: now,
        created_at: now,
        expires_at: session_expires_at,
    };
    let handoff = AuthenticationHandoff {
        service_id: transaction.service_id,
        internal_user_id,
        common_session_lookup: reference_value_lookup(&common_session_reference),
        code_challenge: transaction.handoff_code_challenge,
        authenticated_at: now,
        issued_at: now,
        expires_at: handoff_expires_at,
        status: UsageStatus::Unused,
    };
    let mut callback_url = callback_url;
    callback_url.set_query(None);
    callback_url
        .query_pairs_mut()
        .append_pair("code", &handoff_reference)
        .append_pair("state", &transaction.service_state);
    let location = callback_url.to_string();
    if create_session_and_handoff(
        &mut connection,
        &common_session_reference,
        &session,
        &handoff_reference,
        &handoff,
    )
    .await
    .is_err()
    {
        error!("authentication Redis state unavailable");
        return HttpResponse::ServiceUnavailable().finish();
    }
    let cookie = Cookie::build(AUTH_SESSION_COOKIE_NAME, common_session_reference)
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .finish();
    HttpResponse::Found()
        .cookie(cookie)
        .append_header((header::LOCATION, location))
        .finish()
}

async fn exchange_auth_handoff(
    request: HttpRequest,
    body: web::Json<HandoffExchangeRequest>,
    postgres_pool: web::Data<PgPool>,
    redis_connection: web::Data<redis::aio::MultiplexedConnection>,
) -> HttpResponse {
    let body = body.into_inner();
    if validate_fixed_reference_value(&body.code).is_err()
        || body.code_verifier.is_empty()
        || pkce_s256_challenge(&body.code_verifier).is_err()
    {
        return HttpResponse::BadRequest().finish();
    }
    let Some((service_id, service_secret)) = basic_credentials(&request) else {
        return HttpResponse::Unauthorized().finish();
    };
    if validate_service_id(&service_id).is_err() {
        return HttpResponse::Unauthorized().finish();
    }
    match authenticate_service(postgres_pool.get_ref(), &service_id, &service_secret).await {
        Ok(_) => {}
        Err(PostgresAuthError::ServiceNotFound | PostgresAuthError::ServiceSecretMismatch) => {
            return HttpResponse::Unauthorized().finish()
        }
        Err(PostgresAuthError::ServiceDisabled) => return HttpResponse::Forbidden().finish(),
        Err(PostgresAuthError::DatabaseFailure | PostgresAuthError::StoredSecretInvalidLength) => {
            return HttpResponse::ServiceUnavailable().finish()
        }
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    }
    let challenge = match pkce_s256_challenge(&body.code_verifier) {
        Ok(value) => value,
        Err(_) => return HttpResponse::BadRequest().finish(),
    };
    let mut connection = redis_connection.get_ref().clone();
    match exchange_handoff(&mut connection, &body.code, &service_id, &challenge).await {
        Ok(result) => HttpResponse::Ok().json(HandoffExchangeResponse {
            internal_user_id: result.internal_user_id,
            authenticated_at: result.authenticated_at,
        }),
        Err(
            RedisStateError::NotFound
            | RedisStateError::Expired
            | RedisStateError::AlreadyUsed
            | RedisStateError::ServiceMismatch
            | RedisStateError::ChallengeMismatch,
        ) => HttpResponse::BadRequest().finish(),
        Err(_) => HttpResponse::ServiceUnavailable().finish(),
    }
}

async fn logout_get(
    request: HttpRequest,
    query: web::Query<LogoutQuery>,
    postgres_pool: web::Data<PgPool>,
    redis_connection: web::Data<redis::aio::MultiplexedConnection>,
) -> HttpResponse {
    let query = query.into_inner();
    if validate_service_id(&query.service_id).is_err() {
        return HttpResponse::BadRequest().finish();
    }
    let return_uri =
        match lookup_logout_return_uri(postgres_pool.get_ref(), &query.service_id).await {
            Ok(value) => value,
            Err(PostgresAuthError::ServiceNotFound | PostgresAuthError::ServiceDisabled) => {
                return HttpResponse::Forbidden().finish()
            }
            Err(_) => return HttpResponse::ServiceUnavailable().finish(),
        };
    if valid_callback_url(&return_uri).is_none() {
        return HttpResponse::InternalServerError().finish();
    }
    let Some(cookie) = request.cookie(AUTH_SESSION_COOKIE_NAME) else {
        return HttpResponse::Found()
            .append_header((header::LOCATION, return_uri))
            .finish();
    };
    if validate_fixed_reference_value(cookie.value()).is_err() {
        return HttpResponse::Found()
            .append_header((header::LOCATION, return_uri))
            .finish();
    }
    let logout_reference = match generate_reference_value() {
        Ok(value) => value,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let csrf_plaintext = match generate_reference_value() {
        Ok(value) => value,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let now = match unix_seconds(SystemTime::now()) {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let expires_at = match checked_expires_at(now, COMMON_LOGOUT_TRANSACTION_TTL_SECONDS) {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let transaction = CommonLogoutTransaction {
        service_id: query.service_id,
        logout_return_uri: return_uri,
        csrf_lookup: reference_value_lookup(&csrf_plaintext),
        created_at: now,
        expires_at,
        status: UsageStatus::Unused,
    };
    let mut connection = redis_connection.get_ref().clone();
    if write_logout(&mut connection, &logout_reference, &transaction, now)
        .await
        .is_err()
    {
        return HttpResponse::ServiceUnavailable().finish();
    }
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(format!("<form method=\"post\" action=\"/auth/logout\"><input type=\"hidden\" name=\"logout_reference\" value=\"{logout_reference}\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_plaintext}\"><button type=\"submit\">Log out</button></form>"))
}

async fn logout_post(
    request: HttpRequest,
    form: web::Form<LogoutForm>,
    redis_connection: web::Data<redis::aio::MultiplexedConnection>,
) -> HttpResponse {
    let form = form.into_inner();
    if validate_fixed_reference_value(&form.logout_reference).is_err()
        || validate_fixed_reference_value(&form.csrf_token).is_err()
    {
        return HttpResponse::BadRequest().finish();
    }
    let Some(cookie) = request.cookie(AUTH_SESSION_COOKIE_NAME) else {
        return HttpResponse::BadRequest().finish();
    };
    if validate_fixed_reference_value(cookie.value()).is_err() {
        return HttpResponse::BadRequest().finish();
    }
    let csrf_lookup = reference_value_lookup(&form.csrf_token);
    let mut connection = redis_connection.get_ref().clone();
    match complete_common_logout(
        &mut connection,
        &form.logout_reference,
        cookie.value(),
        &csrf_lookup,
    )
    .await
    {
        Ok(return_uri) => HttpResponse::SeeOther()
            .cookie(build_deleted_common_auth_cookie())
            .append_header((header::LOCATION, return_uri))
            .finish(),
        Err(
            RedisStateError::NotFound | RedisStateError::Expired | RedisStateError::AlreadyUsed,
        ) => HttpResponse::BadRequest().finish(),
        Err(RedisStateError::CsrfMismatch) => HttpResponse::Forbidden().finish(),
        Err(_) => HttpResponse::ServiceUnavailable().finish(),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let auth_foundation_config = AuthFoundationConfig::from_env()?;

    let postgres_options = PgConnectOptions::new()
        .host(&auth_foundation_config.pg_host)
        .port(auth_foundation_config.pg_port)
        .database(&auth_foundation_config.pg_database)
        .username(&auth_foundation_config.pg_user)
        .password(&auth_foundation_config.pg_password);
    let postgres_pool: PgPool = PgPoolOptions::new()
        .connect_with(postgres_options)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "failed to connect to PostgreSQL",
            )
        })?;
    info!("PostgreSQL connection established");

    let redis_client =
        redis::Client::open(auth_foundation_config.redis_url.as_str()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "failed to create Redis client")
        })?;
    let redis_connection = redis_client
        .get_multiplexed_tokio_connection()
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "failed to connect to Redis",
            )
        })?;
    info!("Redis connection established");

    let google_authorization_config = GoogleAuthorizationConfig {
        client_id: auth_foundation_config.google_client_id.clone(),
        redirect_uri: RedirectUrl::new(auth_foundation_config.google_redirect_uri.clone())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "GOOGLE_REDIRECT_URI must be a valid URL",
                )
            })?,
    };
    let google_callback_config = web::Data::new(GoogleCallbackConfig {
        oauth_client: BasicClient::new(
            ClientId::new(auth_foundation_config.google_client_id.clone()),
            Some(ClientSecret::new(
                auth_foundation_config.google_client_secret.clone(),
            )),
            AuthUrl::new(GOOGLE_AUTHORIZATION_URL.to_owned()).expect("valid URL"),
            Some(TokenUrl::new(GOOGLE_TOKEN_URL.to_owned()).expect("valid URL")),
        )
        .set_redirect_uri(
            RedirectUrl::new(auth_foundation_config.google_redirect_uri.clone()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "GOOGLE_REDIRECT_URI must be a valid URL",
                )
            })?,
        ),
        userinfo_url: reqwest::Url::parse(GOOGLE_USERINFO_URL).expect("valid URL"),
    });

    drop(auth_foundation_config);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(google_authorization_config.clone()))
            .app_data(google_callback_config.clone())
            .app_data(web::Data::new(postgres_pool.clone()))
            .app_data(web::Data::new(redis_connection.clone()))
            .service(
                web::scope("")
                    .wrap(auth_security_headers())
                    .service(login)
                    .service(google_auth_callback)
                    .service(
                        web::resource("/auth/handoffs/exchange")
                            .app_data(web::JsonConfig::default().limit(HTTP_BODY_MAX_BYTES))
                            .route(web::post().to(exchange_auth_handoff)),
                    )
                    .service(
                        web::resource("/auth/logout")
                            .app_data(web::FormConfig::default().limit(HTTP_BODY_MAX_BYTES))
                            .route(web::get().to(logout_get))
                            .route(web::post().to(logout_post)),
                    ),
            )
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_query_rejects_duplicate_required_fields() {
        let challenge = "A".repeat(43);
        for parameter in [
            "service_id=service&service_id=other",
            "state=one&state=two",
            "code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "code_challenge_method=S256&code_challenge_method=S256",
        ] {
            let query = format!(
                "{parameter}&service_id=service&state=state&code_challenge={challenge}&code_challenge_method=S256"
            );
            assert!(web::Query::<LoginQuery>::from_query(&query).is_err());
        }
    }

    #[test]
    fn google_user_info_normalization_preserves_optional_identity_metadata() {
        let verified = normalize_google_user_info(GoogleUserInfo {
            id: "google-subject".to_owned(),
            email: Some("person@example.test".to_owned()),
            verified_email: Some(true),
            name: Some("Display Name".to_owned()),
            picture: None,
        })
        .expect("valid identity");
        assert_eq!(verified.provider, "google");
        assert_eq!(verified.subject, "google-subject");
        assert_eq!(verified.email.as_deref(), Some("person@example.test"));
        assert_eq!(verified.email_verification, EmailVerification::Verified);
        assert_eq!(verified.picture_url, None);
        assert_eq!(verified.display_name.as_deref(), Some("Display Name"));

        for (verified_email, expected) in [
            (Some(false), EmailVerification::Unverified),
            (None, EmailVerification::Unknown),
        ] {
            let identity = normalize_google_user_info(GoogleUserInfo {
                id: "google-subject".to_owned(),
                email: None,
                verified_email,
                name: None,
                picture: Some(String::new()),
            })
            .expect("valid identity");
            assert_eq!(identity.email, None);
            assert_eq!(identity.email_verification, expected);
            assert_eq!(identity.picture_url, None);
            assert_eq!(identity.display_name, None);
        }

        let empty_name = normalize_google_user_info(GoogleUserInfo {
            id: "google-subject".to_owned(),
            email: None,
            verified_email: None,
            name: Some(String::new()),
            picture: None,
        })
        .expect("valid identity");
        assert_eq!(empty_name.display_name, None);

        let whitespace_only_name = normalize_google_user_info(GoogleUserInfo {
            id: "google-subject".to_owned(),
            email: None,
            verified_email: None,
            name: Some("   ".to_owned()),
            picture: None,
        })
        .expect("valid identity");
        assert_eq!(whitespace_only_name.display_name, None);

        let surrounding_whitespace_name = normalize_google_user_info(GoogleUserInfo {
            id: "google-subject".to_owned(),
            email: None,
            verified_email: None,
            name: Some(" Alice Example ".to_owned()),
            picture: None,
        })
        .expect("valid identity");
        assert_eq!(
            surrounding_whitespace_name.display_name.as_deref(),
            Some(" Alice Example ")
        );
    }

    #[test]
    fn google_user_info_normalization_rejects_empty_or_oversized_subject() {
        for id in [
            String::new(),
            "s".repeat(crate::auth_foundation::SUBJECT_MAX_BYTES + 1),
        ] {
            assert!(normalize_google_user_info(GoogleUserInfo {
                id,
                email: None,
                verified_email: None,
                name: None,
                picture: None,
            })
            .is_err());
        }
    }

    #[actix_web::test]
    #[ignore = "requires disposable PostgreSQL and Redis 7"]
    async fn t10_login_http_integration_cases() {
        use crate::redis_state::{read_handoff, write_session, CommonSession};
        use sqlx::postgres::PgPoolOptions;
        use sqlx::Row;

        let database_url = std::env::var("AUTH_FOUNDATION_TEST_DATABASE_URL")
            .expect("AUTH_FOUNDATION_TEST_DATABASE_URL must be set");
        let redis_url = std::env::var("AUTH_FOUNDATION_TEST_REDIS_URL")
            .expect("AUTH_FOUNDATION_TEST_REDIS_URL must be set");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect disposable PostgreSQL");
        let redis_connection = redis::Client::open(redis_url)
            .expect("open disposable Redis")
            .get_multiplexed_tokio_connection()
            .await
            .expect("connect disposable Redis");
        let service_id = format!(
            "t10{}",
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time after epoch")
                .as_nanos()
        );
        async fn insert_service(pool: &PgPool, service_id: &str, enabled: bool) {
            sqlx::query(
                "INSERT INTO public.registered_web_services (service_id, is_enabled, login_callback_uri, logout_return_uri, service_secret_sha256)
                 VALUES ($1, $2, 'https://service.example.test/login?existing=value', 'https://service.example.test/logout', $3)",
            )
            .bind(service_id)
            .bind(enabled)
            .bind(vec![0_u8; 32])
            .execute(pool)
            .await
            .expect("insert registered service");
        }

        async fn state_key_count(
            connection: &mut redis::aio::MultiplexedConnection,
            pattern: &str,
        ) -> usize {
            let keys: Vec<String> = redis::cmd("KEYS")
                .arg(pattern)
                .query_async(connection)
                .await
                .expect("list disposable Redis keys");
            keys.len()
        }

        fn login_uri(service_id: &str, state: &str, challenge: &str, method: &str) -> String {
            format!(
                "/auth/login?service_id={service_id}&state={state}&code_challenge={challenge}&code_challenge_method={method}"
            )
        }

        fn google_state(response: &actix_web::dev::ServiceResponse) -> String {
            let location = response
                .headers()
                .get(header::LOCATION)
                .expect("Google Location")
                .to_str()
                .expect("valid Location");
            let url = reqwest::Url::parse(location).expect("valid Google URL");
            assert_eq!(url.host_str(), Some("accounts.google.com"));
            let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(pairs.get("response_type"), Some(&"code".to_owned()));
            assert_eq!(pairs.get("client_id"), Some(&"test-client".to_owned()));
            assert_eq!(
                pairs.get("redirect_uri"),
                Some(&"https://auth.example.test/auth/google/callback".to_owned())
            );
            assert_eq!(pairs.get("scope"), Some(&"email profile".to_owned()));
            assert!(!pairs.contains_key("access_type"));
            assert!(!pairs.contains_key("prompt"));
            let state = pairs.get("state").expect("OAuth state").to_owned();
            assert!(validate_fixed_reference_value(&state).is_ok());
            state
        }

        insert_service(&pool, &service_id, true).await;

        let google_config = GoogleAuthorizationConfig {
            client_id: "test-client".to_owned(),
            redirect_uri: RedirectUrl::new(
                "https://auth.example.test/auth/google/callback".to_owned(),
            )
            .expect("valid redirect URL"),
        };
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(redis_connection.clone()))
                .app_data(web::Data::new(google_config))
                .service(web::scope("").wrap(auth_security_headers()).service(login)),
        )
        .await;
        let challenge = "A".repeat(43);

        // A. Google 開始と ExternalAuthTransaction。
        let request = actix_web::test::TestRequest::get()
            .uri(&login_uri(&service_id, "service-state", &challenge, "S256"))
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::FOUND);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
        let oauth_state = google_state(&response);
        let mut connection = redis_connection.clone();
        let external = crate::redis_state::read_external(
            &mut connection,
            &oauth_state,
            unix_seconds(SystemTime::now()).expect("clock"),
        )
        .await
        .expect("external transaction");
        assert_eq!(external.service_id, service_id);
        assert_eq!(external.service_state, "service-state");
        assert_eq!(external.handoff_code_challenge, challenge);
        assert_eq!(external.provider, "google");
        assert_eq!(external.provider_verification_data, "");
        assert_eq!(external.status, ExternalStatus::Waiting);
        let observed_now = unix_seconds(SystemTime::now()).expect("clock");
        assert!(external.created_at <= observed_now);
        assert!(external.expires_at > observed_now);
        let _: i32 = redis::cmd("DEL")
            .arg(crate::redis_state::external_key(&oauth_state))
            .query_async(&mut connection)
            .await
            .expect("remove Redis state");

        // B. 有効 CommonSession による SSO handoff。
        let enabled_user: i32 = sqlx::query(
            "INSERT INTO public.internal_users DEFAULT VALUES RETURNING internal_user_id",
        )
        .fetch_one(&pool)
        .await
        .expect("insert enabled user")
        .try_get("internal_user_id")
        .expect("internal user id");
        let session_reference = generate_reference_value().expect("session reference");
        let now = unix_seconds(SystemTime::now()).expect("clock");
        let session = CommonSession {
            internal_user_id: enabled_user,
            authenticated_at: now - 10,
            created_at: now - 20,
            expires_at: now + 300,
        };
        write_session(&mut connection, &session_reference, &session, now)
            .await
            .expect("write CommonSession");
        let request = actix_web::test::TestRequest::get()
            .uri(&login_uri(&service_id, "sso-state", &challenge, "S256"))
            .cookie(Cookie::new(
                AUTH_SESSION_COOKIE_NAME,
                session_reference.clone(),
            ))
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::FOUND);
        let callback = reqwest::Url::parse(
            response
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .expect("callback Location");
        assert_eq!(callback.host_str(), Some("service.example.test"));
        let callback_pairs: std::collections::HashMap<_, _> =
            callback.query_pairs().into_owned().collect();
        assert_eq!(callback_pairs.get("state"), Some(&"sso-state".to_owned()));
        let handoff_reference = callback_pairs.get("code").expect("handoff code").to_owned();
        assert!(validate_fixed_reference_value(&handoff_reference).is_ok());
        let handoff = read_handoff(&mut connection, &handoff_reference, now)
            .await
            .expect("SSO handoff");
        assert_eq!(handoff.service_id, service_id);
        assert_eq!(handoff.internal_user_id, enabled_user);
        assert_eq!(
            handoff.common_session_lookup,
            reference_value_lookup(&session_reference)
        );
        assert_eq!(handoff.code_challenge, challenge);
        assert_eq!(handoff.authenticated_at, session.authenticated_at);
        assert_eq!(handoff.status, UsageStatus::Unused);
        assert!(handoff.expires_at > now);
        assert_eq!(state_key_count(&mut connection, "auth:external:*").await, 0);
        let _: i32 = redis::cmd("DEL")
            .arg(crate::redis_state::handoff_key(&handoff_reference))
            .arg(crate::redis_state::session_key(&session_reference))
            .query_async(&mut connection)
            .await
            .expect("remove SSO state");

        // C. 入力不正と duplicate query は副作用なし。
        for uri in [
            login_uri("INVALID!", "state", &challenge, "S256"),
            login_uri(&service_id, "", &challenge, "S256"),
            login_uri(&service_id, &"a".repeat(257), &challenge, "S256"),
            login_uri(&service_id, "state", "short", "S256"),
            login_uri(&service_id, "state", &challenge, "plain"),
            format!(
                "{}&service_id=other",
                login_uri(&service_id, "state", &challenge, "S256")
            ),
            format!(
                "{}&state=other",
                login_uri(&service_id, "state", &challenge, "S256")
            ),
            format!(
                "{}&code_challenge={}",
                login_uri(&service_id, "state", &challenge, "S256"),
                "B".repeat(43)
            ),
            format!(
                "{}&code_challenge_method=S256",
                login_uri(&service_id, "state", &challenge, "S256")
            ),
        ] {
            let external_before = state_key_count(&mut connection, "auth:external:*").await;
            let handoff_before = state_key_count(&mut connection, "auth:handoff:*").await;
            let response = actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get().uri(&uri).to_request(),
            )
            .await;
            assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert_eq!(
                response.headers().get(header::REFERRER_POLICY).unwrap(),
                "no-referrer"
            );
            assert!(response.headers().get(header::LOCATION).is_none());
            assert_eq!(
                state_key_count(&mut connection, "auth:external:*").await,
                external_before
            );
            assert_eq!(
                state_key_count(&mut connection, "auth:handoff:*").await,
                handoff_before
            );
        }

        // D. 未登録・disabled service は同じ 403 で副作用なし。
        let disabled_service_id = format!("t10disabled{}", service_id.trim_start_matches("t10"));
        insert_service(&pool, &disabled_service_id, false).await;
        for denied_service in ["t10unknown", disabled_service_id.as_str()] {
            let external_before = state_key_count(&mut connection, "auth:external:*").await;
            let response = actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get()
                    .uri(&login_uri(denied_service, "state", &challenge, "S256"))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), actix_web::http::StatusCode::FORBIDDEN);
            assert!(response.headers().get(header::LOCATION).is_none());
            assert_eq!(
                state_key_count(&mut connection, "auth:external:*").await,
                external_before
            );
            assert_eq!(state_key_count(&mut connection, "auth:handoff:*").await, 0);
        }

        // E. logical expiry は物理 TTL が残っていても削除され、Google開始へ進む。
        let expired_reference = generate_reference_value().expect("expired reference");
        let expired_key = crate::redis_state::session_key(&expired_reference);
        let now = unix_seconds(SystemTime::now()).expect("clock");
        let _: () = redis::cmd("HSET")
            .arg(&expired_key)
            .arg("internal_user_id")
            .arg(enabled_user)
            .arg("authenticated_at")
            .arg(now - 20)
            .arg("created_at")
            .arg(now - 30)
            .arg("expires_at")
            .arg(now - 1)
            .query_async(&mut connection)
            .await
            .expect("write logically expired session");
        let _: () = redis::cmd("EXPIREAT")
            .arg(&expired_key)
            .arg(now + 300)
            .query_async(&mut connection)
            .await
            .expect("retain physical TTL");
        let response = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&login_uri(&service_id, "expired-state", &challenge, "S256"))
                .cookie(Cookie::new(
                    AUTH_SESSION_COOKIE_NAME,
                    expired_reference.clone(),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), actix_web::http::StatusCode::FOUND);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
        let expired_oauth_state = google_state(&response);
        let exists: i32 = redis::cmd("EXISTS")
            .arg(&expired_key)
            .query_async(&mut connection)
            .await
            .expect("check expired deletion");
        assert_eq!(exists, 0);
        let _: i32 = redis::cmd("DEL")
            .arg(crate::redis_state::external_key(&expired_oauth_state))
            .query_async(&mut connection)
            .await
            .expect("remove external state");

        // F/G. disabled または欠損 InternalUser は Google fallback しない。
        let disabled_user: i32 = sqlx::query("INSERT INTO public.internal_users (is_enabled) VALUES (false) RETURNING internal_user_id")
            .fetch_one(&pool).await.expect("insert disabled user").try_get("internal_user_id").expect("user id");
        for user_id in [disabled_user, -1] {
            let reference = generate_reference_value().expect("session reference");
            let now = unix_seconds(SystemTime::now()).expect("clock");
            write_session(
                &mut connection,
                &reference,
                &CommonSession {
                    internal_user_id: user_id,
                    authenticated_at: now - 1,
                    created_at: now - 2,
                    expires_at: now + 300,
                },
                now,
            )
            .await
            .expect("write session");
            let response = actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get()
                    .uri(&login_uri(&service_id, "denied-user", &challenge, "S256"))
                    .cookie(Cookie::new(AUTH_SESSION_COOKIE_NAME, reference.clone()))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), actix_web::http::StatusCode::FORBIDDEN);
            assert!(response.headers().get(header::LOCATION).is_none());
            assert_eq!(state_key_count(&mut connection, "auth:external:*").await, 0);
            assert_eq!(state_key_count(&mut connection, "auth:handoff:*").await, 0);
            let _: i32 = redis::cmd("DEL")
                .arg(crate::redis_state::session_key(&reference))
                .query_async(&mut connection)
                .await
                .expect("remove denied session");
        }

        // I. 壊れた CommonSession は 503 であり Google fallback しない。
        let invalid_reference = generate_reference_value().expect("invalid reference");
        let invalid_key = crate::redis_state::session_key(&invalid_reference);
        let _: () = redis::cmd("HSET")
            .arg(&invalid_key)
            .arg("internal_user_id")
            .arg(enabled_user)
            .query_async(&mut connection)
            .await
            .expect("write invalid session");
        let _: () = redis::cmd("EXPIREAT")
            .arg(&invalid_key)
            .arg(unix_seconds(SystemTime::now()).expect("clock") + 300)
            .query_async(&mut connection)
            .await
            .expect("set invalid session TTL");
        let response = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&login_uri(&service_id, "invalid-redis", &challenge, "S256"))
                .cookie(Cookie::new(
                    AUTH_SESSION_COOKIE_NAME,
                    invalid_reference.clone(),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_eq!(state_key_count(&mut connection, "auth:external:*").await, 0);
        assert_eq!(state_key_count(&mut connection, "auth:handoff:*").await, 0);
        let _: i32 = redis::cmd("DEL")
            .arg(&invalid_key)
            .query_async(&mut connection)
            .await
            .expect("remove invalid session");

        // H. 閉じた専用 Pool は 503 で、serviceなしへ偽装されない。
        let closed_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("connect pool to close");
        closed_pool.close().await;
        let failed_app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(closed_pool))
                .app_data(web::Data::new(redis_connection.clone()))
                .app_data(web::Data::new(GoogleAuthorizationConfig {
                    client_id: "test-client".to_owned(),
                    redirect_uri: RedirectUrl::new(
                        "https://auth.example.test/auth/google/callback".to_owned(),
                    )
                    .unwrap(),
                }))
                .service(web::scope("").wrap(auth_security_headers()).service(login)),
        )
        .await;
        let response = actix_web::test::call_service(
            &failed_app,
            actix_web::test::TestRequest::get()
                .uri(&login_uri(
                    &service_id,
                    "database-failure",
                    &challenge,
                    "S256",
                ))
                .to_request(),
        )
        .await;
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_eq!(state_key_count(&mut connection, "auth:external:*").await, 0);
        assert_eq!(state_key_count(&mut connection, "auth:handoff:*").await, 0);

        sqlx::query("DELETE FROM public.registered_web_services WHERE service_id = $1")
            .bind(&service_id)
            .execute(&pool)
            .await
            .expect("remove registered service");
        sqlx::query("DELETE FROM public.registered_web_services WHERE service_id = $1")
            .bind(&disabled_service_id)
            .execute(&pool)
            .await
            .expect("remove disabled service");
        sqlx::query("DELETE FROM public.internal_users WHERE internal_user_id = $1 OR internal_user_id = $2")
            .bind(enabled_user).bind(disabled_user).execute(&pool).await.expect("remove users");
    }

    #[actix_web::test]
    #[ignore = "requires disposable PostgreSQL and Redis 7"]
    async fn t11_google_callback_http_integration_cases() {
        use crate::redis_state::{read_external, read_handoff, read_session};
        use sqlx::postgres::PgPoolOptions;
        use sqlx::Row;
        use std::net::TcpListener;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        #[derive(Clone)]
        struct FakeGoogle {
            token_calls: Arc<AtomicUsize>,
            userinfo_calls: Arc<AtomicUsize>,
            mode: Arc<AtomicUsize>,
        }

        async fn token(google: web::Data<FakeGoogle>) -> HttpResponse {
            google.token_calls.fetch_add(1, Ordering::SeqCst);
            if google.mode.load(Ordering::SeqCst) == 1 {
                HttpResponse::BadGateway().finish()
            } else {
                HttpResponse::Ok().json(serde_json::json!({
                    "access_token": "test-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }))
            }
        }

        async fn userinfo(google: web::Data<FakeGoogle>) -> HttpResponse {
            google.userinfo_calls.fetch_add(1, Ordering::SeqCst);
            match google.mode.load(Ordering::SeqCst) {
                2 => HttpResponse::BadGateway().finish(),
                3 => HttpResponse::Ok().json(serde_json::json!({"id": ""})),
                4 => HttpResponse::Ok().json(serde_json::json!({"id": "google-subject-disabled"})),
                _ => HttpResponse::Ok().json(serde_json::json!({
                    "id": "google-subject-new",
                    "email": "user@example.test",
                    "verified_email": true,
                    "name": "Google User",
                    "picture": "https://example.test/picture.png"
                })),
            }
        }

        async fn insert_service(pool: &PgPool, service_id: &str, enabled: bool) {
            sqlx::query(
                "INSERT INTO public.registered_web_services (service_id, is_enabled, login_callback_uri, logout_return_uri, service_secret_sha256) \
                 VALUES ($1, $2, 'https://service.example.test/login?existing=value', 'https://service.example.test/logout', $3)",
            )
            .bind(service_id)
            .bind(enabled)
            .bind(vec![7_u8; 32])
            .execute(pool)
            .await
            .expect("insert service");
        }

        async fn insert_external(
            connection: &mut redis::aio::MultiplexedConnection,
            reference: &str,
            service_id: &str,
            service_state: &str,
        ) {
            let now = unix_seconds(SystemTime::now()).expect("clock");
            write_external(
                connection,
                reference,
                &ExternalAuthTransaction {
                    service_id: service_id.to_owned(),
                    service_state: service_state.to_owned(),
                    handoff_code_challenge: "A".repeat(43),
                    provider: "google".to_owned(),
                    provider_verification_data: String::new(),
                    created_at: now,
                    expires_at: now + 600,
                    status: ExternalStatus::Waiting,
                },
                now,
            )
            .await
            .expect("write external transaction");
        }

        async fn redis_key_count(
            connection: &mut redis::aio::MultiplexedConnection,
            pattern: &str,
        ) -> usize {
            redis::cmd("KEYS")
                .arg(pattern)
                .query_async::<Vec<String>>(connection)
                .await
                .expect("count Redis state")
                .len()
        }

        fn callback_uri(code: &str, state: &str) -> String {
            format!("/auth/google/callback?code={code}&state={state}")
        }

        let database_url = std::env::var("AUTH_FOUNDATION_TEST_DATABASE_URL")
            .expect("AUTH_FOUNDATION_TEST_DATABASE_URL");
        let redis_url = std::env::var("AUTH_FOUNDATION_TEST_REDIS_URL")
            .expect("AUTH_FOUNDATION_TEST_REDIS_URL");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("connect disposable PostgreSQL");
        let redis_connection = redis::Client::open(redis_url)
            .expect("open disposable Redis")
            .get_multiplexed_tokio_connection()
            .await
            .expect("connect disposable Redis");
        let suffix = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        let service_id = format!("t11{suffix}");
        insert_service(&pool, &service_id, true).await;

        let fake_google = FakeGoogle {
            token_calls: Arc::new(AtomicUsize::new(0)),
            userinfo_calls: Arc::new(AtomicUsize::new(0)),
            mode: Arc::new(AtomicUsize::new(0)),
        };
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Google");
        let address = listener.local_addr().expect("fake Google address");
        let fake_google_server_state = fake_google.clone();
        let fake_google_server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(fake_google_server_state.clone()))
                .route("/token", web::post().to(token))
                .route("/userinfo", web::get().to(userinfo))
        })
        .listen(listener)
        .expect("listen fake Google")
        .run();
        let fake_google_handle = fake_google_server.handle();
        actix_web::rt::spawn(fake_google_server);
        let token_url = format!("http://{address}/token");
        let userinfo_url = format!("http://{address}/userinfo");
        let google_config = GoogleCallbackConfig {
            oauth_client: BasicClient::new(
                ClientId::new("test-client".to_owned()),
                Some(ClientSecret::new("test-secret".to_owned())),
                AuthUrl::new("https://accounts.example.test/authorize".to_owned())
                    .expect("authorization URL"),
                Some(TokenUrl::new(token_url).expect("token URL")),
            )
            .set_redirect_uri(
                RedirectUrl::new("https://auth.example.test/auth/google/callback".to_owned())
                    .expect("redirect URL"),
            ),
            userinfo_url: reqwest::Url::parse(&userinfo_url).expect("userinfo URL"),
        };
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(redis_connection.clone()))
                .app_data(web::Data::new(google_config))
                .service(
                    web::scope("")
                        .wrap(auth_security_headers())
                        .service(google_auth_callback),
                ),
        )
        .await;

        // 正常 callback: 新規本人、Cookie、handoff、二重 callback。
        let new_reference = generate_reference_value().expect("external reference");
        insert_external(
            &mut redis_connection.clone(),
            &new_reference,
            &service_id,
            "new-state",
        )
        .await;
        let users_before: i64 = sqlx::query_scalar("SELECT count(*) FROM public.internal_users")
            .fetch_one(&pool)
            .await
            .expect("count users");
        let response = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&callback_uri("valid-code", &new_reference))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), actix_web::http::StatusCode::FOUND);
        let location = reqwest::Url::parse(
            response
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .expect("callback Location");
        assert_eq!(location.host_str(), Some("service.example.test"));
        let pairs: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs.get("state"), Some(&"new-state".to_owned()));
        let handoff_reference = pairs.get("code").expect("handoff code").to_owned();
        assert!(!location.as_str().contains("google-subject-new"));
        assert!(!location.as_str().contains("user@example.test"));
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .expect("auth cookie")
            .to_str()
            .unwrap();
        assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 1);
        assert!(set_cookie.starts_with("__Host-auth_session="));
        for attribute in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(set_cookie.contains(attribute));
        }
        assert!(!set_cookie.contains("Domain="));
        assert!(!set_cookie.contains("Max-Age="));
        assert!(!set_cookie.contains("Expires="));
        let session_reference = Cookie::parse(set_cookie.to_owned())
            .expect("parse cookie")
            .value()
            .to_owned();
        let now = unix_seconds(SystemTime::now()).expect("clock");
        let mut connection = redis_connection.clone();
        let external = read_external(&mut connection, &new_reference, now)
            .await
            .expect("claimed transaction");
        assert_eq!(external.status, ExternalStatus::Processing);
        let session = read_session(&mut connection, &session_reference, now)
            .await
            .expect("CommonSession");
        assert_eq!(session.authenticated_at, session.created_at);
        assert_eq!(
            session.expires_at - session.created_at,
            COMMON_SESSION_TTL_SECONDS
        );
        let handoff = read_handoff(&mut connection, &handoff_reference, now)
            .await
            .expect("handoff");
        assert_eq!(handoff.service_id, service_id);
        assert_eq!(handoff.internal_user_id, session.internal_user_id);
        assert_eq!(
            handoff.common_session_lookup,
            reference_value_lookup(&session_reference)
        );
        assert_eq!(handoff.code_challenge, external.handoff_code_challenge);
        assert_eq!(handoff.authenticated_at, session.authenticated_at);
        assert_eq!(handoff.issued_at, session.authenticated_at);
        assert_eq!(
            handoff.expires_at - handoff.issued_at,
            AUTHENTICATION_HANDOFF_TTL_SECONDS
        );
        assert_eq!(handoff.status, UsageStatus::Unused);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.internal_users")
                .fetch_one(&pool)
                .await
                .unwrap(),
            users_before + 1
        );
        assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.external_identities WHERE provider = 'google' AND subject = 'google-subject-new'").fetch_one(&pool).await.unwrap(), 1);
        assert_eq!(fake_google.token_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fake_google.userinfo_calls.load(Ordering::SeqCst), 1);
        let sessions_before = redis_key_count(&mut connection, "auth:session:*").await;
        let handoffs_before = redis_key_count(&mut connection, "auth:handoff:*").await;
        let duplicate = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&callback_uri("valid-code", &new_reference))
                .to_request(),
        )
        .await;
        assert_eq!(duplicate.status(), actix_web::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            duplicate.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            duplicate.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
        assert_eq!(fake_google.token_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fake_google.userinfo_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            redis_key_count(&mut connection, "auth:session:*").await,
            sessions_before
        );
        assert_eq!(
            redis_key_count(&mut connection, "auth:handoff:*").await,
            handoffs_before
        );

        // 既存本人は provider + subject のみで解決し、新規ユーザーを作らない。
        let existing_user: i32 = sqlx::query(
            "INSERT INTO public.internal_users DEFAULT VALUES RETURNING internal_user_id",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("internal_user_id")
        .unwrap();
        sqlx::query("INSERT INTO public.external_identities (provider, subject, internal_user_id) VALUES ('google', 'google-subject-new', $1) ON CONFLICT (provider, subject) DO UPDATE SET internal_user_id = EXCLUDED.internal_user_id")
            .bind(existing_user).execute(&pool).await.unwrap();
        let existing_reference = generate_reference_value().unwrap();
        insert_external(
            &mut connection,
            &existing_reference,
            &service_id,
            "existing-state",
        )
        .await;
        let users_before_existing: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.internal_users")
                .fetch_one(&pool)
                .await
                .unwrap();
        let existing_response = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&callback_uri("existing-code", &existing_reference))
                .to_request(),
        )
        .await;
        assert_eq!(
            existing_response.status(),
            actix_web::http::StatusCode::FOUND
        );
        let existing_cookie = Cookie::parse(
            existing_response
                .headers()
                .get(header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap()
        .value()
        .to_owned();
        assert_eq!(
            read_session(
                &mut connection,
                &existing_cookie,
                unix_seconds(SystemTime::now()).unwrap()
            )
            .await
            .unwrap()
            .internal_user_id,
            existing_user
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.internal_users")
                .fetch_one(&pool)
                .await
                .unwrap(),
            users_before_existing
        );

        // query validation は claim/Google 呼出前に止まる。
        let input_reference = generate_reference_value().unwrap();
        insert_external(
            &mut connection,
            &input_reference,
            &service_id,
            "input-state",
        )
        .await;
        let token_before = fake_google.token_calls.load(Ordering::SeqCst);
        let userinfo_before = fake_google.userinfo_calls.load(Ordering::SeqCst);
        for uri in [
            format!("/auth/google/callback?state={input_reference}"),
            format!("/auth/google/callback?code=&state={input_reference}"),
            callback_uri(&"x".repeat(4097), &input_reference),
            callback_uri("code", "invalid"),
            format!("{}&code=other", callback_uri("code", &input_reference)),
            format!("{}&state=other", callback_uri("code", &input_reference)),
            format!("/auth/google/callback?error=access_denied&state={input_reference}"),
        ] {
            let rejected = actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get().uri(&uri).to_request(),
            )
            .await;
            assert_eq!(rejected.status(), actix_web::http::StatusCode::BAD_REQUEST);
        }
        assert_eq!(
            read_external(
                &mut connection,
                &input_reference,
                unix_seconds(SystemTime::now()).unwrap()
            )
            .await
            .unwrap()
            .status,
            ExternalStatus::Waiting
        );
        assert_eq!(fake_google.token_calls.load(Ordering::SeqCst), token_before);
        assert_eq!(
            fake_google.userinfo_calls.load(Ordering::SeqCst),
            userinfo_before
        );

        // disabled user は claim 後に 403、service disabled は Google 呼出前に 403。
        let disabled_user: i32 = sqlx::query("INSERT INTO public.internal_users (is_enabled) VALUES (false) RETURNING internal_user_id").fetch_one(&pool).await.unwrap().try_get("internal_user_id").unwrap();
        sqlx::query("INSERT INTO public.external_identities (provider, subject, internal_user_id) VALUES ('google', 'google-subject-disabled', $1)").bind(disabled_user).execute(&pool).await.unwrap();
        fake_google.mode.store(4, Ordering::SeqCst);
        let disabled_reference = generate_reference_value().unwrap();
        insert_external(
            &mut connection,
            &disabled_reference,
            &service_id,
            "disabled-state",
        )
        .await;
        let disabled_sessions = redis_key_count(&mut connection, "auth:session:*").await;
        let disabled_handoffs = redis_key_count(&mut connection, "auth:handoff:*").await;
        let disabled_response = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&callback_uri("disabled-user", &disabled_reference))
                .to_request(),
        )
        .await;
        assert_eq!(
            disabled_response.status(),
            actix_web::http::StatusCode::FORBIDDEN
        );
        assert!(disabled_response.headers().get(header::LOCATION).is_none());
        assert!(disabled_response
            .headers()
            .get(header::SET_COOKIE)
            .is_none());
        assert_eq!(
            read_external(
                &mut connection,
                &disabled_reference,
                unix_seconds(SystemTime::now()).unwrap()
            )
            .await
            .unwrap()
            .status,
            ExternalStatus::Processing
        );
        assert_eq!(
            redis_key_count(&mut connection, "auth:session:*").await,
            disabled_sessions
        );
        assert_eq!(
            redis_key_count(&mut connection, "auth:handoff:*").await,
            disabled_handoffs
        );

        // Google token failure: processing に固定され、再送しても再実行しない。
        fake_google.mode.store(1, Ordering::SeqCst);
        let token_failure_reference = generate_reference_value().unwrap();
        insert_external(
            &mut connection,
            &token_failure_reference,
            &service_id,
            "token-failure",
        )
        .await;
        let token_calls_before = fake_google.token_calls.load(Ordering::SeqCst);
        let userinfo_calls_before = fake_google.userinfo_calls.load(Ordering::SeqCst);
        let token_failure = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&callback_uri("token-failure", &token_failure_reference))
                .to_request(),
        )
        .await;
        assert_eq!(
            token_failure.status(),
            actix_web::http::StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            read_external(
                &mut connection,
                &token_failure_reference,
                unix_seconds(SystemTime::now()).unwrap()
            )
            .await
            .unwrap()
            .status,
            ExternalStatus::Processing
        );
        assert_eq!(
            fake_google.token_calls.load(Ordering::SeqCst),
            token_calls_before + 1
        );
        assert_eq!(
            fake_google.userinfo_calls.load(Ordering::SeqCst),
            userinfo_calls_before
        );
        assert!(token_failure.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(
            redis_key_count(&mut connection, "auth:session:*").await,
            disabled_sessions
        );
        assert_eq!(
            redis_key_count(&mut connection, "auth:handoff:*").await,
            disabled_handoffs
        );
        let token_retry = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&callback_uri("token-failure", &token_failure_reference))
                .to_request(),
        )
        .await;
        assert_eq!(
            token_retry.status(),
            actix_web::http::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            fake_google.token_calls.load(Ordering::SeqCst),
            token_calls_before + 1
        );

        // userinfo failure と不正 identity は、session/handoff/cookie を作らず 502。
        for mode in [2, 3] {
            fake_google.mode.store(mode, Ordering::SeqCst);
            let reference = generate_reference_value().unwrap();
            insert_external(&mut connection, &reference, &service_id, "userinfo-failure").await;
            let sessions = redis_key_count(&mut connection, "auth:session:*").await;
            let handoffs = redis_key_count(&mut connection, "auth:handoff:*").await;
            let response = actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get()
                    .uri(&callback_uri("userinfo-failure", &reference))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), actix_web::http::StatusCode::BAD_GATEWAY);
            assert!(response.headers().get(header::SET_COOKIE).is_none());
            assert_eq!(
                redis_key_count(&mut connection, "auth:session:*").await,
                sessions
            );
            assert_eq!(
                redis_key_count(&mut connection, "auth:handoff:*").await,
                handoffs
            );
        }

        // service disabled after start は claim 後、Google 呼出前に停止する。
        fake_google.mode.store(0, Ordering::SeqCst);
        let disabled_service_id = format!("t11disabled{suffix}");
        insert_service(&pool, &disabled_service_id, true).await;
        let service_disabled_reference = generate_reference_value().unwrap();
        insert_external(
            &mut connection,
            &service_disabled_reference,
            &disabled_service_id,
            "service-disabled",
        )
        .await;
        sqlx::query(
            "UPDATE public.registered_web_services SET is_enabled = false WHERE service_id = $1",
        )
        .bind(&disabled_service_id)
        .execute(&pool)
        .await
        .unwrap();
        let token_before_disabled = fake_google.token_calls.load(Ordering::SeqCst);
        let userinfo_before_disabled = fake_google.userinfo_calls.load(Ordering::SeqCst);
        let service_disabled = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&callback_uri(
                    "service-disabled",
                    &service_disabled_reference,
                ))
                .to_request(),
        )
        .await;
        assert_eq!(
            service_disabled.status(),
            actix_web::http::StatusCode::FORBIDDEN
        );
        assert_eq!(
            read_external(
                &mut connection,
                &service_disabled_reference,
                unix_seconds(SystemTime::now()).unwrap()
            )
            .await
            .unwrap()
            .status,
            ExternalStatus::Processing
        );
        assert_eq!(
            fake_google.token_calls.load(Ordering::SeqCst),
            token_before_disabled
        );
        assert_eq!(
            fake_google.userinfo_calls.load(Ordering::SeqCst),
            userinfo_before_disabled
        );

        // 壊れた ExternalAuthTransaction は 503 で Google に到達しない。
        let invalid_redis_reference = generate_reference_value().unwrap();
        insert_external(
            &mut connection,
            &invalid_redis_reference,
            &service_id,
            "invalid-redis",
        )
        .await;
        let _: i32 = redis::cmd("HDEL")
            .arg(crate::redis_state::external_key(&invalid_redis_reference))
            .arg("service_id")
            .query_async(&mut connection)
            .await
            .unwrap();
        let token_before_invalid_redis = fake_google.token_calls.load(Ordering::SeqCst);
        let invalid_redis = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&callback_uri("invalid-redis", &invalid_redis_reference))
                .to_request(),
        )
        .await;
        assert_eq!(
            invalid_redis.status(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            fake_google.token_calls.load(Ordering::SeqCst),
            token_before_invalid_redis
        );

        fake_google_handle.stop(true).await;
    }

    #[actix_web::test]
    #[ignore = "requires disposable PostgreSQL and Redis 7"]
    async fn t12_handoff_exchange_and_common_logout_http_integration() {
        use crate::auth_foundation::sha256_digest;
        use crate::redis_state::{
            read_handoff, read_logout, read_session, write_handoff, write_logout, write_session,
            AuthenticationHandoff, CommonLogoutTransaction, CommonSession, UsageStatus,
        };
        use sqlx::postgres::PgPoolOptions;
        use sqlx::Row;

        let database_url = std::env::var("AUTH_FOUNDATION_TEST_DATABASE_URL")
            .expect("AUTH_FOUNDATION_TEST_DATABASE_URL must be set");
        let redis_url = std::env::var("AUTH_FOUNDATION_TEST_REDIS_URL")
            .expect("AUTH_FOUNDATION_TEST_REDIS_URL must be set");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect disposable PostgreSQL");
        let redis_connection = redis::Client::open(redis_url)
            .expect("open disposable Redis")
            .get_multiplexed_tokio_connection()
            .await
            .expect("connect disposable Redis");
        let suffix = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let service_id = format!("t12{suffix}");
        let other_service_id = format!("t12other{suffix}");
        let disabled_service_id = format!("t12disabled{suffix}");
        let secret = "t12-service-secret";
        for (id, enabled) in [
            (&service_id, true),
            (&other_service_id, true),
            (&disabled_service_id, false),
        ] {
            sqlx::query("INSERT INTO public.registered_web_services (service_id, is_enabled, login_callback_uri, logout_return_uri, service_secret_sha256) VALUES ($1, $2, 'https://service.example.test/login', 'https://service.example.test/logout-old', $3)")
                .bind(id).bind(enabled).bind(sha256_digest(secret.as_bytes()).to_vec()).execute(&pool).await.expect("insert service");
        }
        let user_id: i32 = sqlx::query(
            "INSERT INTO public.internal_users DEFAULT VALUES RETURNING internal_user_id",
        )
        .fetch_one(&pool)
        .await
        .expect("insert user")
        .try_get("internal_user_id")
        .expect("user id");
        let now = unix_seconds(SystemTime::now()).expect("clock");
        let session_reference = generate_reference_value().expect("session reference");
        let mut connection = redis_connection.clone();
        write_session(
            &mut connection,
            &session_reference,
            &CommonSession {
                internal_user_id: user_id,
                authenticated_at: now - 1,
                created_at: now - 2,
                expires_at: now + 300,
            },
            now,
        )
        .await
        .expect("write session");
        let verifier = "v".repeat(43);
        let challenge = pkce_s256_challenge(&verifier).expect("PKCE challenge");
        let handoff_reference = generate_reference_value().expect("handoff reference");
        let handoff = AuthenticationHandoff {
            service_id: service_id.clone(),
            internal_user_id: user_id,
            common_session_lookup: reference_value_lookup(&session_reference),
            code_challenge: challenge.clone(),
            authenticated_at: now - 1,
            issued_at: now,
            expires_at: now + 120,
            status: UsageStatus::Unused,
        };
        write_handoff(&mut connection, &handoff_reference, &handoff, now)
            .await
            .expect("write handoff");
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(redis_connection.clone()))
                .service(
                    web::scope("")
                        .wrap(auth_security_headers())
                        .service(
                            web::resource("/auth/handoffs/exchange")
                                .app_data(web::JsonConfig::default().limit(HTTP_BODY_MAX_BYTES))
                                .route(web::post().to(exchange_auth_handoff)),
                        )
                        .service(
                            web::resource("/auth/logout")
                                .app_data(web::FormConfig::default().limit(HTTP_BODY_MAX_BYTES))
                                .route(web::get().to(logout_get))
                                .route(web::post().to(logout_post)),
                        ),
                ),
        )
        .await;
        let basic =
            |id: &str, value: &str| format!("Basic {}", STANDARD.encode(format!("{id}:{value}")));
        let exchange_body =
            |code: &str, value: &str| format!(r#"{{"code":"{code}","code_verifier":"{value}"}}"#);
        let response = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::AUTHORIZATION, basic(&service_id, secret)))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&handoff_reference, &verifier))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let response_body = String::from_utf8(actix_web::test::read_body(response).await.to_vec())
            .expect("JSON body");
        assert!(
            response_body.contains("internal_user_id")
                && response_body.contains("authenticated_at")
        );
        for forbidden in [
            "provider",
            "subject",
            "email",
            "code",
            "cookie",
            "common_session",
        ] {
            assert!(!response_body.to_ascii_lowercase().contains(forbidden));
        }
        assert_eq!(
            read_handoff(&mut connection, &handoff_reference, now)
                .await
                .expect("used handoff")
                .status,
            UsageStatus::Used
        );
        let second = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::AUTHORIZATION, basic(&service_id, secret)))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&handoff_reference, &verifier))
                .to_request(),
        )
        .await;
        assert_eq!(second.status(), actix_web::http::StatusCode::BAD_REQUEST);
        for request in [
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&handoff_reference, &verifier))
                .to_request(),
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::AUTHORIZATION, "Basic not-base64"))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&handoff_reference, &verifier))
                .to_request(),
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::AUTHORIZATION, basic(&service_id, "wrong")))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&handoff_reference, &verifier))
                .to_request(),
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::AUTHORIZATION, basic("t12unknown", secret)))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&handoff_reference, &verifier))
                .to_request(),
        ] {
            assert_eq!(
                actix_web::test::call_service(&app, request).await.status(),
                actix_web::http::StatusCode::UNAUTHORIZED
            );
        }
        let disabled = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::AUTHORIZATION, basic(&disabled_service_id, secret)))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&handoff_reference, &verifier))
                .to_request(),
        )
        .await;
        assert_eq!(disabled.status(), actix_web::http::StatusCode::FORBIDDEN);
        let oversized = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload("x".repeat(HTTP_BODY_MAX_BYTES + 1))
                .to_request(),
        )
        .await;
        assert_eq!(
            oversized.status(),
            actix_web::http::StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            oversized.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            oversized.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );

        // T12 残件: exchange の拒否系は handoff を消費しない。
        let exchange_handoff = |_reference: &str,
                                bound_service: String,
                                challenge: String,
                                expires_at| AuthenticationHandoff {
            service_id: bound_service,
            internal_user_id: user_id,
            common_session_lookup: reference_value_lookup(&session_reference),
            code_challenge: challenge,
            authenticated_at: now - 1,
            issued_at: now,
            expires_at,
            status: UsageStatus::Unused,
        };
        let pkce_reference = generate_reference_value().expect("PKCE handoff");
        write_handoff(
            &mut connection,
            &pkce_reference,
            &exchange_handoff(
                &pkce_reference,
                service_id.clone(),
                challenge.clone(),
                now + 120,
            ),
            now,
        )
        .await
        .expect("write PKCE handoff");
        let pkce = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::AUTHORIZATION, basic(&service_id, secret)))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&pkce_reference, &"w".repeat(43)))
                .to_request(),
        )
        .await;
        assert_eq!(pkce.status(), actix_web::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            read_handoff(&mut connection, &pkce_reference, now)
                .await
                .unwrap()
                .status,
            UsageStatus::Unused
        );

        let service_mismatch_reference =
            generate_reference_value().expect("service mismatch handoff");
        write_handoff(
            &mut connection,
            &service_mismatch_reference,
            &exchange_handoff(
                &service_mismatch_reference,
                service_id.clone(),
                challenge.clone(),
                now + 120,
            ),
            now,
        )
        .await
        .expect("write mismatch handoff");
        let service_mismatch = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::AUTHORIZATION, basic(&other_service_id, secret)))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&service_mismatch_reference, &verifier))
                .to_request(),
        )
        .await;
        assert_eq!(
            service_mismatch.status(),
            actix_web::http::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            read_handoff(&mut connection, &service_mismatch_reference, now)
                .await
                .unwrap()
                .status,
            UsageStatus::Unused
        );

        let expired_reference = generate_reference_value().expect("expired handoff");
        let expired = exchange_handoff(
            &expired_reference,
            service_id.clone(),
            challenge.clone(),
            now + 300,
        );
        write_handoff(&mut connection, &expired_reference, &expired, now)
            .await
            .expect("write expired fixture");
        redis::cmd("HSET")
            .arg(crate::redis_state::handoff_key(&expired_reference))
            .arg("expires_at")
            .arg((now - 1).to_string())
            .query_async::<()>(&mut connection)
            .await
            .unwrap();
        let expired_response = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::AUTHORIZATION, basic(&service_id, secret)))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&expired_reference, &verifier))
                .to_request(),
        )
        .await;
        assert_eq!(
            expired_response.status(),
            actix_web::http::StatusCode::BAD_REQUEST
        );

        let invalid_reference = generate_reference_value().expect("invalid handoff");
        write_handoff(
            &mut connection,
            &invalid_reference,
            &exchange_handoff(
                &invalid_reference,
                service_id.clone(),
                challenge.clone(),
                now + 120,
            ),
            now,
        )
        .await
        .unwrap();
        redis::cmd("HSET")
            .arg(crate::redis_state::handoff_key(&invalid_reference))
            .arg("status")
            .arg("broken")
            .query_async::<()>(&mut connection)
            .await
            .unwrap();
        let invalid = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::AUTHORIZATION, basic(&service_id, secret)))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&invalid_reference, &verifier))
                .to_request(),
        )
        .await;
        assert_eq!(
            invalid.status(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );

        let invalid_code = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .insert_header((header::AUTHORIZATION, basic(&service_id, secret)))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body("bad", &verifier))
                .to_request(),
        )
        .await;
        assert_eq!(
            invalid_code.status(),
            actix_web::http::StatusCode::BAD_REQUEST
        );
        let duplicate_authorization = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/handoffs/exchange")
                .append_header((header::AUTHORIZATION, basic(&service_id, secret)))
                .append_header((header::AUTHORIZATION, basic(&service_id, secret)))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(exchange_body(&pkce_reference, &verifier))
                .to_request(),
        )
        .await;
        assert_eq!(
            duplicate_authorization.status(),
            actix_web::http::StatusCode::UNAUTHORIZED
        );
        for payload in [
            format!(
                r#"{{\"code\":\"{pkce_reference}\",\"code\":\"{pkce_reference}\",\"code_verifier\":\"{verifier}\"}}"#
            ),
            format!(
                r#"{{\"code\":\"{pkce_reference}\",\"code_verifier\":\"{verifier}\",\"code_verifier\":\"{verifier}\"}}"#
            ),
        ] {
            let duplicate_json = actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::post()
                    .uri("/auth/handoffs/exchange")
                    .insert_header((header::AUTHORIZATION, basic(&service_id, secret)))
                    .insert_header((header::CONTENT_TYPE, "application/json"))
                    .set_payload(payload)
                    .to_request(),
            )
            .await;
            assert_eq!(
                duplicate_json.status(),
                actix_web::http::StatusCode::BAD_REQUEST
            );
        }

        let get = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&format!("/auth/logout?service_id={service_id}"))
                .cookie(Cookie::new(
                    AUTH_SESSION_COOKIE_NAME,
                    session_reference.clone(),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(get.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            get.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            get.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
        let html =
            String::from_utf8(actix_web::test::read_body(get).await.to_vec()).expect("logout HTML");
        assert!(
            html.contains("<form method=\"post\" action=\"/auth/logout\">")
                && html.contains("logout_reference")
                && html.contains("csrf_token")
        );
        let field = |name: &str| {
            html.split(&format!("name=\"{name}\" value=\""))
                .nth(1)
                .and_then(|v| v.split('\"').next())
                .expect("form field")
                .to_owned()
        };
        let logout_reference = field("logout_reference");
        let csrf_token = field("csrf_token");
        let logout = read_logout(&mut connection, &logout_reference, now)
            .await
            .expect("logout transaction");
        assert_eq!(logout.service_id, service_id);
        assert_eq!(
            logout.logout_return_uri,
            "https://service.example.test/logout-old"
        );
        assert_eq!(logout.csrf_lookup, reference_value_lookup(&csrf_token));
        assert_eq!(logout.status, UsageStatus::Unused);
        assert_eq!(
            read_session(&mut connection, &session_reference, now)
                .await
                .expect("session retained")
                .internal_user_id,
            user_id
        );
        for (payload, cookie) in [
            (format!("csrf_token={csrf_token}"), Some(session_reference.clone())),
            (format!("logout_reference={logout_reference}"), Some(session_reference.clone())),
            (format!("logout_reference=bad&csrf_token={csrf_token}"), Some(session_reference.clone())),
            (format!("logout_reference={logout_reference}&csrf_token=bad"), Some(session_reference.clone())),
            (format!("logout_reference={logout_reference}&csrf_token={csrf_token}"), None),
            (format!("logout_reference={logout_reference}&csrf_token={csrf_token}"), Some("bad".to_owned())),
            (format!("logout_reference={logout_reference}&logout_reference={logout_reference}&csrf_token={csrf_token}"), Some(session_reference.clone())),
            (format!("logout_reference={logout_reference}&csrf_token={csrf_token}&csrf_token={csrf_token}"), Some(session_reference.clone())),
        ] {
            let mut request = actix_web::test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .set_payload(payload);
            if let Some(value) = cookie { request = request.cookie(Cookie::new(AUTH_SESSION_COOKIE_NAME, value)); }
            let response = actix_web::test::call_service(&app, request.to_request()).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
            assert!(response.headers().get(header::SET_COOKIE).is_none());
            assert_eq!(read_logout(&mut connection, &logout_reference, now).await.unwrap().status, UsageStatus::Unused);
        }
        let no_cookie = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&format!("/auth/logout?service_id={service_id}"))
                .to_request(),
        )
        .await;
        assert_eq!(no_cookie.status(), actix_web::http::StatusCode::FOUND);
        let malformed_cookie = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri(&format!("/auth/logout?service_id={service_id}"))
                .cookie(Cookie::new(AUTH_SESSION_COOKIE_NAME, "bad"))
                .to_request(),
        )
        .await;
        assert_eq!(
            malformed_cookie.status(),
            actix_web::http::StatusCode::FOUND
        );
        for denied in ["t12unknown", disabled_service_id.as_str()] {
            assert_eq!(
                actix_web::test::call_service(
                    &app,
                    actix_web::test::TestRequest::get()
                        .uri(&format!("/auth/logout?service_id={denied}"))
                        .to_request()
                )
                .await
                .status(),
                actix_web::http::StatusCode::FORBIDDEN
            );
        }
        let csrf_mismatch = format!("x{}", &csrf_token[1..]);
        let mismatch = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .cookie(Cookie::new(
                    AUTH_SESSION_COOKIE_NAME,
                    session_reference.clone(),
                ))
                .set_payload(format!(
                    "logout_reference={logout_reference}&csrf_token={csrf_mismatch}"
                ))
                .to_request(),
        )
        .await;
        assert_eq!(mismatch.status(), actix_web::http::StatusCode::FORBIDDEN);
        assert_eq!(
            read_logout(&mut connection, &logout_reference, now)
                .await
                .expect("unused transaction")
                .status,
            UsageStatus::Unused
        );
        sqlx::query("UPDATE public.registered_web_services SET logout_return_uri = 'https://service.example.test/logout-new' WHERE service_id = $1").bind(&service_id).execute(&pool).await.expect("change DB URI");
        let post = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .cookie(Cookie::new(
                    AUTH_SESSION_COOKIE_NAME,
                    session_reference.clone(),
                ))
                .set_payload(format!(
                    "logout_reference={logout_reference}&csrf_token={csrf_token}"
                ))
                .to_request(),
        )
        .await;
        assert_eq!(post.status(), actix_web::http::StatusCode::SEE_OTHER);
        assert_eq!(
            post.headers().get(header::LOCATION).unwrap(),
            "https://service.example.test/logout-old"
        );
        let set_cookie = post
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .expect("Set-Cookie");
        for required in [
            "__Host-auth_session=",
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=0",
        ] {
            assert!(set_cookie.contains(required));
        }
        assert!(!set_cookie.contains("Domain=") && !set_cookie.contains("Expires="));
        assert_eq!(
            read_logout(&mut connection, &logout_reference, now)
                .await
                .expect("used transaction")
                .status,
            UsageStatus::Used
        );
        assert!(matches!(
            read_session(&mut connection, &session_reference, now).await,
            Err(crate::redis_state::RedisStateError::NotFound)
        ));
        let form_too_large = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .set_payload("x".repeat(HTTP_BODY_MAX_BYTES + 1))
                .to_request(),
        )
        .await;
        assert_eq!(
            form_too_large.status(),
            actix_web::http::StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            form_too_large.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            form_too_large
                .headers()
                .get(header::REFERRER_POLICY)
                .unwrap(),
            "no-referrer"
        );

        let expired_session_reference =
            generate_reference_value().expect("expired session reference");
        write_session(
            &mut connection,
            &expired_session_reference,
            &CommonSession {
                internal_user_id: user_id,
                authenticated_at: now - 1,
                created_at: now - 2,
                expires_at: now + 300,
            },
            now,
        )
        .await
        .expect("write expired session");
        let expired_logout_reference =
            generate_reference_value().expect("expired logout reference");
        let expired_csrf = generate_reference_value().expect("expired csrf");
        write_logout(
            &mut connection,
            &expired_logout_reference,
            &CommonLogoutTransaction {
                service_id: service_id.clone(),
                logout_return_uri: "https://service.example.test/logout-expired".to_owned(),
                csrf_lookup: reference_value_lookup(&expired_csrf),
                created_at: now - 2,
                expires_at: now + 300,
                status: UsageStatus::Unused,
            },
            now,
        )
        .await
        .expect("write expired logout");
        redis::cmd("HSET")
            .arg(crate::redis_state::logout_key(&expired_logout_reference))
            .arg("expires_at")
            .arg((now - 1).to_string())
            .query_async::<()>(&mut connection)
            .await
            .expect("make logout logically expired");
        let expired_post = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .cookie(Cookie::new(
                    AUTH_SESSION_COOKIE_NAME,
                    expired_session_reference.clone(),
                ))
                .set_payload(format!(
                    "logout_reference={expired_logout_reference}&csrf_token={expired_csrf}"
                ))
                .to_request(),
        )
        .await;
        assert_eq!(
            expired_post.status(),
            actix_web::http::StatusCode::BAD_REQUEST
        );
        assert!(expired_post.headers().get(header::SET_COOKIE).is_none());
        assert!(expired_post.headers().get(header::LOCATION).is_none());
        assert!(
            read_session(&mut connection, &expired_session_reference, now)
                .await
                .is_ok()
        );

        let used_session_reference = generate_reference_value().expect("used session reference");
        write_session(
            &mut connection,
            &used_session_reference,
            &CommonSession {
                internal_user_id: user_id,
                authenticated_at: now - 1,
                created_at: now - 2,
                expires_at: now + 300,
            },
            now,
        )
        .await
        .expect("write used session");
        let used_logout_reference = generate_reference_value().expect("used logout reference");
        let used_csrf = generate_reference_value().expect("used csrf");
        write_logout(
            &mut connection,
            &used_logout_reference,
            &CommonLogoutTransaction {
                service_id: service_id.clone(),
                logout_return_uri: "https://service.example.test/logout-used".to_owned(),
                csrf_lookup: reference_value_lookup(&used_csrf),
                created_at: now,
                expires_at: now + 300,
                status: UsageStatus::Unused,
            },
            now,
        )
        .await
        .expect("write used logout");
        let used_payload =
            format!("logout_reference={used_logout_reference}&csrf_token={used_csrf}");
        let first_used = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .cookie(Cookie::new(
                    AUTH_SESSION_COOKIE_NAME,
                    used_session_reference.clone(),
                ))
                .set_payload(used_payload.clone())
                .to_request(),
        )
        .await;
        assert_eq!(first_used.status(), actix_web::http::StatusCode::SEE_OTHER);
        let second_used = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .cookie(Cookie::new(
                    AUTH_SESSION_COOKIE_NAME,
                    used_session_reference.clone(),
                ))
                .set_payload(used_payload)
                .to_request(),
        )
        .await;
        assert_eq!(
            second_used.status(),
            actix_web::http::StatusCode::BAD_REQUEST
        );
        assert!(second_used.headers().get(header::SET_COOKIE).is_none());
        assert!(second_used.headers().get(header::LOCATION).is_none());

        let invalid_session_reference =
            generate_reference_value().expect("invalid session reference");
        write_session(
            &mut connection,
            &invalid_session_reference,
            &CommonSession {
                internal_user_id: user_id,
                authenticated_at: now - 1,
                created_at: now - 2,
                expires_at: now + 300,
            },
            now,
        )
        .await
        .expect("write invalid session");
        let invalid_logout_reference =
            generate_reference_value().expect("invalid logout reference");
        let invalid_csrf = generate_reference_value().expect("invalid csrf");
        write_logout(
            &mut connection,
            &invalid_logout_reference,
            &CommonLogoutTransaction {
                service_id: service_id.clone(),
                logout_return_uri: "https://service.example.test/logout-invalid".to_owned(),
                csrf_lookup: reference_value_lookup(&invalid_csrf),
                created_at: now,
                expires_at: now + 300,
                status: UsageStatus::Unused,
            },
            now,
        )
        .await
        .expect("write invalid logout");
        redis::cmd("HSET")
            .arg(crate::redis_state::logout_key(&invalid_logout_reference))
            .arg("csrf_lookup")
            .arg("invalid")
            .query_async::<()>(&mut connection)
            .await
            .expect("corrupt logout transaction");
        let invalid_post = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .cookie(Cookie::new(
                    AUTH_SESSION_COOKIE_NAME,
                    invalid_session_reference.clone(),
                ))
                .set_payload(format!(
                    "logout_reference={invalid_logout_reference}&csrf_token={invalid_csrf}"
                ))
                .to_request(),
        )
        .await;
        assert_eq!(
            invalid_post.status(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(invalid_post.headers().get(header::SET_COOKIE).is_none());
        assert!(invalid_post.headers().get(header::LOCATION).is_none());
        assert!(
            read_session(&mut connection, &invalid_session_reference, now)
                .await
                .is_ok()
        );

        let absent_session_reference =
            generate_reference_value().expect("absent session reference");
        write_session(
            &mut connection,
            &absent_session_reference,
            &CommonSession {
                internal_user_id: user_id,
                authenticated_at: now - 1,
                created_at: now - 2,
                expires_at: now + 300,
            },
            now,
        )
        .await
        .expect("write absent session");
        let absent_logout_reference = generate_reference_value().expect("absent logout reference");
        let absent_csrf = generate_reference_value().expect("absent csrf");
        let absent_return_uri = "https://service.example.test/logout-absent";
        write_logout(
            &mut connection,
            &absent_logout_reference,
            &CommonLogoutTransaction {
                service_id: service_id.clone(),
                logout_return_uri: absent_return_uri.to_owned(),
                csrf_lookup: reference_value_lookup(&absent_csrf),
                created_at: now,
                expires_at: now + 300,
                status: UsageStatus::Unused,
            },
            now,
        )
        .await
        .expect("write absent logout");
        redis::cmd("DEL")
            .arg(crate::redis_state::session_key(&absent_session_reference))
            .query_async::<()>(&mut connection)
            .await
            .expect("remove session before logout");
        let absent_post = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .cookie(Cookie::new(
                    AUTH_SESSION_COOKIE_NAME,
                    absent_session_reference,
                ))
                .set_payload(format!(
                    "logout_reference={absent_logout_reference}&csrf_token={absent_csrf}"
                ))
                .to_request(),
        )
        .await;
        assert_eq!(absent_post.status(), actix_web::http::StatusCode::SEE_OTHER);
        assert_eq!(
            absent_post.headers().get(header::LOCATION).unwrap(),
            absent_return_uri
        );
        assert!(absent_post.headers().get(header::SET_COOKIE).is_some());
        assert_eq!(
            read_logout(&mut connection, &absent_logout_reference, now)
                .await
                .expect("used absent-session logout")
                .status,
            UsageStatus::Used
        );

        let concurrent_session_reference =
            generate_reference_value().expect("concurrent session reference");
        write_session(
            &mut connection,
            &concurrent_session_reference,
            &CommonSession {
                internal_user_id: user_id,
                authenticated_at: now - 1,
                created_at: now - 2,
                expires_at: now + 300,
            },
            now,
        )
        .await
        .expect("write concurrent session");
        let concurrent_handoff_reference =
            generate_reference_value().expect("concurrent handoff reference");
        write_handoff(
            &mut connection,
            &concurrent_handoff_reference,
            &AuthenticationHandoff {
                service_id: service_id.clone(),
                internal_user_id: user_id,
                common_session_lookup: reference_value_lookup(&concurrent_session_reference),
                code_challenge: challenge.clone(),
                authenticated_at: now - 1,
                issued_at: now,
                expires_at: now + 120,
                status: UsageStatus::Unused,
            },
            now,
        )
        .await
        .expect("write concurrent handoff");
        let concurrent_app_a = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(redis_connection.clone()))
                .service(
                    web::scope("").wrap(auth_security_headers()).service(
                        web::resource("/auth/handoffs/exchange")
                            .app_data(web::JsonConfig::default().limit(HTTP_BODY_MAX_BYTES))
                            .route(web::post().to(exchange_auth_handoff)),
                    ),
                ),
        )
        .await;
        let concurrent_app_b = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(redis_connection.clone()))
                .service(
                    web::scope("").wrap(auth_security_headers()).service(
                        web::resource("/auth/handoffs/exchange")
                            .app_data(web::JsonConfig::default().limit(HTTP_BODY_MAX_BYTES))
                            .route(web::post().to(exchange_auth_handoff)),
                    ),
                ),
        )
        .await;
        let concurrent_authorization = basic(&service_id, secret);
        let concurrent_payload = exchange_body(&concurrent_handoff_reference, &verifier);
        let concurrent_service_id = service_id.clone();
        let concurrent_handoff_for_second = concurrent_handoff_reference.clone();
        let concurrent_verifier = verifier.clone();
        let first_exchange = actix_web::rt::spawn(async move {
            actix_web::test::call_service(
                &concurrent_app_a,
                actix_web::test::TestRequest::post()
                    .uri("/auth/handoffs/exchange")
                    .insert_header((header::AUTHORIZATION, concurrent_authorization))
                    .insert_header((header::CONTENT_TYPE, "application/json"))
                    .set_payload(concurrent_payload)
                    .to_request(),
            )
            .await
        });
        let second_exchange = actix_web::rt::spawn(async move {
            actix_web::test::call_service(
                &concurrent_app_b,
                actix_web::test::TestRequest::post()
                    .uri("/auth/handoffs/exchange")
                    .insert_header((header::AUTHORIZATION, basic(&concurrent_service_id, secret)))
                    .insert_header((header::CONTENT_TYPE, "application/json"))
                    .set_payload(exchange_body(
                        &concurrent_handoff_for_second,
                        &concurrent_verifier,
                    ))
                    .to_request(),
            )
            .await
        });
        let first_exchange = first_exchange
            .await
            .expect("first concurrent exchange task");
        let second_exchange = second_exchange
            .await
            .expect("second concurrent exchange task");
        let success_count = [first_exchange.status(), second_exchange.status()]
            .into_iter()
            .filter(|status| *status == actix_web::http::StatusCode::OK)
            .count();
        assert_eq!(
            success_count, 1,
            "exactly one concurrent exchange must succeed"
        );
        assert_eq!(
            read_handoff(&mut connection, &concurrent_handoff_reference, now)
                .await
                .expect("used concurrent handoff")
                .status,
            UsageStatus::Used
        );
        sqlx::query("DELETE FROM public.registered_web_services WHERE service_id IN ($1, $2)")
            .bind(&service_id)
            .bind(&disabled_service_id)
            .execute(&pool)
            .await
            .expect("cleanup services");
        redis::cmd("DEL")
            .arg(crate::redis_state::handoff_key(&handoff_reference))
            .arg(crate::redis_state::logout_key(&logout_reference))
            .arg(crate::redis_state::session_key(&session_reference))
            .query_async::<()>(&mut connection)
            .await
            .expect("cleanup Redis state");
    }
}
