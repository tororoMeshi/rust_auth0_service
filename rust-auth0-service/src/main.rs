// src/main.rs for rust-auth0-service

// 必要なクレートのインポート
// T02で定義し、後続の認証タスクから順次接続する。
#[allow(dead_code)]
mod auth_foundation;
mod postgres;
mod redis_state;

#[allow(unused_imports)]
use actix_cors::Cors;
#[allow(unused_imports)]
use actix_web::http::header;

use actix_session::storage::RedisSessionStore;
use actix_session::{Session, SessionMiddleware};
use actix_web::cookie::{time::Duration, Cookie, Key, SameSite};
use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer};
use dotenv::dotenv;
use log::{error, info};
use oauth2::reqwest::async_http_client;
use oauth2::TokenResponse;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    Scope, TokenUrl,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::{env, io, time::SystemTime};

use crate::auth_foundation::{
    checked_expires_at, generate_reference_value, reference_value_lookup, unix_seconds,
    validate_fixed_reference_value, validate_max_bytes, validate_service_id, EmailVerification,
    NormalizedExternalIdentity, OAUTH_CODE_MAX_BYTES, SERVICE_STATE_MAX_BYTES,
};
use crate::postgres::{
    lookup_login_callback_uri, read_internal_user_enabled, resolve_external_identity,
    PostgresAuthError,
};
use crate::redis_state::{
    claim_external_callback, create_session_and_handoff, issue_sso_handoff, read_session,
    write_external, AuthenticationHandoff, CommonSession, ExternalAuthTransaction, ExternalStatus,
    RedisStateError, UsageStatus, AUTHENTICATION_HANDOFF_TTL_SECONDS, COMMON_SESSION_TTL_SECONDS,
    EXTERNAL_AUTH_TRANSACTION_TTL_SECONDS,
};

const AUTH_SESSION_COOKIE_NAME: &str = "__Host-auth_session";
const GOOGLE_AUTHORIZATION_URL: &str = "https://accounts.google.com/o/oauth2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";

#[derive(Clone)]
struct AppConfig {
    google_client_id: String,
    google_redirect_uri: String,
    uniauth_url: String,
}

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

fn required_env(name: &str) -> io::Result<String> {
    env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} environment variable is required"),
        )
    })
}

fn app_base_url() -> String {
    env::var("APP_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string())
        .trim_end_matches('/')
        .to_string()
}

fn split_csv_env(name: &str) -> Vec<String> {
    env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_end_matches('/').to_string())
        .collect()
}

fn allowed_redirect_origins() -> Vec<String> {
    let mut origins = split_csv_env("ALLOWED_REDIRECT_ORIGINS");
    let base_url = app_base_url();

    if !origins.iter().any(|origin| origin == &base_url) {
        origins.push(base_url);
    }

    origins
}

fn allowed_cors_origins() -> Vec<String> {
    let origins = split_csv_env("ALLOWED_CORS_ORIGINS");

    if origins.is_empty() {
        allowed_redirect_origins()
    } else {
        origins
    }
}

fn post_login_redirect() -> String {
    env::var("POST_LOGIN_REDIRECT").unwrap_or_else(|_| format!("{}/", app_base_url()))
}

fn cookie_domain() -> Option<String> {
    env::var("COOKIE_DOMAIN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn is_allowed_absolute_redirect(raw_redirect: &str, allowed_origin: &str) -> bool {
    if raw_redirect == allowed_origin {
        return true;
    }

    raw_redirect
        .strip_prefix(allowed_origin)
        .and_then(|rest| rest.chars().next())
        .is_some_and(|next| matches!(next, '/' | '?' | '#'))
}

fn is_allowed_post_login_redirect(raw_redirect: &str, allowed_origins: &[String]) -> bool {
    if raw_redirect.starts_with('/') && !raw_redirect.starts_with("//") {
        return true;
    }

    allowed_origins
        .iter()
        .any(|origin| is_allowed_absolute_redirect(raw_redirect, origin))
}

fn validate_post_login_redirect(raw_redirect: &str, allowed_origins: &[String]) -> io::Result<()> {
    if is_allowed_post_login_redirect(raw_redirect, allowed_origins) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "POST_LOGIN_REDIRECT must match one of the allowed redirect origins or a relative path: {raw_redirect}"
            ),
        ))
    }
}

fn resolve_redirect_url(raw_redirect: &str) -> String {
    let base_url = app_base_url();

    if raw_redirect.starts_with('/') && !raw_redirect.starts_with("//") {
        return format!("{}{}", base_url, raw_redirect);
    }

    if allowed_redirect_origins()
        .iter()
        .any(|origin| is_allowed_absolute_redirect(raw_redirect, origin))
    {
        return raw_redirect.to_string();
    }

    post_login_redirect()
}

fn build_auth_cookie(name: &'static str, value: String) -> Cookie<'static> {
    let mut builder = Cookie::build(name, value)
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict);

    if let Some(domain) = cookie_domain() {
        builder = builder.domain(domain);
    }

    builder.finish()
}

fn build_expired_auth_cookie(name: &'static str) -> Cookie<'static> {
    let mut builder = Cookie::build(name, "")
        .path("/")
        .max_age(Duration::seconds(0))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict);

    if let Some(domain) = cookie_domain() {
        builder = builder.domain(domain);
    }

    builder.finish()
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

// クエリパラメータ用構造体
#[derive(Debug, Deserialize)]
struct StartAuthQuery {
    redirect: Option<String>,
}

// Google OAuth 認証開始エンドポイント
#[get("/auth/google")]
async fn start_google_auth(
    session: Session,
    query: web::Query<StartAuthQuery>,
    config: web::Data<AppConfig>,
) -> HttpResponse {
    // CSRF 対策用の state を生成しセッションに保存
    let state: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    if let Err(_) = session.insert("oauth_state", state.clone()) {
        error!("Failed to store OAuth request data in legacy session");
        return HttpResponse::InternalServerError()
            .body("Internal server error: cannot set oauth_state");
    }

    // ログイン前のリダイレクト先をセッションに保存
    if let Some(ref redirect) = query.redirect {
        if let Err(_) = session.insert("redirect", redirect) {
            error!("Failed to store redirect in legacy session");
            return HttpResponse::InternalServerError()
                .body("Internal server error: cannot set redirect");
        }
    }

    // Google OAuth 認可 URL を生成
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={}&redirect_uri={}&scope=email%20profile&access_type=offline&prompt=consent&state={}",
        config.google_client_id, config.google_redirect_uri, state
    );
    info!("redirecting to Google authorization endpoint");

    HttpResponse::Found()
        .append_header(("Location", auth_url))
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

#[post("/auth/logout")]
async fn logout(req: HttpRequest, config: web::Data<AppConfig>) -> HttpResponse {
    if let Some(cookie) = req.cookie("session_id") {
        if let Err(_) = request_logout_from_uniauth(&config.uniauth_url, cookie.value()).await {
            error!("legacy uniauth logout request failed");
        }
    }

    HttpResponse::Ok()
        .cookie(build_expired_auth_cookie("session_id"))
        .cookie(build_expired_auth_cookie("jwt"))
        .body("Logged out")
}

async fn request_logout_from_uniauth(
    uniauth_url: &str,
    session_id: &str,
) -> Result<(), reqwest::Error> {
    let url = format!("{}/logout", uniauth_url);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Cookie", format!("session_id={}", session_id))
        .send()
        .await?;
    if !resp.status().is_success() {
        error!("Uniauth logout returned error status: {}", resp.status());
        return Err(resp.error_for_status().unwrap_err());
    }

    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    // CORS の設定
    use actix_cors::Cors;
    use actix_web::http::header;

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

    let config = AppConfig {
        google_client_id: auth_foundation_config.google_client_id.clone(),
        google_redirect_uri: auth_foundation_config.google_redirect_uri.clone(),
        uniauth_url: env::var("UNIAUTH_URL").unwrap_or_else(|_| "http://uniauth:8081".to_string()),
    };
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

    let allowed_redirect_origins = allowed_redirect_origins();
    let post_login_redirect = post_login_redirect();
    validate_post_login_redirect(&post_login_redirect, &allowed_redirect_origins)?;

    // RedisSessionStore の初期化
    let redis_store = RedisSessionStore::new(auth_foundation_config.redis_url.clone())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "failed to create legacy Redis session store",
            )
        })?;

    drop(auth_foundation_config);

    // セッション Cookie 署名用の秘密鍵
    let secret_key = required_env("SESSION_SECRET_KEY")?;

    HttpServer::new(move || {
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::ACCEPT,
                header::CONTENT_TYPE,
            ])
            .supports_credentials();

        for origin in allowed_cors_origins() {
            cors = cors.allowed_origin(&origin);
        }

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(config.clone()))
            .app_data(web::Data::new(google_authorization_config.clone()))
            .app_data(google_callback_config.clone())
            .app_data(web::Data::new(postgres_pool.clone()))
            .app_data(web::Data::new(redis_connection.clone()))
            .app_data(web::Data::new(redis_store.clone()))
            .wrap(SessionMiddleware::new(
                redis_store.clone(),
                Key::from(secret_key.as_bytes()),
            ))
            .service(login)
            .service(start_google_auth)
            .service(google_auth_callback)
            .service(logout)
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
                .service(login),
        )
        .await;
        let challenge = "A".repeat(43);

        // A. Google 開始と ExternalAuthTransaction。
        let request = actix_web::test::TestRequest::get()
            .uri(&login_uri(&service_id, "service-state", &challenge, "S256"))
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::FOUND);
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
                .service(login),
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
                .service(google_auth_callback),
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

    #[test]
    fn post_login_redirect_accepts_relative_path() {
        let allowed = vec!["https://portal.example.com".to_string()];
        assert!(is_allowed_post_login_redirect("/dashboard", &allowed));
    }

    #[test]
    fn post_login_redirect_accepts_allowed_absolute_url() {
        let allowed = vec!["https://portal.example.com".to_string()];
        assert!(is_allowed_post_login_redirect(
            "https://portal.example.com/dashboard",
            &allowed
        ));
    }

    #[test]
    fn post_login_redirect_rejects_disallowed_absolute_url() {
        let allowed = vec!["https://portal.example.com".to_string()];
        assert!(!is_allowed_post_login_redirect(
            "https://evil.example.com/dashboard",
            &allowed
        ));
        assert!(
            validate_post_login_redirect("https://evil.example.com/dashboard", &allowed).is_err()
        );
    }
}
