use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use cookie::Cookie;
use cookie::SameSite;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use url::Url;
use warp::Filter;

const LOGIN_START_TTL_SECONDS: u64 = 600;
const LOCAL_SESSION_TTL_SECONDS: u64 = 28_800;
const LOCAL_STATE_CLEANUP_INTERVAL_SECONDS: u64 = 60;
const PORTAL_LOGIN_CONTEXT_COOKIE_NAME: &str = "__Host-portal_login_ctx";
const PORTAL_SESSION_COOKIE_NAME: &str = "__Host-portal_session";
const PORTAL_CSRF_COOKIE_NAME: &str = "__Host-portal_csrf";
const REFERENCE_RANDOM_BYTES: usize = 32;
const POST_LOGIN_PATH_MAX_BYTES: usize = 2048;

struct AppConfig {
    service_id: String,
    service_secret: String,
    auth_foundation_base_url: Url,
    login_start_capacity: usize,
    local_session_capacity: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum ConfigError {
    MissingEnvironment(&'static str),
    InvalidEnvironment(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvironment(name) => {
                write!(formatter, "required environment variable {name} is not set")
            }
            Self::InvalidEnvironment(name) => {
                write!(formatter, "invalid environment variable {name}")
            }
        }
    }
}

impl AppConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let service_id = required_env("PORTAL_SERVICE_ID")?;
        validate_service_id(&service_id)?;
        let service_secret = required_env("PORTAL_SERVICE_SECRET")?;
        validate_service_secret(&service_secret)?;
        let auth_foundation_base_url =
            parse_auth_foundation_base_url(&required_env("PORTAL_AUTH_FOUNDATION_BASE_URL")?)?;
        Ok(Self {
            service_id,
            service_secret,
            auth_foundation_base_url,
            login_start_capacity: capacity_from_env("PORTAL_LOGIN_START_CAPACITY", 10_000)?,
            local_session_capacity: capacity_from_env("PORTAL_LOCAL_SESSION_CAPACITY", 50_000)?,
        })
    }
}

fn required_env(name: &'static str) -> Result<String, ConfigError> {
    env::var(name).map_err(|_| ConfigError::MissingEnvironment(name))
}

fn validate_service_id(value: &str) -> Result<(), ConfigError> {
    let bytes = value.as_bytes();
    let valid = (1..=64).contains(&bytes.len())
        && matches!(bytes.first(), Some(b'a'..=b'z' | b'0'..=b'9'))
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
    valid
        .then_some(())
        .ok_or(ConfigError::InvalidEnvironment("PORTAL_SERVICE_ID"))
}

fn validate_service_secret(value: &str) -> Result<(), ConfigError> {
    (!value.is_empty())
        .then_some(())
        .ok_or(ConfigError::InvalidEnvironment("PORTAL_SERVICE_SECRET"))
}

fn parse_auth_foundation_base_url(value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value)
        .map_err(|_| ConfigError::InvalidEnvironment("PORTAL_AUTH_FOUNDATION_BASE_URL"))?;
    if matches!(url.scheme(), "http" | "https") && url.host().is_some() {
        Ok(url)
    } else {
        Err(ConfigError::InvalidEnvironment(
            "PORTAL_AUTH_FOUNDATION_BASE_URL",
        ))
    }
}

fn capacity_from_env(name: &'static str, default: usize) -> Result<usize, ConfigError> {
    match env::var(name) {
        Ok(value) => parse_capacity(Some(&value), name, default),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(ConfigError::InvalidEnvironment(name)),
    }
}

fn parse_capacity(
    value: Option<&str>,
    name: &'static str,
    default: usize,
) -> Result<usize, ConfigError> {
    match value {
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|capacity| *capacity > 0)
            .ok_or(ConfigError::InvalidEnvironment(name)),
        None => Ok(default),
    }
}

struct AppState {
    config: AppConfig,
    local_state: Mutex<PortalLocalState>,
}

struct LoginStart {
    browser_context_reference: String,
    code_verifier: String,
    post_login_path: String,
    created_at: u64,
    expires_at: u64,
}

struct CreatedLoginStart {
    state: String,
    browser_context_reference: String,
    code_challenge: String,
}

struct LocalSession {
    internal_user_id: i32,
    authenticated_at: u64,
    created_at: u64,
    expires_at: u64,
    csrf_lookup: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
enum LocalStateError {
    CapacityReached,
    NotFound,
    Expired,
    BrowserContextMismatch,
    InvalidPostLoginPath,
    ExpiryOverflow,
}

struct PortalLocalState {
    login_starts: HashMap<String, LoginStart>,
    local_sessions: HashMap<String, LocalSession>,
    login_start_capacity: usize,
    local_session_capacity: usize,
}

impl PortalLocalState {
    fn new(login_start_capacity: usize, local_session_capacity: usize) -> Self {
        Self {
            login_starts: HashMap::new(),
            local_sessions: HashMap::new(),
            login_start_capacity,
            local_session_capacity,
        }
    }

    fn cleanup_expired(&mut self, now: u64) {
        self.login_starts
            .retain(|_, record| record.expires_at > now);
        self.local_sessions
            .retain(|_, record| record.expires_at > now);
    }

    fn create_login_start(
        &mut self,
        post_login_path: String,
        now: u64,
    ) -> Result<CreatedLoginStart, LocalStateError> {
        validate_post_login_path(&post_login_path)?;
        self.cleanup_expired(now);
        if self.login_starts.len() >= self.login_start_capacity {
            return Err(LocalStateError::CapacityReached);
        }
        let expires_at = now
            .checked_add(LOGIN_START_TTL_SECONDS)
            .ok_or(LocalStateError::ExpiryOverflow)?;
        loop {
            let state = random_reference();
            if self.login_starts.contains_key(&state) {
                continue;
            }
            let browser_context_reference = random_reference();
            let code_verifier = random_reference();
            let code_challenge = sha256_base64url(code_verifier.as_bytes());
            self.login_starts.insert(
                state.clone(),
                LoginStart {
                    browser_context_reference: browser_context_reference.clone(),
                    code_verifier,
                    post_login_path,
                    created_at: now,
                    expires_at,
                },
            );
            return Ok(CreatedLoginStart {
                state,
                browser_context_reference,
                code_challenge,
            });
        }
    }

    fn claim_login_start(
        &mut self,
        state: &str,
        browser_context_reference: &str,
        now: u64,
    ) -> Result<LoginStart, LocalStateError> {
        let record = self
            .login_starts
            .get(state)
            .ok_or(LocalStateError::NotFound)?;
        if record.expires_at <= now {
            self.login_starts.remove(state);
            return Err(LocalStateError::Expired);
        }
        if record.browser_context_reference != browser_context_reference {
            return Err(LocalStateError::BrowserContextMismatch);
        }
        self.login_starts
            .remove(state)
            .ok_or(LocalStateError::NotFound)
    }

    fn create_local_session(
        &mut self,
        internal_user_id: i32,
        authenticated_at: u64,
        now: u64,
    ) -> Result<(String, String), LocalStateError> {
        self.cleanup_expired(now);
        if self.local_sessions.len() >= self.local_session_capacity {
            return Err(LocalStateError::CapacityReached);
        }
        let expires_at = now
            .checked_add(LOCAL_SESSION_TTL_SECONDS)
            .ok_or(LocalStateError::ExpiryOverflow)?;
        loop {
            let reference = random_reference();
            if self.local_sessions.contains_key(&reference) {
                continue;
            }
            let csrf_plaintext = random_reference();
            self.local_sessions.insert(
                reference.clone(),
                LocalSession {
                    internal_user_id,
                    authenticated_at,
                    created_at: now,
                    expires_at,
                    csrf_lookup: sha256_digest(csrf_plaintext.as_bytes()),
                },
            );
            return Ok((reference, csrf_plaintext));
        }
    }

    fn get_local_session(&mut self, reference: &str, now: u64) -> Option<&LocalSession> {
        if self
            .local_sessions
            .get(reference)
            .is_some_and(|record| record.expires_at <= now)
        {
            self.local_sessions.remove(reference);
            return None;
        }
        self.local_sessions.get(reference)
    }

    fn remove_local_session(&mut self, reference: &str) -> Option<LocalSession> {
        self.local_sessions.remove(reference)
    }
}

fn validate_post_login_path(value: &str) -> Result<(), LocalStateError> {
    if value.is_empty()
        || value.len() > POST_LOGIN_PATH_MAX_BYTES
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
    {
        return Err(LocalStateError::InvalidPostLoginPath);
    }
    Ok(())
}

fn random_reference() -> String {
    let mut bytes = [0_u8; REFERENCE_RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn sha256_base64url(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(sha256_digest(value))
}

fn login_context_cookie(value: String) -> Cookie<'static> {
    Cookie::build((PORTAL_LOGIN_CONTEXT_COOKIE_NAME, value))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .build()
}

fn portal_session_cookie(value: String) -> Cookie<'static> {
    Cookie::build((PORTAL_SESSION_COOKIE_NAME, value))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .build()
}

fn portal_csrf_cookie(value: String) -> Cookie<'static> {
    Cookie::build((PORTAL_CSRF_COOKIE_NAME, value))
        .path("/")
        .secure(true)
        .http_only(false)
        .same_site(SameSite::Lax)
        .build()
}

fn unix_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    user: Claims,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    timestamp: String,
}

async fn get_me(cookie_header: Option<String>) -> Result<impl warp::Reply, warp::Rejection> {
    let now = Utc::now();
    println!("[{}] GET /api/me", now.to_rfc3339());

    let jwt_secret = match env::var("JWT_SECRET") {
        Ok(secret) => secret,
        Err(_) => {
            eprintln!("JWT_SECRET environment variable is not set.");
            return Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse {
                    error: "Internal server error".to_string(),
                    details: None,
                }),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let token = match cookie_header {
        Some(cookie_str) => {
            let mut jwt_token = None;
            for cookie_part in cookie_str.split(';') {
                if let Ok(cookie) = Cookie::parse(cookie_part.trim()) {
                    if cookie.name() == "jwt" {
                        jwt_token = Some(cookie.value().to_string());
                        break;
                    }
                }
            }
            match jwt_token {
                Some(token) => token,
                None => {
                    return Ok(warp::reply::with_status(
                        warp::reply::json(&ErrorResponse {
                            error: "Not authenticated: JWT missing".to_string(),
                            details: None,
                        }),
                        warp::http::StatusCode::UNAUTHORIZED,
                    ));
                }
            }
        }
        None => {
            return Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse {
                    error: "Not authenticated: JWT missing".to_string(),
                    details: None,
                }),
                warp::http::StatusCode::UNAUTHORIZED,
            ));
        }
    };

    let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);

    match decode::<Claims>(&token, &decoding_key, &validation) {
        Ok(token_data) => Ok(warp::reply::with_status(
            warp::reply::json(&UserResponse {
                user: token_data.claims,
            }),
            warp::http::StatusCode::OK,
        )),
        Err(err) => {
            eprintln!("JWT verification failed: {:?}", err);
            Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse {
                    error: "Invalid JWT".to_string(),
                    details: Some(err.to_string()),
                }),
                warp::http::StatusCode::UNAUTHORIZED,
            ))
        }
    }
}

async fn health() -> Result<impl warp::Reply, warp::Rejection> {
    let timestamp = Utc::now().to_rfc3339();
    Ok(warp::reply::json(&HealthResponse {
        status: "OK".to_string(),
        timestamp,
    }))
}

#[tokio::main]
async fn main() {
    let config = match AppConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Portal configuration error: {error}");
            return;
        }
    };
    let state = Arc::new(AppState {
        local_state: Mutex::new(PortalLocalState::new(
            config.login_start_capacity,
            config.local_session_capacity,
        )),
        config,
    });
    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(LOCAL_STATE_CLEANUP_INTERVAL_SECONDS));
        loop {
            interval.tick().await;
            cleanup_state
                .local_state
                .lock()
                .await
                .cleanup_expired(unix_epoch_seconds());
        }
    });

    let port = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);

    let frontend_url =
        env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let cors = warp::cors()
        .allow_origin(frontend_url.as_str())
        .allow_headers(vec!["content-type", "cookie"])
        .allow_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        .allow_credentials(true);

    let me_route = warp::path!("api" / "me")
        .and(warp::get())
        .and(warp::header::optional::<String>("cookie"))
        .and_then(get_me);

    let health_route = warp::path!("health").and(warp::get()).and_then(health);

    let routes = me_route
        .or(health_route)
        .with(cors)
        .with(warp::log("portal_backend"));

    println!("Backend server running on port {}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_state() -> PortalLocalState {
        PortalLocalState::new(10, 10)
    }

    #[test]
    fn service_id_validation_accepts_and_rejects_expected_values() {
        assert!(validate_service_id("portal-dev").is_ok());
        for invalid in ["", "Portal", "-portal", "portal!", &"a".repeat(65)] {
            assert_eq!(
                validate_service_id(invalid),
                Err(ConfigError::InvalidEnvironment("PORTAL_SERVICE_ID"))
            );
        }
    }

    #[test]
    fn auth_foundation_url_validation_accepts_http_and_https_only() {
        assert_eq!(
            parse_auth_foundation_base_url("http://localhost:8080")
                .unwrap()
                .scheme(),
            "http"
        );
        assert_eq!(
            parse_auth_foundation_base_url("https://auth.example.com")
                .unwrap()
                .scheme(),
            "https"
        );
        for invalid in ["/relative", "ftp://auth.example.com", "https://"] {
            assert_eq!(
                parse_auth_foundation_base_url(invalid),
                Err(ConfigError::InvalidEnvironment(
                    "PORTAL_AUTH_FOUNDATION_BASE_URL"
                ))
            );
        }
    }

    #[test]
    fn service_secret_empty_is_rejected_without_exposing_its_value() {
        assert_eq!(
            validate_service_secret(""),
            Err(ConfigError::InvalidEnvironment("PORTAL_SERVICE_SECRET"))
        );
        assert!(validate_service_secret("not-empty").is_ok());
    }

    #[test]
    fn capacity_parsing_has_defaults_and_rejects_zero() {
        assert_eq!(
            parse_capacity(None, "PORTAL_LOGIN_START_CAPACITY", 10_000),
            Ok(10_000)
        );
        assert_eq!(
            parse_capacity(None, "PORTAL_LOCAL_SESSION_CAPACITY", 50_000),
            Ok(50_000)
        );
        assert_eq!(
            parse_capacity(Some("7"), "PORTAL_LOGIN_START_CAPACITY", 10_000),
            Ok(7)
        );
        assert_eq!(
            parse_capacity(Some("0"), "PORTAL_LOGIN_START_CAPACITY", 10_000),
            Err(ConfigError::InvalidEnvironment(
                "PORTAL_LOGIN_START_CAPACITY"
            ))
        );
    }

    #[test]
    fn post_login_path_validation_is_exact() {
        for valid in ["/", "/foo", "/foo?bar=baz"] {
            assert!(validate_post_login_path(valid).is_ok());
        }
        let too_long = format!("/{}", "a".repeat(POST_LOGIN_PATH_MAX_BYTES));
        for invalid in [
            "",
            too_long.as_str(),
            "https://evil.example/",
            "http://evil.example/",
            "//evil.example/",
            "\\evil",
            "/foo\\bar",
            "javascript:alert(1)",
        ] {
            assert_eq!(
                validate_post_login_path(invalid),
                Err(LocalStateError::InvalidPostLoginPath)
            );
        }
    }

    #[test]
    fn login_start_create_claim_and_browser_binding_are_one_shot() {
        let mut state = local_state();
        let created = state.create_login_start("/foo".into(), 100).unwrap();
        assert_eq!(created.state.len(), 43);
        assert_eq!(created.browser_context_reference.len(), 43);
        assert_eq!(created.code_challenge.len(), 43);
        assert!(matches!(
            state.claim_login_start(&created.state, "wrong", 101),
            Err(LocalStateError::BrowserContextMismatch)
        ));
        assert!(state.login_starts.contains_key(&created.state));
        let claim = state
            .claim_login_start(&created.state, &created.browser_context_reference, 101)
            .unwrap();
        assert_eq!(claim.post_login_path, "/foo");
        assert_eq!(claim.created_at, 100);
        assert_eq!(claim.expires_at, 700);
        assert!(!state.login_starts.contains_key(&created.state));
        assert!(matches!(
            state.claim_login_start(&created.state, &created.browser_context_reference, 101),
            Err(LocalStateError::NotFound)
        ));
    }

    #[test]
    fn login_start_expiry_capacity_and_cleanup_preserve_valid_records() {
        let mut state = PortalLocalState::new(1, 1);
        let created = state.create_login_start("/".into(), 100).unwrap();
        assert!(matches!(
            state.claim_login_start(&created.state, &created.browser_context_reference, 700),
            Err(LocalStateError::Expired)
        ));
        assert!(!state.login_starts.contains_key(&created.state));
        let first = state.create_login_start("/".into(), 1000).unwrap();
        assert!(matches!(
            state.create_login_start("/other".into(), 1001),
            Err(LocalStateError::CapacityReached)
        ));
        assert!(state.login_starts.contains_key(&first.state));
        state.cleanup_expired(1599);
        assert!(state.login_starts.contains_key(&first.state));
        state.cleanup_expired(1600);
        assert!(!state.login_starts.contains_key(&first.state));
    }

    #[test]
    fn local_session_create_lookup_remove_expiry_and_capacity() {
        let mut state = PortalLocalState::new(1, 1);
        let (reference, csrf_plaintext) = state.create_local_session(42, 90, 100).unwrap();
        assert_eq!(reference.len(), 43);
        assert_eq!(csrf_plaintext.len(), 43);
        let record = state.get_local_session(&reference, 101).unwrap();
        assert_eq!(record.internal_user_id, 42);
        assert_eq!(record.authenticated_at, 90);
        assert_eq!(record.created_at, 100);
        assert_eq!(record.expires_at, 28_900);
        assert_ne!(record.csrf_lookup.as_slice(), csrf_plaintext.as_bytes());
        assert_eq!(record.csrf_lookup, sha256_digest(csrf_plaintext.as_bytes()));
        assert!(state.get_local_session(&reference, 102).is_some());
        assert_eq!(
            state.create_local_session(43, 100, 103),
            Err(LocalStateError::CapacityReached)
        );
        assert!(state.local_sessions.contains_key(&reference));
        assert!(state.remove_local_session(&reference).is_some());
        assert!(state.get_local_session(&reference, 103).is_none());

        let (expired_reference, _) = state.create_local_session(44, 110, 110).unwrap();
        assert!(state
            .get_local_session(&expired_reference, 28_909)
            .is_some());
        assert!(state
            .get_local_session(&expired_reference, 28_910)
            .is_none());
        assert!(!state.local_sessions.contains_key(&expired_reference));
    }

    #[test]
    fn cleanup_removes_both_expired_kinds_and_restart_invalidates_everything() {
        let mut first = local_state();
        let login = first.create_login_start("/".into(), 10).unwrap();
        let (session, _) = first.create_local_session(1, 10, 10).unwrap();
        first.cleanup_expired(609);
        assert!(first.login_starts.contains_key(&login.state));
        assert!(first.local_sessions.contains_key(&session));
        first.cleanup_expired(28_810);
        assert!(first.login_starts.is_empty());
        assert!(first.local_sessions.is_empty());

        let restarted = local_state();
        assert!(!restarted.login_starts.contains_key(&login.state));
        assert!(!restarted.local_sessions.contains_key(&session));
    }

    #[test]
    fn cookie_builders_fix_the_required_attributes_without_issuing_http_cookies() {
        let login = login_context_cookie("a".into());
        let session = portal_session_cookie("b".into());
        let csrf = portal_csrf_cookie("c".into());
        for cookie in [&login, &session, &csrf] {
            assert_eq!(cookie.path(), Some("/"));
            assert_eq!(cookie.secure(), Some(true));
            assert_eq!(cookie.same_site(), Some(SameSite::Lax));
            assert_eq!(cookie.domain(), None);
        }
        assert_eq!(login.http_only(), Some(true));
        assert_eq!(session.http_only(), Some(true));
        assert_eq!(csrf.http_only(), Some(false));
    }
}
