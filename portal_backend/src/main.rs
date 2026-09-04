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
use std::convert::Infallible;
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
    http_client: reqwest::Client,
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

fn delete_login_context_cookie() -> Cookie<'static> {
    Cookie::build((PORTAL_LOGIN_CONTEXT_COOKIE_NAME, ""))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(0))
        .build()
}

fn is_fixed_reference(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn auth_foundation_endpoint(base_url: &Url, path: &str) -> Url {
    let mut url = base_url.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn build_http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0)
        .build()
}

fn empty_response(status: warp::http::StatusCode) -> warp::reply::Response {
    warp::http::Response::builder()
        .status(status)
        .body(warp::hyper::Body::empty())
        .expect("fixed HTTP response is valid")
}

fn append_cookie(response: &mut warp::reply::Response, cookie: Cookie<'static>) {
    let value = warp::http::HeaderValue::from_str(&cookie.to_string())
        .expect("fixed cookie attributes produce a valid header");
    response
        .headers_mut()
        .append(warp::http::header::SET_COOKIE, value);
}

fn redirect_response(location: &str) -> warp::reply::Response {
    let mut response = empty_response(warp::http::StatusCode::FOUND);
    response.headers_mut().insert(
        warp::http::header::LOCATION,
        warp::http::HeaderValue::from_str(location).expect("URL is a valid header value"),
    );
    response
}

#[derive(Serialize)]
struct HandoffExchangeRequest<'a> {
    code: &'a str,
    code_verifier: &'a str,
}

#[derive(Deserialize)]
struct HandoffExchangeResponse {
    internal_user_id: i32,
    authenticated_at: u64,
}

struct CallbackQuery {
    code: String,
    state: String,
}

fn parse_callback_query(raw_query: &str) -> Result<CallbackQuery, ()> {
    let mut code = None;
    let mut state = None;
    for (name, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        let target = match name.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            _ => return Err(()),
        };
        if target.is_some() || !is_fixed_reference(&value) {
            return Err(());
        }
        *target = Some(value.into_owned());
    }
    match (code, state) {
        (Some(code), Some(state)) => Ok(CallbackQuery { code, state }),
        _ => Err(()),
    }
}

fn login_context_from_cookie_header(cookie_header: Option<String>) -> Result<String, ()> {
    let header = cookie_header.ok_or(())?;
    let mut value = None;
    for cookie in Cookie::split_parse(header) {
        let cookie = cookie.map_err(|_| ())?;
        if cookie.name() == PORTAL_LOGIN_CONTEXT_COOKIE_NAME {
            if value.is_some() || !is_fixed_reference(cookie.value()) {
                return Err(());
            }
            value = Some(cookie.value().to_string());
        }
    }
    value.ok_or(())
}

async fn login(state: Arc<AppState>) -> Result<warp::reply::Response, warp::Rejection> {
    // All URL construction precedes consuming capacity in the login-start store.
    let mut login_url =
        auth_foundation_endpoint(&state.config.auth_foundation_base_url, "/auth/login");
    let now = unix_epoch_seconds();
    let created = {
        let mut local_state = state.local_state.lock().await;
        local_state.create_login_start("/".to_string(), now)
    };
    let created = match created {
        Ok(created) => created,
        Err(LocalStateError::CapacityReached) => {
            return Ok(empty_response(warp::http::StatusCode::SERVICE_UNAVAILABLE));
        }
        Err(_) => {
            return Ok(empty_response(
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    };
    login_url.query_pairs_mut().extend_pairs([
        ("service_id", state.config.service_id.as_str()),
        ("state", created.state.as_str()),
        ("code_challenge", created.code_challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    let mut response = redirect_response(login_url.as_str());
    append_cookie(
        &mut response,
        login_context_cookie(created.browser_context_reference),
    );
    Ok(response)
}

async fn callback(
    raw_query: String,
    cookie_header: Option<String>,
    state: Arc<AppState>,
) -> Result<warp::reply::Response, warp::Rejection> {
    let query = match parse_callback_query(&raw_query) {
        Ok(query) => query,
        Err(()) => return Ok(empty_response(warp::http::StatusCode::BAD_REQUEST)),
    };
    let browser_context_reference = match login_context_from_cookie_header(cookie_header) {
        Ok(value) => value,
        Err(()) => return Ok(empty_response(warp::http::StatusCode::BAD_REQUEST)),
    };
    let now = unix_epoch_seconds();
    let login_start = {
        let mut local_state = state.local_state.lock().await;
        local_state.claim_login_start(&query.state, &browser_context_reference, now)
    };
    let login_start = match login_start {
        Ok(login_start) => login_start,
        Err(
            LocalStateError::NotFound
            | LocalStateError::Expired
            | LocalStateError::BrowserContextMismatch,
        ) => return Ok(empty_response(warp::http::StatusCode::BAD_REQUEST)),
        Err(_) => {
            return Ok(empty_response(
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    };

    // A claimed handoff is deliberately never retried, restored, or redirected.
    let exchange_url = auth_foundation_endpoint(
        &state.config.auth_foundation_base_url,
        "/auth/handoffs/exchange",
    );
    let exchange = state
        .http_client
        .post(exchange_url)
        .basic_auth(&state.config.service_id, Some(&state.config.service_secret))
        .json(&HandoffExchangeRequest {
            code: &query.code,
            code_verifier: &login_start.code_verifier,
        })
        .send()
        .await;
    let handoff = match exchange {
        Ok(response) if response.status() == reqwest::StatusCode::OK => {
            match response.json::<HandoffExchangeResponse>().await {
                Ok(handoff) => handoff,
                Err(_) => {
                    let mut response = empty_response(warp::http::StatusCode::BAD_GATEWAY);
                    append_cookie(&mut response, delete_login_context_cookie());
                    return Ok(response);
                }
            }
        }
        _ => {
            let mut response = empty_response(warp::http::StatusCode::BAD_GATEWAY);
            append_cookie(&mut response, delete_login_context_cookie());
            return Ok(response);
        }
    };
    let session = {
        let mut local_state = state.local_state.lock().await;
        local_state.create_local_session(
            handoff.internal_user_id,
            handoff.authenticated_at,
            unix_epoch_seconds(),
        )
    };
    let (session_reference, csrf_plaintext) = match session {
        Ok(session) => session,
        Err(LocalStateError::CapacityReached) => {
            let mut response = empty_response(warp::http::StatusCode::SERVICE_UNAVAILABLE);
            append_cookie(&mut response, delete_login_context_cookie());
            return Ok(response);
        }
        Err(_) => {
            let mut response = empty_response(warp::http::StatusCode::INTERNAL_SERVER_ERROR);
            append_cookie(&mut response, delete_login_context_cookie());
            return Ok(response);
        }
    };
    let mut response = redirect_response(&login_start.post_login_path);
    append_cookie(&mut response, portal_session_cookie(session_reference));
    append_cookie(&mut response, portal_csrf_cookie(csrf_plaintext));
    append_cookie(&mut response, delete_login_context_cookie());
    Ok(response)
}

fn with_state(
    state: Arc<AppState>,
) -> impl Filter<Extract = (Arc<AppState>,), Error = Infallible> + Clone {
    warp::any().map(move || Arc::clone(&state))
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
    let http_client = match build_http_client() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("Portal HTTP client configuration error: {error}");
            return;
        }
    };
    let state = Arc::new(AppState {
        local_state: Mutex::new(PortalLocalState::new(
            config.login_start_capacity,
            config.local_session_capacity,
        )),
        config,
        http_client,
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

    let login_route = warp::path!("login")
        .and(warp::path::end())
        .and(warp::get())
        .and(with_state(Arc::clone(&state)))
        .and_then(login);

    let callback_route = warp::path!("auth" / "callback")
        .and(warp::path::end())
        .and(warp::get())
        .and(warp::query::raw())
        .and(warp::header::optional::<String>("cookie"))
        .and(with_state(Arc::clone(&state)))
        .and_then(callback);

    let routes = me_route
        .or(health_route)
        .or(login_route)
        .or(callback_route)
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

    fn test_state(base_url: Url, login_capacity: usize, session_capacity: usize) -> Arc<AppState> {
        Arc::new(AppState {
            config: AppConfig {
                service_id: "portal-test".to_string(),
                service_secret: "test-secret".to_string(),
                auth_foundation_base_url: base_url,
                login_start_capacity: login_capacity,
                local_session_capacity: session_capacity,
            },
            local_state: Mutex::new(PortalLocalState::new(login_capacity, session_capacity)),
            http_client: build_http_client().expect("test HTTP client"),
        })
    }

    fn header_cookie(response: &warp::reply::Response, name: &str) -> Option<Cookie<'static>> {
        response
            .headers()
            .get_all(warp::http::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| Cookie::parse(value.to_string()).ok())
            .find(|cookie| cookie.name() == name)
    }

    async fn started_login(state: Arc<AppState>) -> (String, String) {
        let response = login(state).await.expect("login handler result");
        assert_eq!(response.status(), warp::http::StatusCode::FOUND);
        let location = response
            .headers()
            .get(warp::http::header::LOCATION)
            .expect("login location")
            .to_str()
            .expect("valid location");
        let url = Url::parse(location).expect("login URL");
        let state = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .expect("state query");
        let cookie = header_cookie(&response, PORTAL_LOGIN_CONTEXT_COOKIE_NAME)
            .expect("login context cookie");
        (state, cookie.value().to_string())
    }

    async fn spawn_exchange_server(
        response: String,
    ) -> (Url, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake exchange server");
        let address = listener.local_addr().expect("local address");
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept exchange request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let bytes = socket
                    .read(&mut buffer)
                    .await
                    .expect("read exchange request");
                if bytes == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..bytes]);
                let Some(headers_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                else {
                    continue;
                };
                let header_text = String::from_utf8_lossy(&request[..headers_end]);
                let content_length = header_text
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length: ")
                            .or_else(|| line.strip_prefix("Content-Length: "))
                    })
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= headers_end + 4 + content_length {
                    break;
                }
            }
            let _ = sender.send(request);
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write exchange response");
        });
        (
            Url::parse(&format!("http://{address}")).expect("server URL"),
            receiver,
        )
    }

    #[tokio::test]
    async fn login_redirect_has_only_the_authentication_contract_and_context_cookie() {
        let state = test_state(
            Url::parse("https://auth.example/ignored?x=y#fragment").unwrap(),
            2,
            2,
        );
        let response = login(state).await.unwrap();
        assert_eq!(response.status(), warp::http::StatusCode::FOUND);
        let location = response.headers()[warp::http::header::LOCATION]
            .to_str()
            .unwrap();
        let url = Url::parse(location).unwrap();
        assert_eq!(url.path(), "/auth/login");
        let pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(pairs.len(), 4);
        assert_eq!(pairs.get("service_id"), Some(&"portal-test".to_string()));
        assert_eq!(
            pairs.get("code_challenge_method"),
            Some(&"S256".to_string())
        );
        assert!(is_fixed_reference(pairs.get("state").unwrap()));
        assert!(is_fixed_reference(pairs.get("code_challenge").unwrap()));
        for forbidden in [
            "service_secret",
            "code_verifier",
            "browser_context_reference",
            "post_login_path",
        ] {
            assert!(!pairs.contains_key(forbidden));
        }
        let cookie = header_cookie(&response, PORTAL_LOGIN_CONTEXT_COOKIE_NAME).unwrap();
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        assert_eq!(cookie.domain(), None);
    }

    #[tokio::test]
    async fn callback_exchanges_once_creates_session_and_deletes_login_context() {
        let (base_url, request) = spawn_exchange_server(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 47\r\nconnection: close\r\n\r\n{\"internal_user_id\":123,\"authenticated_at\":456}".to_string(),
        )
        .await;
        let app_state = test_state(base_url, 2, 2);
        let (state, context) = started_login(Arc::clone(&app_state)).await;
        let response = callback(
            format!("code={}&state={state}", "A".repeat(43)),
            Some(format!("{PORTAL_LOGIN_CONTEXT_COOKIE_NAME}={context}")),
            Arc::clone(&app_state),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), warp::http::StatusCode::FOUND);
        assert_eq!(response.headers()[warp::http::header::LOCATION], "/");
        let request = request.await.expect("one exchange request");
        let request_text = String::from_utf8(request).expect("HTTP request text");
        assert!(request_text.starts_with("POST /auth/handoffs/exchange "));
        assert!(request_text.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("authorization")
                    && value.trim() == "Basic cG9ydGFsLXRlc3Q6dGVzdC1zZWNyZXQ="
            })
        }));
        let body = request_text.split("\r\n\r\n").nth(1).expect("JSON body");
        let body: serde_json::Value = serde_json::from_str(body).expect("exchange JSON");
        assert!(body.get("code").is_some());
        assert!(body
            .get("code_verifier")
            .and_then(|value| value.as_str())
            .is_some_and(is_fixed_reference));
        let session =
            header_cookie(&response, PORTAL_SESSION_COOKIE_NAME).expect("portal session cookie");
        let csrf = header_cookie(&response, PORTAL_CSRF_COOKIE_NAME).expect("CSRF cookie");
        let deleted = header_cookie(&response, PORTAL_LOGIN_CONTEXT_COOKIE_NAME)
            .expect("deleted context cookie");
        assert_eq!(session.http_only(), Some(true));
        assert_eq!(csrf.http_only(), None);
        assert_eq!(
            deleted.max_age().map(|value| value.whole_seconds()),
            Some(0)
        );
        let local_state = app_state.local_state.lock().await;
        assert_eq!(local_state.local_sessions.len(), 1);
        assert_eq!(
            local_state
                .local_sessions
                .values()
                .next()
                .unwrap()
                .authenticated_at,
            456
        );
    }

    #[tokio::test]
    async fn callback_invalid_and_wrong_browser_do_not_exchange_or_delete_context() {
        let app_state = test_state(Url::parse("http://127.0.0.1:9").unwrap(), 3, 3);
        for query in [
            "",
            "code=",
            "state=",
            "code=a&code=b&state=c",
            "code=a&state=b&extra=c",
        ] {
            let response = callback(query.to_string(), None, Arc::clone(&app_state))
                .await
                .unwrap();
            assert_eq!(response.status(), warp::http::StatusCode::BAD_REQUEST);
            assert!(header_cookie(&response, PORTAL_LOGIN_CONTEXT_COOKIE_NAME).is_none());
        }
        let (state, context) = started_login(Arc::clone(&app_state)).await;
        let missing_cookie = callback(
            format!("code={}&state={state}", "A".repeat(43)),
            None,
            Arc::clone(&app_state),
        )
        .await
        .unwrap();
        assert_eq!(missing_cookie.status(), warp::http::StatusCode::BAD_REQUEST);
        assert!(app_state
            .local_state
            .lock()
            .await
            .login_starts
            .contains_key(&state));
        let wrong = callback(
            format!("code={}&state={state}", "A".repeat(43)),
            Some(format!(
                "{PORTAL_LOGIN_CONTEXT_COOKIE_NAME}={}",
                "B".repeat(43)
            )),
            Arc::clone(&app_state),
        )
        .await
        .unwrap();
        assert_eq!(wrong.status(), warp::http::StatusCode::BAD_REQUEST);
        assert!(header_cookie(&wrong, PORTAL_LOGIN_CONTEXT_COOKIE_NAME).is_none());
        assert!(app_state
            .local_state
            .lock()
            .await
            .login_starts
            .contains_key(&state));
        let retry = callback(
            format!("code={}&state={state}", "A".repeat(43)),
            Some(format!("{PORTAL_LOGIN_CONTEXT_COOKIE_NAME}={context}")),
            Arc::clone(&app_state),
        )
        .await
        .unwrap();
        assert_eq!(retry.status(), warp::http::StatusCode::BAD_GATEWAY);
        assert!(header_cookie(&retry, PORTAL_LOGIN_CONTEXT_COOKIE_NAME).is_some());

        let reused = callback(
            format!("code={}&state={state}", "A".repeat(43)),
            Some(format!("{PORTAL_LOGIN_CONTEXT_COOKIE_NAME}={context}")),
            Arc::clone(&app_state),
        )
        .await
        .unwrap();
        assert_eq!(reused.status(), warp::http::StatusCode::BAD_REQUEST);
        assert!(header_cookie(&reused, PORTAL_LOGIN_CONTEXT_COOKIE_NAME).is_none());

        let (expired_state, expired_context) = started_login(Arc::clone(&app_state)).await;
        app_state
            .local_state
            .lock()
            .await
            .login_starts
            .get_mut(&expired_state)
            .expect("created login start")
            .expires_at = unix_epoch_seconds();
        let expired = callback(
            format!("code={}&state={expired_state}", "A".repeat(43)),
            Some(format!(
                "{PORTAL_LOGIN_CONTEXT_COOKIE_NAME}={expired_context}"
            )),
            Arc::clone(&app_state),
        )
        .await
        .unwrap();
        assert_eq!(expired.status(), warp::http::StatusCode::BAD_REQUEST);
        assert!(header_cookie(&expired, PORTAL_LOGIN_CONTEXT_COOKIE_NAME).is_none());
    }

    #[tokio::test]
    async fn callback_exchange_failures_consume_login_and_never_create_session() {
        for response in [
            "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            "HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            "HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 1\r\nconnection: close\r\n\r\n?",
        ] {
            let (base_url, request) = spawn_exchange_server(response.to_string()).await;
            let app_state = test_state(base_url, 2, 2);
            let (state, context) = started_login(Arc::clone(&app_state)).await;
            let result = callback(
                format!("code={}&state={state}", "A".repeat(43)),
                Some(format!("{PORTAL_LOGIN_CONTEXT_COOKIE_NAME}={context}")),
                Arc::clone(&app_state),
            ).await.unwrap();
            assert_eq!(result.status(), warp::http::StatusCode::BAD_GATEWAY);
            assert!(header_cookie(&result, PORTAL_LOGIN_CONTEXT_COOKIE_NAME).is_some());
            assert!(header_cookie(&result, PORTAL_SESSION_COOKIE_NAME).is_none());
            assert!(app_state.local_state.lock().await.login_starts.get(&state).is_none());
            assert!(app_state.local_state.lock().await.local_sessions.is_empty());
            let _ = request.await.expect("one exchange request");
        }
    }

    #[tokio::test]
    async fn callback_connection_failure_and_response_loss_are_single_use_failures() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unused_base =
            Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        drop(listener);
        let connection_failure = test_state(unused_base, 2, 2);
        let (state, context) = started_login(Arc::clone(&connection_failure)).await;
        let result = callback(
            format!("code={}&state={state}", "A".repeat(43)),
            Some(format!("{PORTAL_LOGIN_CONTEXT_COOKIE_NAME}={context}")),
            Arc::clone(&connection_failure),
        )
        .await
        .unwrap();
        assert_eq!(result.status(), warp::http::StatusCode::BAD_GATEWAY);
        assert!(connection_failure
            .local_state
            .lock()
            .await
            .login_starts
            .get(&state)
            .is_none());
        assert!(connection_failure
            .local_state
            .lock()
            .await
            .local_sessions
            .is_empty());

        let (base_url, request) = spawn_exchange_server(String::new()).await;
        let response_loss = test_state(base_url, 2, 2);
        let (state, context) = started_login(Arc::clone(&response_loss)).await;
        let result = callback(
            format!("code={}&state={state}", "A".repeat(43)),
            Some(format!("{PORTAL_LOGIN_CONTEXT_COOKIE_NAME}={context}")),
            Arc::clone(&response_loss),
        )
        .await
        .unwrap();
        assert_eq!(result.status(), warp::http::StatusCode::BAD_GATEWAY);
        let _ = request.await.expect("exactly one observed exchange");
        assert!(response_loss
            .local_state
            .lock()
            .await
            .login_starts
            .get(&state)
            .is_none());
        assert!(response_loss
            .local_state
            .lock()
            .await
            .local_sessions
            .is_empty());
    }

    #[tokio::test]
    async fn callback_session_capacity_consumes_handoff_and_deletes_context() {
        let (base_url, request) = spawn_exchange_server(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 47\r\nconnection: close\r\n\r\n{\"internal_user_id\":123,\"authenticated_at\":456}".to_string(),
        )
        .await;
        let app_state = test_state(base_url, 2, 1);
        app_state
            .local_state
            .lock()
            .await
            .create_local_session(99, 100, unix_epoch_seconds())
            .unwrap();
        let (state, context) = started_login(Arc::clone(&app_state)).await;
        let result = callback(
            format!("code={}&state={state}", "A".repeat(43)),
            Some(format!("{PORTAL_LOGIN_CONTEXT_COOKIE_NAME}={context}")),
            Arc::clone(&app_state),
        )
        .await
        .unwrap();
        assert_eq!(result.status(), warp::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(header_cookie(&result, PORTAL_LOGIN_CONTEXT_COOKIE_NAME).is_some());
        assert!(header_cookie(&result, PORTAL_SESSION_COOKIE_NAME).is_none());
        assert!(header_cookie(&result, PORTAL_CSRF_COOKIE_NAME).is_none());
        let _ = request.await.expect("exactly one exchange request");
        let local_state = app_state.local_state.lock().await;
        assert!(!local_state.login_starts.contains_key(&state));
        assert_eq!(local_state.local_sessions.len(), 1);
    }

    #[tokio::test]
    async fn login_capacity_does_not_issue_a_cookie_or_redirect() {
        let app_state = test_state(Url::parse("https://auth.example").unwrap(), 1, 1);
        let _ = started_login(Arc::clone(&app_state)).await;
        let response = login(Arc::clone(&app_state)).await.unwrap();
        assert_eq!(
            response.status(),
            warp::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(response
            .headers()
            .get(warp::http::header::LOCATION)
            .is_none());
        assert!(header_cookie(&response, PORTAL_LOGIN_CONTEXT_COOKIE_NAME).is_none());
        assert_eq!(app_state.local_state.lock().await.login_starts.len(), 1);
    }

    #[tokio::test]
    async fn callback_route_maps_a_missing_query_to_bad_request() {
        let app_state = test_state(Url::parse("https://auth.example").unwrap(), 1, 1);
        let route = warp::path!("auth" / "callback")
            .and(warp::path::end())
            .and(warp::get())
            .and(warp::query::raw())
            .and(warp::header::optional::<String>("cookie"))
            .and(with_state(app_state))
            .and_then(callback);
        let response = warp::test::request()
            .method("GET")
            .path("/auth/callback")
            .reply(&route)
            .await;
        assert_eq!(response.status(), warp::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn callback_does_not_follow_exchange_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("first exchange request");
            let mut buffer = [0_u8; 2048];
            let _ = first.read(&mut buffer).await.expect("read first request");
            first
                .write_all(b"HTTP/1.1 307 Temporary Redirect\r\nlocation: /should-not-receive\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await
                .expect("write redirect");
            drop(first);
            let followed = tokio::time::timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_ok();
            let _ = sender.send(followed);
        });
        let app_state = test_state(base_url, 2, 2);
        let (state, context) = started_login(Arc::clone(&app_state)).await;
        let response = callback(
            format!("code={}&state={state}", "A".repeat(43)),
            Some(format!("{PORTAL_LOGIN_CONTEXT_COOKIE_NAME}={context}")),
            app_state,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), warp::http::StatusCode::BAD_GATEWAY);
        assert!(!receiver.await.expect("redirect observation"));
    }
}
