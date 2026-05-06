// src/main.rs for rust-auth0-service

// 必要なクレートのインポート
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
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, RedirectUrl, TokenUrl,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::{env, io};

#[derive(Clone)]
struct AppConfig {
    google_client_id: String,
    google_client_secret: String,
    google_redirect_uri: String,
    uniauth_url: String,
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
    if let Err(e) = session.insert("oauth_state", state.clone()) {
        error!("Failed to insert oauth_state: {:?}", e);
        return HttpResponse::InternalServerError()
            .body("Internal server error: cannot set oauth_state");
    }

    // ログイン前のリダイレクト先をセッションに保存
    if let Some(ref redirect) = query.redirect {
        if let Err(e) = session.insert("redirect", redirect) {
            error!("Failed to insert redirect: {:?}", e);
            return HttpResponse::InternalServerError()
                .body("Internal server error: cannot set redirect");
        }
    }

    // Google OAuth 認可 URL を生成
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={}&redirect_uri={}&scope=email%20profile&access_type=offline&prompt=consent&state={}",
        config.google_client_id, config.google_redirect_uri, state
    );
    info!("Redirecting to Google OAuth URL: {}", auth_url);

    HttpResponse::Found()
        .append_header(("Location", auth_url))
        .finish()
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserInfo {
    id: String,
    email: String,
    verified_email: bool,
    picture: String,
}

#[get("/auth/google/callback")]
async fn google_auth_callback(
    session: Session,
    query: web::Query<CallbackQuery>,
    config: web::Data<AppConfig>,
) -> HttpResponse {
    // セッションに保存された state と受信した state の比較（CSRF 対策）
    let stored_state: Option<String> = match session.get("oauth_state") {
        Ok(value) => value,
        Err(e) => {
            error!("Failed to get oauth_state: {:?}", e);
            return HttpResponse::InternalServerError()
                .body("Internal server error: cannot get oauth_state");
        }
    };
    if stored_state.as_deref() != Some(query.state.as_str()) {
        error!("State parameter mismatch. Potential CSRF attack.");
        return HttpResponse::BadRequest()
            .body("Invalid state parameter. Please try logging in again.");
    }

    // Google からアクセストークンを取得
    let auth_url = match AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string()) {
        Ok(url) => url,
        Err(e) => {
            error!("Invalid Google auth URL: {:?}", e);
            return HttpResponse::InternalServerError()
                .body("Internal server error: invalid auth URL");
        }
    };
    let token_url = match TokenUrl::new("https://oauth2.googleapis.com/token".to_string()) {
        Ok(url) => url,
        Err(e) => {
            error!("Invalid Google token URL: {:?}", e);
            return HttpResponse::InternalServerError()
                .body("Internal server error: invalid token URL");
        }
    };
    let redirect_uri = match RedirectUrl::new(config.google_redirect_uri.clone()) {
        Ok(url) => url,
        Err(e) => {
            error!("Invalid Google redirect URI: {:?}", e);
            return HttpResponse::InternalServerError()
                .body("Internal server error: invalid redirect URI");
        }
    };

    let client = BasicClient::new(
        ClientId::new(config.google_client_id.clone()),
        Some(ClientSecret::new(config.google_client_secret.clone())),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_uri);

    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;

    match token_result {
        Ok(token) => {
            let access_token = token.access_token().secret().clone();
            match get_google_user_info(&access_token).await {
                Ok(user_info) => {
                    match request_session_from_uniauth(&config.uniauth_url, &user_info).await {
                        Ok(session_data) => {
                            // セッションに保存されたリダイレクト先を取得（デフォルトは "/"）
                            let raw_redirect: String = session
                                .get("redirect")
                                .unwrap_or_else(|_| Some(post_login_redirect()))
                                .unwrap_or_else(post_login_redirect);
                            let redirect_url = resolve_redirect_url(&raw_redirect);

                            let session_cookie =
                                build_auth_cookie("session_id", session_data.session_id.clone());
                            let jwt_cookie = build_auth_cookie("jwt", session_data.token.clone());

                            info!("Redirecting user to: {}", redirect_url);

                            HttpResponse::Found()
                                .cookie(session_cookie)
                                .cookie(jwt_cookie)
                                .append_header(("Location", redirect_url))
                                .finish()
                        }
                        Err(e) => {
                            error!("Error from uniauth: {:?}", e);
                            HttpResponse::InternalServerError()
                                .body("Failed to generate session. Please try again later.")
                        }
                    }
                }
                Err(err) => {
                    error!("Failed to get user info: {:?}", err);
                    HttpResponse::InternalServerError()
                        .body("Failed to get user info. Please try again later.")
                }
            }
        }
        Err(err) => {
            error!("Error exchanging code: {:?}", err);
            HttpResponse::BadRequest()
                .body("Error exchanging code. Please retry the login process.")
        }
    }
}

#[post("/auth/logout")]
async fn logout(req: HttpRequest, config: web::Data<AppConfig>) -> HttpResponse {
    if let Some(cookie) = req.cookie("session_id") {
        if let Err(e) = request_logout_from_uniauth(&config.uniauth_url, cookie.value()).await {
            error!("Failed to delete session from uniauth: {:?}", e);
        }
    }

    HttpResponse::Ok()
        .cookie(build_expired_auth_cookie("session_id"))
        .cookie(build_expired_auth_cookie("jwt"))
        .body("Logged out")
}

async fn get_google_user_info(access_token: &str) -> Result<UserInfo, reqwest::Error> {
    let user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";
    let client = reqwest::Client::new();
    let resp = client
        .get(user_info_url)
        .bearer_auth(access_token)
        .send()
        .await?;
    if !resp.status().is_success() {
        error!("Google userinfo returned error status: {}", resp.status());
        return Err(resp.error_for_status().unwrap_err());
    }
    let user_info = resp.json::<UserInfo>().await?;
    Ok(user_info)
}

#[derive(Debug, Deserialize, Serialize)]
struct UniauthResponse {
    session_id: String,
    token: String,
    user: serde_json::Value,
}

async fn request_session_from_uniauth(
    uniauth_url: &str,
    user_info: &UserInfo,
) -> Result<UniauthResponse, reqwest::Error> {
    let url = format!("{}/upsert_and_token", uniauth_url);
    let client = reqwest::Client::new();
    let resp = client.post(&url).json(user_info).send().await?;
    if !resp.status().is_success() {
        error!("Uniauth returned error status: {}", resp.status());
        return Err(resp.error_for_status().unwrap_err());
    }
    let session_data = resp.json::<UniauthResponse>().await?;
    Ok(session_data)
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

    let config = AppConfig {
        google_client_id: required_env("GOOGLE_CLIENT_ID")?,
        google_client_secret: required_env("GOOGLE_CLIENT_SECRET")?,
        google_redirect_uri: required_env("GOOGLE_REDIRECT_URI")?,
        uniauth_url: env::var("UNIAUTH_URL").unwrap_or_else(|_| "http://uniauth:8081".to_string()),
    };

    let allowed_redirect_origins = allowed_redirect_origins();
    let post_login_redirect = post_login_redirect();
    validate_post_login_redirect(&post_login_redirect, &allowed_redirect_origins)?;

    // RedisSessionStore の初期化
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    let redis_store = RedisSessionStore::new(redis_url).await.map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("failed to create Redis session store: {e}"),
        )
    })?;

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
            .app_data(web::Data::new(redis_store.clone()))
            .wrap(SessionMiddleware::new(
                redis_store.clone(),
                Key::from(secret_key.as_bytes()),
            ))
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
