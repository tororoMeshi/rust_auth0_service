// 必要なクレートのインポート
#[allow(unused_imports)]
use actix_cors::Cors;
#[allow(unused_imports)]
use actix_web::http::header;

use actix_session::storage::RedisSessionStore;
use actix_session::{Session, SessionMiddleware};
use actix_web::cookie::{Cookie, Key, SameSite};
use actix_web::{get, web, App, HttpResponse, HttpServer};
use dotenv::dotenv;
use log::{error, info};
use oauth2::reqwest::async_http_client;
use oauth2::TokenResponse; // access_token() などのメソッドを利用するため
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, RedirectUrl, TokenUrl,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::env;

//
// === OAuth フローとセッション管理のハンドラ ===
//

#[derive(Debug, Deserialize)]
struct StartAuthQuery {
    redirect: Option<String>,
}

#[get("/auth/google")]
async fn start_google_auth(session: Session, query: web::Query<StartAuthQuery>) -> HttpResponse {
    // 1. CSRF 対策: ランダムな state を生成し、セッションに保存
    let state: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    if let Err(e) = session.insert("oauth_state", state.clone()) {
        error!("Failed to insert oauth_state: {:?}", e);
        return HttpResponse::InternalServerError().finish();
    }

    // 2. ログイン前のリダイレクト先をセッションに保存
    if let Some(ref redirect) = query.redirect {
        if let Err(e) = session.insert("redirect", redirect) {
            error!("Failed to insert redirect: {:?}", e);
            return HttpResponse::InternalServerError().finish();
        }
    }

    // 3. Google OAuth 認可 URL を生成（state パラメータ付き）
    let client_id = env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID not set");
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").expect("GOOGLE_REDIRECT_URI not set");
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={}&redirect_uri={}&scope=email%20profile&access_type=offline&prompt=consent&state={}",
        client_id, redirect_uri, state
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
async fn google_auth_callback(session: Session, query: web::Query<CallbackQuery>) -> HttpResponse {
    // 4. セッションに保存された state と受信した state を比較（CSRF 対策）
    let stored_state: Option<String> = session.get("oauth_state").unwrap_or(None);
    if stored_state.is_none() || stored_state.unwrap() != query.state {
        error!("State parameter mismatch. Potential CSRF attack.");
        return HttpResponse::BadRequest().body("Invalid state parameter");
    }

    // 5. Google からアクセストークンを取得
    let client_id = env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID not set");
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET not set");
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").expect("GOOGLE_REDIRECT_URI not set");

    let client = BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap());

    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;

    match token_result {
        Ok(token) => {
            let access_token = token.access_token().secret().clone();
            match get_google_user_info(&access_token).await {
                Ok(user_info) => {
                    match request_session_from_uniauth(&user_info).await {
                        Ok(session_data) => {
                            // 7. セッションに保存されたリダイレクト先を取得（デフォルトは "/"）
                            let raw_redirect: String = session
                                .get("redirect")
                                .unwrap_or(Some("/".to_string()))
                                .unwrap_or("/".to_string());
                            // もしリダイレクト先が相対パスなら、ポータルサイトのドメインを付加
                            let redirect_url = if raw_redirect.starts_with('/') {
                                format!("https://app.tororomeshi.net{}", raw_redirect)
                            } else if raw_redirect.starts_with("https://app.tororomeshi.net") {
                                raw_redirect
                            } else {
                                "https://app.tororomeshi.net/".to_string()
                            };

                            let cookie_domain = env::var("COOKIE_DOMAIN")
                                .unwrap_or_else(|_| ".tororomeshi.net".to_string());

                            let session_cookie =
                                Cookie::build("session_id", session_data.session_id.clone())
                                    .path("/")
                                    .domain(cookie_domain.clone())
                                    .http_only(true)
                                    .secure(true)
                                    .same_site(SameSite::Strict)
                                    .finish();
                            let jwt_cookie = Cookie::build("jwt", session_data.token.clone())
                                .path("/")
                                .domain(cookie_domain)
                                .http_only(true)
                                .secure(true)
                                .same_site(SameSite::Strict)
                                .finish();

                            info!("Redirecting user to: {}", redirect_url);

                            HttpResponse::Found()
                                .cookie(session_cookie)
                                .cookie(jwt_cookie)
                                .append_header(("Location", redirect_url))
                                .finish()
                        }
                        Err(e) => {
                            error!("Error from uniauth: {:?}", e);
                            HttpResponse::InternalServerError().body("Failed to generate session")
                        }
                    }
                }
                Err(err) => {
                    error!("Failed to get user info: {:?}", err);
                    HttpResponse::InternalServerError().body("Failed to get user info")
                }
            }
        }
        Err(err) => {
            error!("Error exchanging code: {:?}", err);
            HttpResponse::BadRequest().body("Error exchanging code")
        }
    }
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
    user_info: &UserInfo,
) -> Result<UniauthResponse, reqwest::Error> {
    let uniauth_url = env::var("UNIAUTH_URL").unwrap_or_else(|_| "http://uniauth:8081".to_string());
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

//
// === メイン処理 ===
//

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    // CORS の設定を追加
    use actix_cors::Cors;
    use actix_web::http::header;

    // RedisSessionStore を REDIS_URL から初期化
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    let redis_store = RedisSessionStore::new(redis_url)
        .await
        .expect("Failed to create Redis session store");

    // セッション Cookie 署名用の秘密鍵（Key 型に変換）
    let secret_key = env::var("SESSION_SECRET_KEY")
        .unwrap_or_else(|_| "0123456789abcdef0123456789abcdef".to_string());

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allowed_origin("https://app.tororomeshi.net")
                    .allowed_origin("https://auth.tororomeshi.net")
                    .allowed_methods(vec!["GET", "POST", "OPTIONS"])
                    .allowed_headers(vec![
                        header::AUTHORIZATION,
                        header::ACCEPT,
                        header::CONTENT_TYPE,
                    ])
                    .supports_credentials(),
            )
            .app_data(web::Data::new(redis_store.clone()))
            .wrap(SessionMiddleware::new(
                redis_store.clone(),
                Key::from(secret_key.as_bytes()),
            ))
            .service(start_google_auth)
            .service(google_auth_callback)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
