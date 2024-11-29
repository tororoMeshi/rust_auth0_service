use actix_web::middleware::{DefaultHeaders, Logger};
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use log::info;
use oauth2::reqwest::async_http_client;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, RedirectUrl,
    TokenResponse, TokenUrl,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
struct AuthRequest {
    code: String,
}

// 認証リクエストの受信
#[get("/auth/google")]
async fn start_google_auth() -> impl Responder {
    // 環境変数からクライアントIDとリダイレクトURIを取得
    let client_id = env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID not set");
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").expect("GOOGLE_REDIRECT_URI not set");

    // GoogleのOAuth 2.0 認証URLを生成
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={}&redirect_uri={}&scope=email%20profile&access_type=offline&prompt=consent",
        client_id,
        redirect_uri
    );

    info!("Redirecting to Google OAuth URL: {}", auth_url);

    // Googleの認証ページにリダイレクト
    HttpResponse::Found()
        .append_header(("Location", auth_url))
        .finish()
}

// 認証コードの受信とアクセストークンの取得
#[get("/auth/google/callback")]
async fn google_auth_callback(query: web::Query<AuthRequest>) -> impl Responder {
    // 環境変数から設定を取得
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

    // 認証コードを使ってアクセストークンを取得
    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;

    match token_result {
        Ok(token) => {
            let access_token = token.access_token().secret().clone();

            // アクセストークンを使ってGoogleのユーザー情報を取得
            match get_user_info(&access_token).await {
                Ok(user_info) => HttpResponse::Ok().json(user_info),
                Err(err) => {
                    info!("Failed to get user info: {:?}", err);
                    HttpResponse::InternalServerError().body("Failed to get user info")
                }
            }
        }
        Err(err) => {
            info!("Error exchanging code: {:?}", err);
            HttpResponse::BadRequest().body("Error exchanging code")
        }
    }
}

// アクセストークンを使ってユーザー情報を取得
async fn get_user_info(access_token: &str) -> Result<UserInfo, reqwest::Error> {
    let user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";
    let client = Client::new();

    let user_info = client
        .get(user_info_url)
        .bearer_auth(access_token)
        .send()
        .await?
        .json::<UserInfo>()
        .await?;

    Ok(user_info)
}

#[derive(Debug, Serialize, Deserialize)]
struct UserInfo {
    id: String,
    email: String,
    verified_email: bool,
    picture: String,
}

// ヘルスチェックエンドポイント
#[get("/healthz")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // ロガーの初期化
    env_logger::init();

    // デバッグ用: 環境変数を表示
    for (key, value) in env::vars() {
        println!("{}: {}", key, value);
    }

    let server = HttpServer::new(|| {
        App::new()
            // セキュリティヘッダーの設定
            .wrap(DefaultHeaders::new().add(("X-Frame-Options", "DENY")))
            // ログミドルウェアの設定
            .wrap(Logger::default())
            .service(start_google_auth)
            .service(google_auth_callback)
            .service(health_check)
    })
    .bind("0.0.0.0:8080")?
    .run();

    // サーバーハンドルの取得
    let server_handle = server.handle();

    // グレースフルシャットダウンのためのシグナルハンドリング
    let ctrl_c = tokio::signal::ctrl_c();

    tokio::pin!(ctrl_c);

    tokio::select! {
        _ = &mut ctrl_c => {
            info!("Received Ctrl+C, shutting down");
            // サーバーを停止
            server_handle.stop(true).await;
        }
        res = server => {
            if let Err(e) = res {
                eprintln!("Server error: {}", e);
            }
        }
    }

    Ok(())
}
