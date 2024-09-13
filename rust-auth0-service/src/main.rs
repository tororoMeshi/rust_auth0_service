use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
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
    // GoogleのOAuth 2.0 認証URLを生成
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={}&redirect_uri={}&scope=email&access_type=offline&approval_prompt=force",
        "459869080847-jl2pvmpebve2efkn75fksh5kubdqdgqc.apps.googleusercontent.com",
        "http://localhost:8080/auth/google/callback"
    );

    // Googleの認証ページにリダイレクト
    HttpResponse::Found()
        .append_header(("Location", auth_url))
        .finish()
}

// 認証コードの受信とアクセストークンの取得
#[get("/auth/google/callback")]
async fn google_auth_callback(query: web::Query<AuthRequest>) -> impl Responder {
    let client = BasicClient::new(
        ClientId::new(env::var("GOOGLE_CLIENT_ID").unwrap()),
        Some(ClientSecret::new(env::var("GOOGLE_CLIENT_SECRET").unwrap())),
        AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
    )
    .set_redirect_uri(
        RedirectUrl::new("http://localhost:8080/auth/google/callback".to_string()).unwrap(),
    );

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
                Err(err) => HttpResponse::InternalServerError()
                    .body(format!("Failed to get user info: {:?}", err)),
            }
        }
        Err(err) => HttpResponse::BadRequest().body(format!("Error: {:?}", err)),
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    HttpServer::new(|| {
        App::new()
            .service(start_google_auth)
            .service(google_auth_callback)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
