use actix_web::middleware::{DefaultHeaders, Logger};
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use log::{error, info};
use oauth2::reqwest::async_http_client;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, RedirectUrl,
    TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
struct AuthRequest {
    code: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserInfo {
    id: String,
    email: String,
    verified_email: bool,
    picture: String,
}

#[get("/healthz")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

#[get("/auth/google")]
async fn start_google_auth() -> impl Responder {
    let client_id = env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID not set");
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").expect("GOOGLE_REDIRECT_URI not set");

    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={}&redirect_uri={}&scope=email%20profile&access_type=offline&prompt=consent",
        client_id, redirect_uri
    );

    info!("Redirecting to Google OAuth URL: {}", auth_url);

    HttpResponse::Found()
        .append_header(("Location", auth_url))
        .finish()
}

#[get("/auth/google/callback")]
async fn google_auth_callback(query: web::Query<AuthRequest>) -> impl Responder {
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
                Ok(user_info) => match request_jwt_from_uniauth(&user_info).await {
                    Ok(token_json) => HttpResponse::Ok().json(token_json),
                    Err(e) => {
                        error!("Error from Uniauth: {:?}", e);
                        HttpResponse::InternalServerError().body("Failed to retrieve token")
                    }
                },
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
        // ステータスコードだけログ
        error!("Google userinfo returned error status: {}", resp.status());
        // ここで reqwest::Error を生成
        return Err(resp.error_for_status().unwrap_err());
    }

    let user_info = resp.json::<UserInfo>().await?;
    Ok(user_info)
}

async fn request_jwt_from_uniauth(
    user_info: &UserInfo,
) -> Result<serde_json::Value, reqwest::Error> {
    let uniauth_url =
        env::var("UNIAUTH_URL").unwrap_or_else(|_| "http://uniauth:8081".to_string());
    let url = format!("{}/upsert_and_token", uniauth_url);

    let client = reqwest::Client::new();
    let resp = client.post(&url).json(user_info).send().await?;

    if !resp.status().is_success() {
        error!("Uniauth returned error status: {}", resp.status());
        return Err(resp.error_for_status().unwrap_err());
    }

    let json_value = resp.json::<serde_json::Value>().await?;
    Ok(json_value)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let server = HttpServer::new(move || {
        App::new()
            .wrap(DefaultHeaders::new().add(("X-Frame-Options", "DENY")))
            .wrap(Logger::default())
            .service(start_google_auth)
            .service(google_auth_callback)
            .service(health_check)
    })
    .bind("0.0.0.0:8080")?
    .run();

    let server_handle = server.handle();
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    tokio::select! {
        _ = &mut ctrl_c => {
            log::info!("Received Ctrl+C, shutting down");
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
