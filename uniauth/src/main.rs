// uniauth/src/main.rs

use actix_cors::Cors;
use actix_web::cookie::{time::Duration, Cookie, SameSite};
use actix_web::{
    get, http::header, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use chrono::{Duration as ChronoDuration, NaiveDateTime, Utc};
use dotenv::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header};
use log::{error, info};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::env;

fn app_base_url() -> String {
    env::var("APP_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string())
        .trim_end_matches('/')
        .to_string()
}

fn cookie_domain() -> Option<String> {
    env::var("COOKIE_DOMAIN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn cookie_secure() -> bool {
    env::var("COOKIE_SECURE")
        .map(|value| value == "true" || value == "1")
        .unwrap_or(true)
}

fn post_login_redirect() -> String {
    env::var("POST_LOGIN_REDIRECT").unwrap_or_else(|_| format!("{}/dashboard", app_base_url()))
}

fn frontend_origin() -> String {
    env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| app_base_url())
}

fn build_auth_cookie(name: &'static str, value: String, max_age: Duration) -> Cookie<'static> {
    let mut builder = Cookie::build(name, value)
        .path("/")
        .max_age(max_age)
        .http_only(true)
        .same_site(SameSite::None);

    if let Some(domain) = cookie_domain() {
        builder = builder.domain(domain);
    }

    let mut cookie = builder.finish();
    cookie.set_secure(cookie_secure());
    cookie
}

#[derive(Clone)]
struct AppState {
    redis_client: redis::Client,
}

// ====== Models ======
#[derive(Debug, Serialize, Deserialize)]
struct SessionData {
    user_id: i32,
    expires_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserInfo {
    id: String,
    email: String,
    verified_email: bool,
    picture: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
struct User {
    id: i32,
    email: String,
    google_id: String,
    name: Option<String>,
    icon_url: Option<String>,
    created_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    email: String,
    name: String,
    picture: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionResponse {
    session_id: String,
    token: String,
    user: User,
}

// ====== Handlers ======
#[post("/upsert_and_token")]
async fn upsert_and_token(
    pool: web::Data<Pool<Postgres>>,
    state: web::Data<AppState>,
    user_info: web::Json<UserInfo>,
) -> impl Responder {
    info!("Received /upsert_and_token request: {:?}", user_info);

    let response_mode = env::var("RESPONSE_MODE").unwrap_or_else(|_| "json".to_string()); // "json" or "redirect"

    // upsert
    let db_user = match upsert_user(&pool, &user_info).await {
        Ok(u) => u,
        Err(e) => {
            error!("Database upsert error: {:?}", e);
            return HttpResponse::InternalServerError().body("Database upsert error");
        }
    };

    // JWT
    let token = match generate_jwt(
        db_user.id,
        &db_user.email,
        db_user.name.as_deref().unwrap_or(""),
        db_user.icon_url.as_deref().unwrap_or(""),
    ) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to generate JWT: {:?}", e);
            return HttpResponse::InternalServerError().body("JWT generation error");
        }
    };

    // セッション ID 生成 & Redis 保存（24h）
    let session_id: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();
    let expires_at = Utc::now().timestamp() + 24 * 3600;
    let session_data = SessionData {
        user_id: db_user.id,
        expires_at,
    };

    let mut conn = match state.redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to get Redis connection: {:?}", e);
            return HttpResponse::InternalServerError()
                .body("Internal server error: Redis connection failed");
        }
    };
    if let Err(e) = conn
        .set_ex::<_, _, ()>(
            &session_id,
            serde_json::to_string(&session_data).unwrap(),
            24 * 3600,
        )
        .await
    {
        error!("Failed to store session in Redis: {:?}", e);
        return HttpResponse::InternalServerError()
            .body("Internal server error: Failed to store session");
    }

    // Cookie 作成（SameSite=None + Secure、本番必須）
    let max_age = Duration::seconds(24 * 3600);

    let jwt_cookie = build_auth_cookie("jwt", token.clone(), max_age);
    let sid_cookie = build_auth_cookie("session_id", session_id.clone(), max_age);

    // 返し方を選択：JSON or 302 リダイレクト
    if response_mode == "redirect" {
        HttpResponse::Found()
            .insert_header((header::LOCATION, post_login_redirect()))
            .cookie(jwt_cookie)
            .cookie(sid_cookie)
            .finish()
    } else {
        HttpResponse::Ok()
            .cookie(jwt_cookie)
            .cookie(sid_cookie)
            .json(SessionResponse {
                session_id,
                token,
                user: db_user,
            })
    }
}

#[post("/logout")]
async fn logout(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Some(cookie) = req.cookie("session_id") {
        let session_id = cookie.value().to_string();
        let mut conn = match state.redis_client.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to get Redis connection: {:?}", e);
                return HttpResponse::InternalServerError()
                    .body("Internal server error: Redis connection failed");
            }
        };
        if let Err(e) = conn.del::<_, ()>(&session_id).await {
            error!("Failed to delete session from Redis: {:?}", e);
        }
    }

    // 有効期限 0 で無効化
    let expired_session = build_auth_cookie("session_id", "".to_string(), Duration::seconds(0));
    let expired_jwt = build_auth_cookie("jwt", "".to_string(), Duration::seconds(0));

    HttpResponse::Ok()
        .cookie(expired_session)
        .cookie(expired_jwt)
        .body("Logged out")
}

#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("ok")
}

// ====== Helpers ======
async fn upsert_user(pool: &Pool<Postgres>, user_info: &UserInfo) -> Result<User, sqlx::Error> {
    let name_guess = format!("User_{}", user_info.id);
    let icon_url = Some(user_info.picture.clone());
    let record = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (email, google_id, name, icon_url)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (google_id)
        DO UPDATE SET email = EXCLUDED.email,
                      name = EXCLUDED.name,
                      icon_url = EXCLUDED.icon_url
        RETURNING id, email, google_id, name, icon_url, created_at
        "#,
    )
    .bind(&user_info.email)
    .bind(&user_info.id)
    .bind(&name_guess)
    .bind(icon_url)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

fn generate_jwt(
    user_id: i32,
    email: &str,
    name: &str,
    picture: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let secret_key = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let expiration = Utc::now()
        .checked_add_signed(ChronoDuration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        name: name.to_string(),
        picture: picture.to_string(),
        exp: expiration,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.as_ref()),
    )
}

// ====== Boot ======
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let host = env::var("POSTGRES_HOST").expect("POSTGRES_HOST not set");
    let user = env::var("POSTGRES_USER").expect("POSTGRES_USER not set");
    let password = env::var("POSTGRES_PASSWORD").expect("POSTGRES_PASSWORD not set");
    let db_name = env::var("DB_NAME").unwrap_or_else(|_| "auth0_accounts".to_string());
    let database_url = format!("postgres://{user}:{password}@{host}:5432/{db_name}");
    let pool = Pool::<Postgres>::connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    let redis_client = redis::Client::open(redis_url).expect("Failed to create Redis client");

    let app_state = AppState { redis_client };
    let frontend_origin = frontend_origin();

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&frontend_origin) // * は使わない
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allowed_headers(vec![header::CONTENT_TYPE, header::COOKIE])
            .supports_credentials(); // Cookie を通す

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(app_state.clone()))
            .service(upsert_and_token)
            .service(logout)
            .service(health)
    })
    .bind("0.0.0.0:8081")?
    .run()
    .await
}
