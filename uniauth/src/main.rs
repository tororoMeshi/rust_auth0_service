// uniauth/src/main.rs

use actix_cors::Cors;
use actix_web::{
    get, http::header, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use chrono::{NaiveDateTime, Utc};
use dotenv::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header};
use log::{error, info};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::{env, io};

fn app_base_url() -> String {
    env::var("APP_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string())
        .trim_end_matches('/')
        .to_string()
}

fn frontend_origin() -> String {
    env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| app_base_url())
}

fn required_env(name: &str) -> io::Result<String> {
    env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} environment variable is required"),
        )
    })
}

#[derive(Clone)]
struct AppState {
    redis_client: redis::Client,
    jwt_secret: String,
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
        &state.jwt_secret,
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
    let serialized_session = match serde_json::to_string(&session_data) {
        Ok(value) => value,
        Err(e) => {
            error!("Failed to serialize session data: {:?}", e);
            return HttpResponse::InternalServerError()
                .body("Internal server error: Failed to serialize session");
        }
    };
    if let Err(e) = conn
        .set_ex::<_, _, ()>(&session_id, serialized_session, 24 * 3600)
        .await
    {
        error!("Failed to store session in Redis: {:?}", e);
        return HttpResponse::InternalServerError()
            .body("Internal server error: Failed to store session");
    }

    HttpResponse::Ok().json(SessionResponse {
        session_id,
        token,
        user: db_user,
    })
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

    HttpResponse::Ok().body("Logged out")
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
    secret_key: &str,
    user_id: i32,
    email: &str,
    name: &str,
    picture: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = (Utc::now().timestamp() + 24 * 3600) as usize;
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

    let host = required_env("POSTGRES_HOST")?;
    let user = required_env("POSTGRES_USER")?;
    let password = required_env("POSTGRES_PASSWORD")?;
    let jwt_secret = required_env("JWT_SECRET")?;
    let db_name = env::var("DB_NAME").unwrap_or_else(|_| "auth0_accounts".to_string());
    let database_url = format!("postgres://{user}:{password}@{host}:5432/{db_name}");
    let pool = Pool::<Postgres>::connect(&database_url)
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("failed to connect to Postgres: {e}"),
            )
        })?;

    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    let redis_client = redis::Client::open(redis_url).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to create Redis client: {e}"),
        )
    })?;

    let app_state = AppState {
        redis_client,
        jwt_secret,
    };
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
