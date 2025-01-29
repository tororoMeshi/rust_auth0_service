use actix_web::middleware::{DefaultHeaders, Logger};
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use chrono::{Duration as ChronoDuration, NaiveDateTime, Utc};
use dotenv::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header};
use log::{error, info};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::env;

// Googleから送られるユーザー情報
#[derive(Debug, Serialize, Deserialize)]
struct UserInfo {
    id: String,
    email: String,
    verified_email: bool,
    picture: String,
}

// DB上の users テーブルと対応
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
struct User {
    // PostgresでSERIALを使っている -> int4 -> Rustではi32
    id: i32,
    email: String,
    google_id: String,
    name: Option<String>,
    icon_url: Option<String>,
    created_at: Option<NaiveDateTime>,
}

// JWT の中身
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // user ID
    email: String,
    exp: usize, // expiration time
}

#[post("/upsert_and_token")]
async fn upsert_and_token(
    pool: web::Data<Pool<Postgres>>,
    user_info: web::Json<UserInfo>,
) -> impl Responder {
    info!("Received /upsert_and_token request: {:?}", user_info);

    // 1. DB に Upsert
    match upsert_user(&pool, &user_info).await {
        Ok(db_user) => {
            info!(
                "Upsert user success: id={}, google_id={}",
                db_user.id, db_user.google_id
            );

            // 2. JWT を作成 (型が i32 に統一)
            match generate_jwt(db_user.id, &db_user.email) {
                Ok(token) => {
                    info!("JWT generated successfully for user_id={}", db_user.id);
                    HttpResponse::Ok().json(serde_json::json!({
                        "token": token,
                        "user": db_user
                    }))
                }
                Err(e) => {
                    error!("Failed to generate JWT: {:?}", e);
                    HttpResponse::InternalServerError().body("JWT generation error")
                }
            }
        }
        Err(e) => {
            error!("Database upsert error: {:?}", e);
            HttpResponse::InternalServerError().body("Database upsert error")
        }
    }
}

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

// ここを i64 → i32 に変更
fn generate_jwt(user_id: i32, email: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let secret_key = env::var("JWT_SECRET").unwrap_or_else(|_| "secret_key".to_string());

    let expiration = Utc::now()
        .checked_add_signed(ChronoDuration::hours(1))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        exp: expiration,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.as_ref()),
    )?;

    Ok(token)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    // 環境変数の読み込みとログ
    let host = env::var("POSTGRES_HOST").expect("POSTGRES_HOST not set");
    info!("POSTGRES_HOST={}", host);

    let user = env::var("POSTGRES_USER").expect("POSTGRES_USER not set");
    info!("POSTGRES_USER={}", user);

    let password = env::var("POSTGRES_PASSWORD").expect("POSTGRES_PASSWORD not set");
    // パスワードはログに出さないほうが安全

    let db_name = env::var("DB_NAME").unwrap_or_else(|_| "auth0_accounts".to_string());
    info!("DB_NAME={}", db_name);

    let database_url = format!("postgres://{user}:{password}@{host}:5432/{db_name}");

    // DB 接続
    let pool = match Pool::<Postgres>::connect(&database_url).await {
        Ok(p) => {
            info!("Successfully connected to Postgres: {}", database_url);
            p
        }
        Err(e) => {
            error!("Failed to connect to Postgres: {}", e);
            std::process::exit(1);
        }
    };

    // Actix Web サーバ起動
    let server = HttpServer::new(move || {
        App::new()
            .wrap(DefaultHeaders::new().add(("X-Frame-Options", "DENY")))
            .wrap(Logger::default())
            .app_data(web::Data::new(pool.clone()))
            .service(upsert_and_token)
    })
    .bind("0.0.0.0:8081")?
    .run();

    // Graceful shutdown 処理
    let server_handle = server.handle();
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    tokio::select! {
        _ = &mut ctrl_c => {
            info!("Received Ctrl+C, shutting down");
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
