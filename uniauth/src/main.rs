use actix_web::{post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use chrono::{Duration as ChronoDuration, NaiveDateTime, Utc};
use dotenv::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header};
use log::{error, info};
use rand::{distributions::Alphanumeric, Rng};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::env; // 非同期の Redis コマンドを利用

//
// === アプリケーション状態（Redis クライアント保持） ===
//

#[derive(Clone)]
struct AppState {
    redis_client: redis::Client,
}

//
// === セッションデータ、ユーザースキーマ ===
//

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
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionResponse {
    session_id: String,
    token: String,
    user: User,
}

//
// === ユーザー Upsert とセッション発行 API (/upsert_and_token) ===
//

#[post("/upsert_and_token")]
async fn upsert_and_token(
    pool: web::Data<Pool<Postgres>>,
    state: web::Data<AppState>,
    user_info: web::Json<UserInfo>,
) -> impl Responder {
    info!("Received /upsert_and_token request: {:?}", user_info);

    // ユーザー情報を DB に登録または更新する
    match upsert_user(&pool, &user_info).await {
        Ok(db_user) => {
            info!(
                "Upsert user success: id={}, google_id={}",
                db_user.id, db_user.google_id
            );
            // JWT を発行（有効期限 24 時間）
            match generate_jwt(db_user.id, &db_user.email) {
                Ok(token) => {
                    // セッション ID を 24 文字のランダム文字列で生成
                    let session_id: String = rand::thread_rng()
                        .sample_iter(&Alphanumeric)
                        .take(24)
                        .map(char::from)
                        .collect();
                    let expires_at = Utc::now().timestamp() + 24 * 3600;
                    let session_data = SessionData {
                        user_id: db_user.id,
                        expires_at,
                    };

                    // Redis にセッション情報を保存（SETEX コマンドで TTL を設定）
                    let mut conn = match state.redis_client.get_async_connection().await {
                        Ok(conn) => conn,
                        Err(e) => {
                            error!("Failed to get Redis connection: {:?}", e);
                            return HttpResponse::InternalServerError()
                                .body("Internal server error");
                        }
                    };

                    let session_json = match serde_json::to_string(&session_data) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Failed to serialize session data: {:?}", e);
                            return HttpResponse::InternalServerError()
                                .body("Internal server error");
                        }
                    };

                    let set_result: redis::RedisResult<()> =
                        conn.set_ex(&session_id, session_json, 24 * 3600).await;
                    if let Err(e) = set_result {
                        error!("Failed to store session in Redis: {:?}", e);
                        return HttpResponse::InternalServerError().body("Internal server error");
                    }

                    info!("Session stored in Redis for user_id={}", db_user.id);

                    HttpResponse::Ok().json(SessionResponse {
                        session_id,
                        token,
                        user: db_user,
                    })
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

fn generate_jwt(user_id: i32, email: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let secret_key = env::var("JWT_SECRET").unwrap_or_else(|_| "secret_key".to_string());
    let expiration = Utc::now()
        .checked_add_signed(ChronoDuration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        exp: expiration,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.as_ref()),
    )
}

//
// === ログアウト API (/logout) ===
//

#[post("/logout")]
async fn logout(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // クライアント送信の Cookie から session_id を抽出
    if let Some(cookie) = req.cookie("session_id") {
        let session_id = cookie.value().to_string();
        let mut conn = match state.redis_client.get_async_connection().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to get Redis connection: {:?}", e);
                return HttpResponse::InternalServerError().body("Internal server error");
            }
        };

        let del_result: redis::RedisResult<()> = conn.del(&session_id).await;
        match del_result {
            Ok(_) => {
                info!("Session {} deleted from Redis", session_id);
                HttpResponse::Ok().body("Logged out")
            }
            Err(e) => {
                error!("Failed to delete session from Redis: {:?}", e);
                HttpResponse::InternalServerError().body("Internal server error")
            }
        }
    } else {
        HttpResponse::BadRequest().body("No session cookie found")
    }
}

//
// === メイン処理 ===
//

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    // PostgreSQL 接続の設定
    let host = env::var("POSTGRES_HOST").expect("POSTGRES_HOST not set");
    let user = env::var("POSTGRES_USER").expect("POSTGRES_USER not set");
    let password = env::var("POSTGRES_PASSWORD").expect("POSTGRES_PASSWORD not set");
    let db_name = env::var("DB_NAME").unwrap_or_else(|_| "auth0_accounts".to_string());
    let database_url = format!("postgres://{user}:{password}@{host}:5432/{db_name}");
    let pool = match Pool::<Postgres>::connect(&database_url).await {
        Ok(p) => {
            info!("Successfully connected to Postgres");
            p
        }
        Err(e) => {
            error!("Failed to connect to Postgres: {}", e);
            std::process::exit(1);
        }
    };

    // Redis クライアントの初期化（REDIS_URL から取得）
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    let redis_client = redis::Client::open(redis_url).expect("Failed to create Redis client");

    let app_state = AppState { redis_client };

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(app_state.clone()))
            .service(upsert_and_token)
            .service(logout)
    })
    .bind("0.0.0.0:8081")?
    .run()
    .await
}
