use chrono::Utc;
use cookie::Cookie;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use warp::Filter;

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

    let routes = me_route
        .or(health_route)
        .with(cors)
        .with(warp::log("portal_backend"));

    println!("Backend server running on port {}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
