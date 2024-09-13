use actix_web::dev::Transform;
use actix_web::{
    dev::Service, dev::ServiceRequest, dev::ServiceResponse, web, App, Error, HttpResponse,
    HttpServer, Responder,
};
// futures::FutureExtのインポートを削除
use dotenv::dotenv;
use futures::future::{ok, Ready};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub struct AuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddlewareMiddleware {
            service: Rc::new(service),
        })
    }
}

pub struct AuthMiddlewareMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            let auth_header = req.headers().get("Authorization");

            if let Some(header_value) = auth_header {
                if let Ok(auth_str) = header_value.to_str() {
                    if let Some(token) = auth_str.strip_prefix("Bearer ") {
                        let secret =
                            env::var("AUTH0_AUDIENCE").expect("AUTH0_AUDIENCE must be set");

                        let validation = Validation::new(Algorithm::RS256);
                        let key = DecodingKey::from_secret(secret.as_ref());

                        match decode::<Claims>(token, &key, &validation) {
                            Ok(_) => {
                                return service.call(req).await;
                            }
                            Err(_) => {
                                return Err(actix_web::error::ErrorUnauthorized("Invalid token"));
                            }
                        }
                    }
                }
            }
            Err(actix_web::error::ErrorUnauthorized(
                "Authorization header missing",
            ))
        })
    }
}

async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    HttpServer::new(|| {
        App::new()
            .wrap(AuthMiddleware)
            .route("/", web::get().to(index))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}