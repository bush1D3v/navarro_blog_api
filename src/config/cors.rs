use actix_cors::Cors;
use actix_web::http;
use std::env;

pub fn cors() -> Cors {
    Cors::default()
        .allowed_origin(&format!(
            "{}:{}",
            env::var("BASE_URL").unwrap(),
            env::var("HTTP_PORT").unwrap()
        ))
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE", "OPTIONS", "PUT"])
        .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
        .allowed_header(http::header::CONTENT_TYPE)
        .max_age(3600)
}
