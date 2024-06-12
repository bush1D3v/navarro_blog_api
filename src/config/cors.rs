use std::env;

use actix_cors::Cors;
use actix_web::http;

pub fn cors() -> Cors {
    let http_port = env::var("HTTP_PORT").unwrap_or("8080".into());

    Cors::default()
        .allowed_origin(&format!("http://localhost:{}", http_port))
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
        .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
        .allowed_header(http::header::CONTENT_TYPE)
        .max_age(3600)
}
