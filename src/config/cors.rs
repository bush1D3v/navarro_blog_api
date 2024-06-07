use actix_cors::Cors;
use actix_web::http;
use std::env;

pub fn cors() -> Cors {
    let http_port: String = env::var("HTTP_PORT").unwrap_or("8080".into());

    return Cors::default()
        .allowed_origin(&format!("http://localhost:{}", http_port))
        .allowed_origin_fn(|origin, _req_head| origin.as_bytes().ends_with(b".rust-lang.org"))
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
        .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
        .allowed_header(http::header::CONTENT_TYPE)
        .max_age(3600);
}
