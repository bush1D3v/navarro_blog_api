use std::env;

use actix_web::{http::KeepAlive, App, HttpServer};

mod controllers;
use controllers::hello_world::hello_world;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let http_port: String = env::var("HTTP_PORT").unwrap_or("8080".into());

    HttpServer::new(move || App::new().service(hello_world))
        .keep_alive(KeepAlive::Os)
        .bind(format!("0.0.0.0:{http_port}"))?
        .run()
        .await?;

    Ok(())
}
