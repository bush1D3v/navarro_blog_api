mod config;
mod controllers;

use crate::controllers::hello_world::hello_world;
use actix_web::{http::KeepAlive, App, HttpServer};
use config::api_doc::api_doc;
use std::{env, net::Ipv4Addr};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let http_port: String = env::var("HTTP_PORT").unwrap_or("8080".into());

    HttpServer::new(move || App::new().service(hello_world).service(api_doc()))
        .keep_alive(KeepAlive::Os)
        .bind((Ipv4Addr::UNSPECIFIED, http_port.parse().unwrap_or(8080)))?
        .run()
        .await?;

    Ok(())
}
