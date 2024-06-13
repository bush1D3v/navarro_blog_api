use actix_web::{http::KeepAlive, web, App, HttpServer};
use config::{api_doc::api_doc, cors::cors};
use infra::{postgres::postgres, redis::Redis};
use modules::user::{
    user_controllers::insert_user,
    user_queues::{user_flush_queue, CreateUserAppQueue},
};
use std::{env, net::Ipv4Addr, sync::Arc};

mod config;
mod infra;
mod middlewares;
mod modules;
mod providers;
mod shared;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    let http_port = env::var("HTTP_PORT").unwrap_or("8080".into());
    let redis_pool = Redis::pool().await;
    let pool = postgres();
    let pool_async = pool.clone();
    let queue = Arc::new(CreateUserAppQueue::new());
    let queue_async = queue.clone();
    tokio::spawn(async move { user_flush_queue(pool_async, queue_async).await });

    HttpServer::new(move || {
        App::new()
            .wrap(cors())
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(redis_pool.clone()))
            .app_data(web::Data::new(queue.clone()))
            .service(api_doc())
            .service(insert_user)
    })
    .keep_alive(KeepAlive::Os)
    .bind((Ipv4Addr::UNSPECIFIED, http_port.parse().unwrap_or(8080)))?
    .run()
    .await?;

    Ok(())
}
