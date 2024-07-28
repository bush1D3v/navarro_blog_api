use actix_web::{http::KeepAlive, web, App, HttpServer};
use config::{api_doc::api_doc, cors::cors};
use infra::{postgres::Postgres, redis::Redis};
use modules::user::{
    user_controllers::user_controllers_module,
    user_queues::{
        delete_user_flush_queue, insert_user_flush_queue, put_user_flush_queue, DeleteUserAppQueue,
        InsertUserAppQueue, PutUserAppQueue,
    },
};
use std::{env, net::Ipv4Addr, sync::Arc};

mod config;
mod infra;
mod middlewares;
mod modules;
mod shared;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    dotenv::dotenv().ok();

    let redis_pool = Redis::pool().await;
    let pool = Postgres::pool();

    let insert_pool_async = pool.clone();
    let insert_user_queue = Arc::new(InsertUserAppQueue::new());
    let insert_user_queue_async = insert_user_queue.clone();

    let delete_pool_async = pool.clone();
    let delete_user_queue = Arc::new(DeleteUserAppQueue::new());
    let delete_user_queue_async = delete_user_queue.clone();

    let put_pool_async = pool.clone();
    let put_user_queue = Arc::new(PutUserAppQueue::new());
    let put_user_queue_async = put_user_queue.clone();

    tokio::spawn(async move {
        insert_user_flush_queue(insert_pool_async, insert_user_queue_async).await
    });
    tokio::spawn(async move {
        delete_user_flush_queue(delete_pool_async, delete_user_queue_async).await
    });
    tokio::spawn(async move { put_user_flush_queue(put_pool_async, put_user_queue_async).await });

    HttpServer::new(move || {
        App::new()
            .wrap(cors())
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(redis_pool.clone()))
            .app_data(web::Data::new(insert_user_queue.clone()))
            .app_data(web::Data::new(delete_user_queue.clone()))
            .app_data(web::Data::new(put_user_queue.clone()))
            .service(user_controllers_module())
            .service(api_doc())
    })
    .keep_alive(KeepAlive::Os)
    .bind((
        Ipv4Addr::UNSPECIFIED,
        env::var("HTTP_PORT").unwrap().parse().unwrap(),
    ))?
    .run()
    .await?;

    Ok(())
}
