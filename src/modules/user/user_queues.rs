use super::user_dtos::CreateUserDTO;
use crate::shared::exceptions::custom_error_to_io_error_kind::{
    custom_error_to_io_error_kind, CustomError,
};
use deadpool_postgres::Pool;
use sql_builder::{quote, SqlBuilder};
use std::{sync::Arc, time::Duration};

type QueueEvent = (String, actix_web::web::Json<CreateUserDTO>, Option<String>);
pub type CreateUserAppQueue = deadqueue::unlimited::Queue<QueueEvent>;

async fn user_insert(pool: Pool, queue: Arc<CreateUserAppQueue>) -> Result<(), std::io::Error> {
    let mut sql = String::new();
    while queue.len() > 0 {
        let (id, body, created_at) = queue.pop().await;
        let mut sql_builder = SqlBuilder::insert_into("users");
        sql_builder
            .field("id")
            .field("name")
            .field("email")
            .field("password")
            .field("created_at");
        sql_builder.values(&[
            &quote(&id),
            &quote(&body.name),
            &quote(&body.email),
            &quote(&body.password),
            &quote(&created_at.unwrap_or(chrono::Utc::now().to_string())),
        ]);
        let mut this_sql = match sql_builder.sql() {
            Ok(x) => x,
            Err(_) => continue,
        };
        this_sql.pop();
        sql.push_str(this_sql.as_str());
    }
    let mut conn = match pool.get().await {
        Ok(x) => x,
        Err(e) => {
            return Err(std::io::Error::new(
                custom_error_to_io_error_kind(CustomError::PoolError(&e)),
                e,
            ))
        }
    };
    let transaction = match conn.transaction().await {
        Ok(x) => x,
        Err(e) => {
            return Err(std::io::Error::new(
                custom_error_to_io_error_kind(CustomError::TokioPostgres(&e)),
                e,
            ))
        }
    };
    match transaction.batch_execute(&sql).await {
        Ok(_) => (),
        Err(e) => {
            return Err(std::io::Error::new(
                custom_error_to_io_error_kind(CustomError::TokioPostgres(&e)),
                e,
            ))
        }
    };
    match transaction.commit().await {
        Ok(_) => (),
        Err(e) => {
            return Err(std::io::Error::new(
                custom_error_to_io_error_kind(CustomError::TokioPostgres(&e)),
                e,
            ))
        }
    };
    Ok(())
}

pub async fn user_flush_queue(pool_async: Pool, queue_async: Arc<CreateUserAppQueue>) {
    loop {
        tokio::time::sleep(Duration::from_secs_f32(0.5)).await;
        let queue = queue_async.clone();
        if queue.len() == 0 {
            continue;
        }
        user_insert(pool_async.clone(), queue).await.unwrap();
    }
}
