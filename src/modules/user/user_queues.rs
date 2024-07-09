use super::user_dtos::CreateUserDTO;
use crate::shared::exceptions::custom_error_to_io_error_kind::{
    custom_error_to_io_error_kind, CustomError,
};
use actix_web::{
    web::{Data, Json},
    HttpResponse,
};
use deadpool_postgres::Pool;
use sql_builder::{quote, SqlBuilder};
use std::{io::ErrorKind, sync::Arc, time::Duration};

type SaltData = (String, String, Data<deadpool_postgres::Pool>);
type QueueEvent = (String, Json<CreateUserDTO>, String, SaltData);
pub type CreateUserAppQueue = deadqueue::unlimited::Queue<QueueEvent>;

async fn insert_user_queue(pool: Pool, queue: Arc<CreateUserAppQueue>) -> Result<(), HttpResponse> {
    let mut user_sql = String::new();
    let mut user_salt_sql = String::new();
    while queue.len() > 0 {
        let (id, body, created_at, salt) = queue.pop().await;
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
            &quote(&created_at),
        ]);
        let mut this_sql = match sql_builder.sql() {
            Ok(x) => x,
            Err(_) => continue,
        };
        this_sql.pop();
        user_sql.push_str(this_sql.as_str());

        let mut sql_builder = SqlBuilder::insert_into("salt");
        sql_builder.field("user_id").field("salt");
        sql_builder.values(&[&quote(&id), &quote(&salt.0)]);
        let mut this_sql = match sql_builder.sql() {
            Ok(x) => x,
            Err(_) => continue,
        };
        this_sql.pop();
        user_salt_sql.push_str(this_sql.as_str());
    }
    let mut conn = match pool.get().await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::PoolError(e))),
    };
    let transaction = match conn.transaction().await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    match transaction.batch_execute(&user_sql).await {
        Ok(_) => (),
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    match transaction.batch_execute(&user_salt_sql).await {
        Ok(_) => (),
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    match transaction.commit().await {
        Ok(_) => (),
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    Ok(())
}

pub async fn user_flush_queue(pool_async: Pool, queue_async: Arc<CreateUserAppQueue>) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let queue = queue_async.clone();
        if queue.len() == 0 {
            continue;
        }
        match insert_user_queue(pool_async.clone(), queue).await {
            Ok(_) => (),
            Err(e) => {
                let status = e.status();
                let kind: ErrorKind;
                if status == 503 {
                    kind = ErrorKind::ConnectionAborted;
                } else {
                    kind = ErrorKind::Other;
                }
                let message = e.error().unwrap().to_string();
                std::io::Error::new(kind, message);
            }
        }
    }
}
