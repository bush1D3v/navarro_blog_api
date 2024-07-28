use super::user_dtos::{InsertUserDTO, PutUserDTO};
use crate::shared::exceptions::custom_error_to_io_error_kind::{
    custom_error_to_io_error_kind, CustomError,
};
use actix_web::{web::Json, HttpResponse};
use deadpool_postgres::Pool;
use sql_builder::{quote, SqlBuilder};
use std::{io::ErrorKind, sync::Arc, time::Duration};

type InsertUserQueueEvent = (String, Json<InsertUserDTO>, String, String);
pub type InsertUserAppQueue = deadqueue::unlimited::Queue<InsertUserQueueEvent>;

async fn insert_user_queue(pool: Pool, queue: Arc<InsertUserAppQueue>) -> Result<(), HttpResponse> {
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
        user_sql.push_str(&this_sql);

        let mut sql_builder = SqlBuilder::insert_into("salt");
        sql_builder.field("user_id").field("salt");
        sql_builder.values(&[&quote(&id), &quote(&salt)]);

        let mut this_sql = match sql_builder.sql() {
            Ok(x) => x,
            Err(_) => continue,
        };
        this_sql.pop();
        user_salt_sql.push_str(&this_sql);
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

pub async fn insert_user_flush_queue(pool_async: Pool, queue_async: Arc<InsertUserAppQueue>) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let queue = queue_async.clone();
        if queue.len() == 0 {
            continue;
        }
        match insert_user_queue(pool_async.clone(), queue).await {
            Ok(_) => (),
            Err(e) => {
                let message = e.error().unwrap().to_string();
                if e.status() == 503 {
                    std::io::Error::new(ErrorKind::ConnectionAborted, message);
                } else {
                    std::io::Error::new(ErrorKind::Other, message);
                }
            }
        }
    }
}

type PutUserQueueEvent = (String, Json<PutUserDTO>, String);
pub type PutUserAppQueue = deadqueue::unlimited::Queue<PutUserQueueEvent>;

async fn put_user_queue(pool: Pool, queue: Arc<PutUserAppQueue>) -> Result<(), HttpResponse> {
    let mut user_sql = String::new();

    while queue.len() > 0 {
        let (user_id, user, updated_at) = queue.pop().await;

        let mut sql_builder = sql_builder::SqlBuilder::update_table("users");

        sql_builder.set("password", &quote(&user.new_password));
        sql_builder.set("email", &quote(&user.new_email));
        sql_builder.set("updated_at", &quote(&updated_at));
        sql_builder.or_where_eq("id", &quote(user_id));

        let mut this_sql = match sql_builder.sql() {
            Ok(x) => x,
            Err(_) => continue,
        };
        this_sql.pop();
        user_sql.push_str(&this_sql);
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
    match transaction.commit().await {
        Ok(_) => (),
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };

    Ok(())
}

pub async fn put_user_flush_queue(pool_async: Pool, queue_async: Arc<PutUserAppQueue>) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let queue = queue_async.clone();
        if queue.len() == 0 {
            continue;
        }
        match put_user_queue(pool_async.clone(), queue).await {
            Ok(_) => (),
            Err(e) => {
                let message = e.error().unwrap().to_string();
                if e.status() == 503 {
                    std::io::Error::new(ErrorKind::ConnectionAborted, message);
                } else {
                    std::io::Error::new(ErrorKind::Other, message);
                }
            }
        }
    }
}

pub type DeleteUserAppQueue = deadqueue::unlimited::Queue<String>;

async fn delete_user_queue(pool: Pool, queue: Arc<DeleteUserAppQueue>) -> Result<(), HttpResponse> {
    let mut salt_sql = String::new();
    let mut user_sql = String::new();

    while queue.len() > 0 {
        let user_id = queue.pop().await;

        let mut sql_builder = SqlBuilder::delete_from("salt");
        sql_builder.or_where_eq("user_id", &quote(user_id.clone()));

        let mut this_sql = match sql_builder.sql() {
            Ok(x) => x,
            Err(_) => continue,
        };
        this_sql.pop();
        salt_sql.push_str(&this_sql);

        let mut sql_builder = SqlBuilder::delete_from("users");
        sql_builder.or_where_eq("id", &quote(user_id));

        let mut this_sql = match sql_builder.sql() {
            Ok(x) => x,
            Err(_) => continue,
        };
        this_sql.pop();
        user_sql.push_str(&this_sql);
    }

    let mut conn = match pool.get().await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::PoolError(e))),
    };
    let transaction = match conn.transaction().await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    match transaction.batch_execute(&salt_sql).await {
        Ok(_) => (),
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    match transaction.batch_execute(&user_sql).await {
        Ok(_) => (),
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    match transaction.commit().await {
        Ok(_) => (),
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };

    Ok(())
}

pub async fn delete_user_flush_queue(pool_async: Pool, queue_async: Arc<DeleteUserAppQueue>) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let queue = queue_async.clone();
        if queue.len() == 0 {
            continue;
        }
        match delete_user_queue(pool_async.clone(), queue).await {
            Ok(_) => (),
            Err(e) => {
                let message = e.error().unwrap().to_string();
                if e.status() == 503 {
                    std::io::Error::new(ErrorKind::ConnectionAborted, message);
                } else {
                    std::io::Error::new(ErrorKind::Other, message);
                }
            }
        }
    }
}
