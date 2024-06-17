use crate::shared::exceptions::custom_error_to_io_error_kind::{
    custom_error_to_io_error_kind, CustomError,
};

use super::{
    user_dtos::{CreateUserDTO, UserDTO},
    user_queues::CreateUserAppQueue,
};
use actix_web::web::{Data, Json};
use serde::Serialize;
use sql_builder::quote;
use std::sync::Arc;

pub async fn get_user_salt_repository(
    user_id: String,
    pool: Data<deadpool_postgres::Pool>,
) -> Result<String, std::io::Error> {
    let mut sql_builder = sql_builder::SqlBuilder::select_from("salt");
    sql_builder.field("salt");
    sql_builder.or_where_eq("user_id", &quote(&user_id));

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
    let sql = match sql_builder.sql() {
        Ok(x) => x,
        Err(e) => {
            return Err(std::io::Error::new(
                custom_error_to_io_error_kind(CustomError::AnyhowError(&e)),
                e,
            ))
        }
    };
    let rows = match transaction.query(sql.as_str(), &[]).await {
        Ok(x) => x,
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

    let salt: uuid::Uuid = rows[0].get("salt");
    Ok(salt.to_string())
}

pub async fn insert_user_repository(
    queue: Data<Arc<CreateUserAppQueue>>,
    pool: Data<deadpool_postgres::Pool>,
    body: Json<CreateUserDTO>,
    user_id: String,
    user_salt: String,
) -> Result<UserDTO, std::io::Error> {
    let name = body.name.clone();
    let email = body.email.clone();
    let password = body.password.clone();
    let created_at = chrono::Utc::now().to_string();
    let dto = UserDTO {
        id: user_id.clone(),
        name,
        email,
        password,
        created_at: created_at.clone(),
    };
    queue.push((
        user_id.clone(),
        body,
        Some(created_at),
        (user_salt, user_id, pool),
    ));

    Ok(dto)
}

#[derive(Serialize)]
pub struct LoginUserRepositoryResponse {
    pub id: String,
    pub password: String,
}

pub async fn login_user_repository(
    email: String,
    pool: Data<deadpool_postgres::Pool>,
) -> Result<LoginUserRepositoryResponse, std::io::Error> {
    let mut sql_builder = sql_builder::SqlBuilder::select_from("users");
    sql_builder.field("id").field("password");
    sql_builder.or_where_eq("email", &quote(&email));

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
    let sql = match sql_builder.sql() {
        Ok(x) => x,
        Err(e) => {
            return Err(std::io::Error::new(
                custom_error_to_io_error_kind(CustomError::AnyhowError(&e)),
                e,
            ))
        }
    };
    let rows = match transaction.query(sql.as_str(), &[]).await {
        Ok(x) => x,
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

    let id: uuid::Uuid = rows[0].get("id");
    Ok(LoginUserRepositoryResponse {
        id: id.to_string(),
        password: rows[0].get("password"),
    })
}
