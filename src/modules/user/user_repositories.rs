use super::{
    user_dtos::{CreateUserDTO, DetailUserDTO, UserDTO},
    user_queues::CreateUserAppQueue,
};
use crate::{
    shared::{
        exceptions::custom_error_to_io_error_kind::{custom_error_to_io_error_kind, CustomError},
        structs::query_params::QueryParams,
    },
    utils::{
        error_construct::error_construct, query_constructor_executor::query_constructor_executor,
    },
};
use actix_web::{
    web::{Data, Json, Query},
    HttpResponse,
};
use sql_builder::quote;
use std::sync::Arc;

pub async fn get_user_salt_repository(
    user_id: String,
    pg_pool: Data<deadpool_postgres::Pool>,
) -> Result<String, HttpResponse> {
    let mut sql_builder = sql_builder::SqlBuilder::select_from("salt");
    sql_builder.field("salt");
    sql_builder.or_where_eq("user_id", &quote(&user_id));

    let rows = match query_constructor_executor(pg_pool, sql_builder).await {
        Ok(x) => x,
        Err(e) => return Err(e),
    };

    if rows.is_empty() {
        return Err(HttpResponse::InternalServerError().json(error_construct(
            String::from("server"),
            String::from("internal server error"),
            String::from("Erro inesperado no servidor. Tente novamente mais tarde."),
            None,
            None,
            None,
        )));
    }
    let salt: uuid::Uuid = rows[0].get("salt");
    Ok(salt.to_string())
}

pub async fn insert_user_repository(
    queue: Data<Arc<CreateUserAppQueue>>,
    pool: Data<deadpool_postgres::Pool>,
    body: Json<CreateUserDTO>,
    user_id: String,
    user_salt: String,
) -> Result<UserDTO, HttpResponse> {
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
        created_at,
        (user_salt, user_id, pool),
    ));

    Ok(dto)
}

pub async fn login_user_repository(
    email: String,
    pg_pool: Data<deadpool_postgres::Pool>,
) -> Result<UserDTO, HttpResponse> {
    let mut sql_builder = sql_builder::SqlBuilder::select_from("users");
    sql_builder.or_where_eq("email", &quote(&email));

    let rows = match query_constructor_executor(pg_pool, sql_builder).await {
        Ok(x) => x,
        Err(e) => return Err(e),
    };

    if rows.is_empty() {
        return Err(HttpResponse::NotFound().json(error_construct(
            String::from("user"),
            String::from("not found"),
            String::from("Não foi encontrado um usuário com este e-mail."),
            Some(email),
            None,
            None,
        )));
    }

    let user_id: uuid::Uuid = rows[0].get("id");
    let created_at: chrono::DateTime<chrono::Utc> = rows[0].get("created_at");
    Ok(UserDTO {
        id: user_id.to_string(),
        name: rows[0].get("name"),
        email: rows[0].get("email"),
        created_at: created_at.to_string(),
        password: rows[0].get("password"),
    })
}

pub async fn detail_user_repository(
    pg_pool: Data<deadpool_postgres::Pool>,
    user_id: String,
) -> Result<UserDTO, HttpResponse> {
    let mut sql_builder = sql_builder::SqlBuilder::select_from("users");
    sql_builder.or_where_eq("id", &quote(&user_id));

    let rows = match query_constructor_executor(pg_pool, sql_builder).await {
        Ok(x) => x,
        Err(e) => return Err(e),
    };

    if rows.is_empty() {
        return Err(HttpResponse::NotFound().json(error_construct(
            String::from("user"),
            String::from("not found"),
            String::from("Não foi encontrado um usuário com este id."),
            None,
            None,
            None,
        )));
    }

    let user_id: uuid::Uuid = rows[0].get("id");
    let created_at: chrono::DateTime<chrono::Utc> = rows[0].get("created_at");
    Ok(UserDTO {
        id: user_id.to_string(),
        name: rows[0].get("name"),
        email: rows[0].get("email"),
        created_at: created_at.to_string(),
        password: rows[0].get("password"),
    })
}

pub async fn list_users_repository(
    pg_pool: Data<deadpool_postgres::Pool>,
    query_params: Query<QueryParams>,
) -> Result<Vec<DetailUserDTO>, HttpResponse> {
    let order_by = query_params
        .order_by
        .clone()
        .unwrap_or(String::from("created_at"));
    let order_direction = query_params
        .order_direction
        .clone()
        .unwrap_or(String::from("desc"));

    let mut sql_builder = sql_builder::SqlBuilder::select_from("users");
    sql_builder.fields(&["id", "name", "email", "created_at"]);
    sql_builder.order_by(
        order_by,
        match order_direction.as_str() {
            "asc" => false,
            "desc" => true,
            _ => true,
        },
    );
    let limit = query_params.limit.unwrap_or(20);
    sql_builder.limit(limit);
    sql_builder.offset(query_params.offset.unwrap_or(0));

    let rows = match query_constructor_executor(pg_pool, sql_builder).await {
        Ok(x) => x,
        Err(e) => return Err(e),
    };

    if rows.is_empty() {
        return Err(HttpResponse::NotFound().json(error_construct(
            String::from("users"),
            String::from("not found"),
            String::from("Não foram encontrados usuários."),
            None,
            None,
            None,
        )));
    }

    let mut users: Vec<DetailUserDTO> = Vec::with_capacity(limit as usize);
    for row in rows {
        let user_id: uuid::Uuid = row.get("id");
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        let user = DetailUserDTO {
            id: user_id.to_string(),
            name: row.get("name"),
            email: row.get("email"),
            created_at: created_at.to_string(),
        };
        users.push(user);
    }
    Ok(users)
}

pub async fn delete_user_repository(
    pg_pool: Data<deadpool_postgres::Pool>,
    user_id: String,
) -> Result<(), HttpResponse> {
    let mut salt_sql_builder = sql_builder::SqlBuilder::delete_from("salt");
    salt_sql_builder.or_where_eq("user_id", &quote(&user_id));

    let mut user_sql_builder = sql_builder::SqlBuilder::delete_from("users");
    user_sql_builder.or_where_eq("id", &quote(&user_id));

    let mut conn = match pg_pool.get().await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::PoolError(e))),
    };
    let transaction = match conn.transaction().await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    let salt_sql = match salt_sql_builder.sql() {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::AnyhowError(e))),
    };
    match transaction.query(salt_sql.as_str(), &[]).await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    let user_sql = match user_sql_builder.sql() {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::AnyhowError(e))),
    };
    match transaction.query(user_sql.as_str(), &[]).await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    match transaction.commit().await {
        Ok(_) => (),
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };

    Ok(())
}
