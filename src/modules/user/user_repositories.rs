use super::{
    user_dtos::{DetailUserDTO, InsertUserDTO, PutUserDTO, UserDTO},
    user_queues::{DeleteUserAppQueue, InsertUserAppQueue, PutUserAppQueue},
};
use crate::{
    shared::structs::query_params::QueryParams,
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

fn user_dto_constructor(rows: Vec<postgres::Row>) -> UserDTO {
    let user_id: uuid::Uuid = rows[0].get("id");
    let created_at: chrono::DateTime<chrono::Utc> = rows[0].get("created_at");
    let updated_at: Option<chrono::DateTime<chrono::Utc>> = rows[0].get("updated_at");

    UserDTO {
        id: user_id.to_string(),
        name: rows[0].get("name"),
        email: rows[0].get("email"),
        password: rows[0].get("password"),
        created_at: created_at.to_string(),
        updated_at: updated_at.map(|dt| dt.to_string()),
    }
}

pub async fn get_user_salt_repository(
    user_id: String,
    postgres_pool: Data<deadpool_postgres::Pool>,
) -> Result<String, HttpResponse> {
    let mut sql_builder = sql_builder::SqlBuilder::select_from("salt");
    sql_builder.field("salt");
    sql_builder.or_where_eq("user_id", &quote(user_id));

    let rows = match query_constructor_executor(postgres_pool, sql_builder).await {
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
    queue: Data<Arc<InsertUserAppQueue>>,
    body: Json<InsertUserDTO>,
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
        updated_at: None,
    };
    queue.push((user_id.clone(), body, created_at, user_salt));

    Ok(dto)
}

pub async fn login_user_repository(
    email: String,
    postgres_pool: Data<deadpool_postgres::Pool>,
) -> Result<UserDTO, HttpResponse> {
    let mut sql_builder = sql_builder::SqlBuilder::select_from("users");
    sql_builder.or_where_eq("email", &quote(email.clone()));

    let rows = match query_constructor_executor(postgres_pool, sql_builder).await {
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

    Ok(user_dto_constructor(rows))
}

pub async fn detail_user_repository(
    postgres_pool: Data<deadpool_postgres::Pool>,
    user_id: String,
) -> Result<UserDTO, HttpResponse> {
    let mut sql_builder = sql_builder::SqlBuilder::select_from("users");
    sql_builder.or_where_eq("id", &quote(user_id));

    let rows = match query_constructor_executor(postgres_pool, sql_builder).await {
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

    Ok(user_dto_constructor(rows))
}

pub async fn list_users_repository(
    postgres_pool: Data<deadpool_postgres::Pool>,
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
    sql_builder.fields(&["id", "name", "email", "created_at", "updated_at"]);
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

    let rows = match query_constructor_executor(postgres_pool, sql_builder).await {
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
        let updated_at: Option<chrono::DateTime<chrono::Utc>> = row.get("updated_at");
        let user = DetailUserDTO {
            id: user_id.to_string(),
            name: row.get("name"),
            email: row.get("email"),
            created_at: created_at.to_string(),
            updated_at: updated_at.map(|x| x.to_string()),
        };
        users.push(user);
    }
    Ok(users)
}

pub async fn delete_user_repository(
    queue: Data<Arc<DeleteUserAppQueue>>,
    user_id: String,
) -> Result<(), HttpResponse> {
    queue.push(user_id.clone());

    Ok(())
}

pub async fn put_user_repository(
    queue: Data<Arc<PutUserAppQueue>>,
    user: Json<PutUserDTO>,
    user_id: String,
) -> Result<String, HttpResponse> {
    let updated_at = chrono::Utc::now().to_string();

    queue.push((user_id.clone(), user, updated_at.clone()));

    Ok(updated_at)
}
