use crate::utils::{
    error_construct::error_construct, query_constructor_executor::query_constructor_executor,
};
use actix_web::{web::Data, HttpResponse};
use deadpool_postgres::Pool;
use sql_builder::SqlBuilder;

pub async fn email_exists(pg_pool: Data<Pool>, email: String) -> Result<(), HttpResponse> {
    let mut sql_builder = SqlBuilder::select_from("users");
    sql_builder.field("id");
    sql_builder.or_where_eq("email", email.clone());

    let rows = match query_constructor_executor(pg_pool, sql_builder).await {
        Ok(x) => x,
        Err(e) => return Err(e),
    };

    if !rows.is_empty() {
        return Err(HttpResponse::Conflict().json(error_construct(
            String::from("email"),
            String::from("conflict"),
            String::from("Este e-mail já está sendo utilizado por outro usuário."),
            Some(email),
            None,
            None,
        )));
    }
    Ok(())
}

pub async fn email_not_exists(pg_pool: Data<Pool>, email: String) -> Result<(), HttpResponse> {
    let mut sql_builder = SqlBuilder::select_from("users");
    sql_builder.field("id");
    sql_builder.or_where_eq("email", email.clone());

    let rows = match query_constructor_executor(pg_pool, sql_builder).await {
        Ok(x) => x,
        Err(e) => return Err(e),
    };

    if rows.is_empty() {
        return Err(HttpResponse::NotFound().json(error_construct(
            String::from("email"),
            String::from("not found"),
            String::from("Não foi encontrado um usuário com este e-mail."),
            Some(email),
            None,
            None,
        )));
    }
    Ok(())
}
