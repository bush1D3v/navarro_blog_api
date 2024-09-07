use crate::{
    shared::exceptions::exception::Exception,
    utils::query_constructor_executor::query_constructor_executor,
};
use actix_web::{web::Data, HttpResponse};
use deadpool_postgres::Pool;
use sql_builder::{quote, SqlBuilder};

pub async fn email_exists(postgres_pool: Data<Pool>, email: String) -> Result<(), HttpResponse> {
    let mut sql_builder = SqlBuilder::select_from("users");
    sql_builder.field("id");
    sql_builder.or_where_eq("email", &quote(email.clone()));

    let rows = match query_constructor_executor(postgres_pool, sql_builder).await {
        Ok(x) => x,
        Err(e) => return Err(e),
    };

    if !rows.is_empty() {
        return Err(Exception::conflict(email));
    }
    Ok(())
}

pub async fn email_not_exists(
    postgres_pool: Data<Pool>,
    email: String,
) -> Result<(), HttpResponse> {
    let mut sql_builder = SqlBuilder::select_from("users");
    sql_builder.field("id");
    sql_builder.or_where_eq("email", &quote(email.clone()));

    let rows = match query_constructor_executor(postgres_pool, sql_builder).await {
        Ok(x) => x,
        Err(e) => return Err(e),
    };

    if rows.is_empty() {
        return Err(Exception::not_found(
            String::from("email"),
            String::from("Não foi encontrado um usuário com este e-mail."),
            Some(email),
        ));
    }
    Ok(())
}
