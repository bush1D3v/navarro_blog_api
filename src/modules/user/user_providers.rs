use crate::shared::exceptions::custom_error_to_io_error_kind::{
    custom_error_to_io_error_kind, CustomError,
};
use actix_web::web::Data;
use deadpool_postgres::Pool;
use sql_builder::{quote, SqlBuilder};

pub async fn email_exists(pool: Data<Pool>, email: String) -> Result<(), std::io::Error> {
    let mut sql_builder = SqlBuilder::select_from("users");
    sql_builder.field("id");
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
    if !rows.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Este e-mail já está sendo utilizado por outro usuário.",
        ));
    }
    Ok(())
}

pub async fn email_not_exists(pool: Data<Pool>, email: String) -> Result<(), std::io::Error> {
    let mut sql_builder = SqlBuilder::select_from("users");
    sql_builder.field("id");
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
    if rows.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Não foi encontrado um usuário com este email.",
        ));
    }
    Ok(())
}
