use crate::shared::exceptions::custom_error_to_io_error_kind::{
    custom_error_to_io_error_kind, CustomError,
};
use actix_web::HttpResponse;
use sql_builder::SqlBuilder;
use tokio_postgres::Row;

pub async fn query_constructor_executor(
    pg_pool: actix_web::web::Data<deadpool_postgres::Pool>,
    sql_builder: SqlBuilder,
) -> Result<Vec<Row>, HttpResponse> {
    let mut conn = match pg_pool.get().await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::PoolError(e))),
    };
    let transaction = match conn.transaction().await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    let sql = match sql_builder.sql() {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::AnyhowError(e))),
    };
    let rows = match transaction.query(sql.as_str(), &[]).await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    match transaction.commit().await {
        Ok(_) => Ok(rows),
        Err(e) => Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    }
}
