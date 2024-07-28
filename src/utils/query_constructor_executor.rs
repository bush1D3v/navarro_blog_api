use crate::shared::exceptions::custom_error_to_io_error_kind::{
    custom_error_to_io_error_kind, CustomError,
};
use actix_web::HttpResponse;
use sql_builder::SqlBuilder;
use tokio_postgres::Row;

/// Construct and execute the query.
///
/// This function constructs and executes the query, based on the provided `SqlBuilder` and `Pool`.
///
/// # Parameters
///
/// - `pg_pool`: A connection pool for the database.
/// - `sql_builder`: An instance of the `SqlBuilder` struct.
///
/// # Returns
///
/// Returns a `Result` which, on success, contains the result of the query. On failure, returns an `HttpResponse` with the corresponding error.
///
/// # Errors
///
/// This function may return an error if:
///
/// - It is not possible to obtain a connection from the pool.
/// - The transaction fails.
/// - The conversion from `sql_builder::SqlBuilder` to `String` fails.
/// - The query fails.
/// - The commit fails.
///
/// # Example
///
/// ```rust
/// use navarro_blog_api::utils::query_constructor_executor::query_constructor_executor;
/// use sql_builder::SqlBuilder;
/// use actix_web::{web::Data, HttpResponse};
/// use deadpool_postgres::Pool;
///
/// pub async fn example(pg_pool: Data<Pool>, sql_builder: SqlBuilder) -> Result<Vec<postgres::Row>, HttpResponse> {
///     match query_constructor_executor(pg_pool, sql_builder).await {
///         Ok(x) => Ok(x),
///         Err(e) => return Err(e),
///     }
/// }
/// ```
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
    let rows = match transaction.query(&sql, &[]).await {
        Ok(x) => x,
        Err(e) => return Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    };
    match transaction.commit().await {
        Ok(_) => Ok(rows),
        Err(e) => Err(custom_error_to_io_error_kind(CustomError::TokioPostgres(e))),
    }
}
