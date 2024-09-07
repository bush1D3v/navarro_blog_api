use crate::utils::error_construct::error_construct;
use actix_web::HttpResponse;
use deadpool_postgres::PoolError;
use std::fmt::{Display, Formatter};

pub enum CustomError {
    PoolError(PoolError),
    TokioPostgres(tokio_postgres::error::Error),
    AnyhowError(anyhow::Error),
}

impl Display for CustomError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            CustomError::PoolError(e) => write!(f, "{}", e),
            CustomError::TokioPostgres(e) => write!(f, "{}", e),
            CustomError::AnyhowError(e) => write!(f, "{}", e),
        }
    }
}

/// # Custom Error to IO Error Kind
///
/// Converts CustomError to actix_web::HttpResponse
///
/// ## Arguments
///
/// * `error` - CustomError
///
/// ## Returns
///
/// HttpResponse
///
/// ## Usages
///
/// ### PoolError:
///
/// Return 503 Error (Service Unavailable) with error message.
///
/// ### TokioPostgres:
///
/// Return 503 Error (Service Unavailable) with error message.
///
/// ### AnyhowError:
///
/// Return 500 Error (Internal Server Error) with error message.
pub fn custom_error_to_io_error_kind(error: CustomError) -> HttpResponse {
    match error {
        CustomError::PoolError(error) => HttpResponse::ServiceUnavailable().json(error_construct(
            String::from("database"),
            String::from("service unavailable"),
            error.to_string(),
            None,
            None,
            None,
        )),
        CustomError::TokioPostgres(error) => {
            HttpResponse::ServiceUnavailable().json(error_construct(
                String::from("database"),
                String::from("service unavailable"),
                error.to_string(),
                None,
                None,
                None,
            ))
        }
        CustomError::AnyhowError(error) => {
            HttpResponse::InternalServerError().json(error_construct(
                String::from("server"),
                String::from("internal server error"),
                error.to_string(),
                None,
                None,
                None,
            ))
        }
    }
}
