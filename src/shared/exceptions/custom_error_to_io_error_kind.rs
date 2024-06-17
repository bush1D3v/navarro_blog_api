use anyhow::Error as AnyhowError;
use bcrypt::BcryptError;
use deadpool_postgres::PoolError;
use jsonwebtoken::errors::Error as JsonWebTokenError;
use std::io::ErrorKind;
use tokio_postgres::Error as TokioPostgresError;

pub enum CustomError<'a> {
    PoolError(&'a PoolError),
    Bcrypt(&'a BcryptError),
    TokioPostgres(&'a TokioPostgresError),
    JWTError(&'a JsonWebTokenError),
    AnyhowError(&'a AnyhowError),
}

pub fn custom_error_to_io_error_kind(error: CustomError) -> ErrorKind {
    match error {
        CustomError::PoolError(_) => ErrorKind::ConnectionAborted,
        CustomError::Bcrypt(_) => ErrorKind::InvalidInput,
        CustomError::TokioPostgres(_) => ErrorKind::ConnectionAborted,
        CustomError::JWTError(_) => ErrorKind::Other,
        CustomError::AnyhowError(_) => ErrorKind::Other,
    }
}
