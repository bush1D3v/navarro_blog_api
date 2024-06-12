use std::io::ErrorKind;

use actix_web::http::StatusCode;
use anyhow::Error as AnyhowError;
use bcrypt::BcryptError;
use deadpool_postgres::PoolError;
use tokio_postgres::{Error as TokioPostgresError, error::SqlState};

pub enum CustomError<'a> {
    _Http(&'a StatusCode),
    _Sql(&'a Option<&'a SqlState>),
    _Anyhow(&'a AnyhowError),
    PoolError(&'a PoolError),
    Bcrypt(&'a BcryptError),
    TokioPostgres(&'a TokioPostgresError),
}

pub fn custom_error_to_io_error_kind(error: CustomError) -> ErrorKind {
    match error {
        CustomError::_Http(status_code) => match status_code.as_u16() {
            400..=499 => ErrorKind::InvalidInput,
            500..=599 => ErrorKind::BrokenPipe,
            _ => ErrorKind::Other,
        },
        CustomError::_Sql(sql_state) => match sql_state {
            Some(_) => ErrorKind::InvalidData,
            None => ErrorKind::Other,
        },
        CustomError::_Anyhow(_) => ErrorKind::Other,
        CustomError::PoolError(e) => match e {
            PoolError::Timeout(_) => ErrorKind::TimedOut,
            PoolError::Closed => ErrorKind::NotConnected,
            PoolError::Backend(_) => ErrorKind::ConnectionAborted,
            PoolError::PostCreateHook(_) => ErrorKind::InvalidData,
            PoolError::NoRuntimeSpecified => ErrorKind::NotConnected,
        },
        CustomError::Bcrypt(e) => match e {
            BcryptError::CostNotAllowed(_) => ErrorKind::Interrupted,
            BcryptError::InvalidBase64(_) => ErrorKind::InvalidInput,
            BcryptError::InvalidCost(_) => ErrorKind::InvalidInput,
            BcryptError::InvalidHash(_) => ErrorKind::InvalidInput,
            BcryptError::InvalidPrefix(_) => ErrorKind::InvalidInput,
            BcryptError::InvalidSaltLen(_) => ErrorKind::InvalidInput,
            BcryptError::Io(_) => ErrorKind::ConnectionAborted,
            BcryptError::Rand(_) => ErrorKind::InvalidData,
        },
        CustomError::TokioPostgres(_) => ErrorKind::ConnectionAborted,
    }
}
