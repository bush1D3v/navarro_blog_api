pub enum CustomError {
    PoolError,
    Bcrypt,
    TokioPostgres,
    JWTError,
    AnyhowError,
}

pub fn custom_error_to_io_error_kind(error: CustomError) -> std::io::ErrorKind {
    match error {
        CustomError::PoolError => std::io::ErrorKind::ConnectionAborted,
        CustomError::Bcrypt => std::io::ErrorKind::InvalidInput,
        CustomError::TokioPostgres => std::io::ErrorKind::ConnectionAborted,
        CustomError::JWTError => std::io::ErrorKind::Other,
        CustomError::AnyhowError => std::io::ErrorKind::Other,
    }
}
