pub enum CustomError {
    PoolError,
    TokioPostgres,
    AnyhowError,
}

pub fn custom_error_to_io_error_kind(error: CustomError) -> std::io::ErrorKind {
    match error {
        CustomError::PoolError => std::io::ErrorKind::ConnectionAborted,
        CustomError::TokioPostgres => std::io::ErrorKind::ConnectionAborted,
        CustomError::AnyhowError => std::io::ErrorKind::Other,
    }
}
